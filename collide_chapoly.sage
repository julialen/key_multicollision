from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography.exceptions
import os
import binascii
import textwrap
import struct
from chapoly_utils import *
from chapoly import *
import time
import math

POLY1305_BLOCK_LENGTH = 16
CHAPOLY_NONCE_LENGTH = 12
CHAPOLY_KEY_LENGTH = 32

ZEROS_KEY = b'\x00'*CHAPOLY_KEY_LENGTH
ONES_KEY = b'\x11'*CHAPOLY_KEY_LENGTH
TWOS_KEY = b'\x22'*32
THREES_KEY = b'\x33'*32
ZEROS_NONCE = b'\x00'*CHAPOLY_NONCE_LENGTH
POLY_MODULUS = 2**130 - 5

def tag_str(i):
    assert i <= 2^130-5
    q = 0
    tmp = i
    while tmp > 2^128:
        tmp -= 2^128
        q += 1
    assert tmp <= 2^128
    return str(q)+"*2^128 + " + str(tmp) + "("+str(len(str(tmp)))+")"


def two_key_interpolate_with_nonce_linalg(key1, key2, nonce):

    otk1 = gen_otkey(key1, nonce)
    otk2 = gen_otkey(key2, nonce)
    r1_int, s1_int = get_otk_pair(otk1)
    r2_int, s2_int = get_otk_pair(otk2)
    print("r1: " + tag_str(r1_int) + " s1: " + tag_str(s1_int))
    print("r2: " + tag_str(r2_int) + " s2: " + tag_str(s2_int))
    lbytes = get_length_bytes(POLY1305_BLOCK_LENGTH)
    gfp = Integers(POLY_MODULUS, is_field=True)
    zzmod = Integers(2^128)
    lblock = poly_field_elt(gfp,lbytes)
    num_ct_blocks = 3
    lbytes2 = get_length_bytes(num_ct_blocks*POLY1305_BLOCK_LENGTH)
    lb2_int = le_bytes_to_num(lbytes2+b'\x01')
    lblock2 = poly_field_elt(gfp,lbytes2)

    topbit = gfp(2^128)
    r1 = gfp(r1_int)
    s1 = zzmod(s1_int)
    
    r2 = gfp(r2_int)
    s2 = zzmod(s2_int)
    #The equation we need to hold is
    #[(C* r1^2 + len*r1) mod 2^{130}-5] + s1 \equiv [(C*r2^2 + len*r2) mod 2^{130}-5] + s2 mod 2^{128}
    #Rearranging, we get [(C)(r1^2-r2^2) + len(r1-r2)] mod 2^130 - 5 \equiv s2-s1 mod 2^{128}

    A = Matrix(gfp, [[(r1^2-r2^2)]])

    b = vector(gfp, [gfp(s2-s1) - lblock*(r1 - r2)])

    gfp_ct_vec = A.solve_right(b)
    naive_ct = gfp_ct_vec[0]
    ct_bytes = num_to_16_le_bytes(Integer(naive_ct))
    tag_bytes = poly1305_linalg(r1_int, s1_int, [ct_bytes, lbytes])

    #This formulation is for tag = 0
    k1_row = [r1^(num_ct_blocks+1-i) for i in range(num_ct_blocks)]
    k2_row = [r2^(num_ct_blocks+1-i) for i in range(num_ct_blocks)]
    A = Matrix(gfp, [k1_row, k2_row])

    #Take the additive inverse of the length block term, mod 2^130-5, and add it to the pad's inverse mod 2^128
    # lb2_rhs1 = ((POLY_MODULUS - (r1_int*lb2_int % POLY_MODULUS))%2^128 + (2^128 - s1_int)) % 2^128
    # lb2_rhs2 = ((POLY_MODULUS - (r2_int*lb2_int % POLY_MODULUS))%2^128 + (2^128 - s2_int)) % 2^128
    # print("row 1: " + str(list(map(lambda x:tag_str(Integer(x)), A[0]))))
    # print("row 2: " + str(list(map(lambda x:tag_str(Integer(x)), A[1]))))
    b = vector(gfp, (gfp(-s1)-lblock2*r1, gfp(-s2)-lblock2*r2))

    gfp_ct = A.solve_right(b)
    if not any(map(lambda x:2^128 <= Integer(x) <= 2^129-1, gfp_ct)):
        #Repeat with four CT blocks
        print("Trying four CT blocks...")
        num_ct_blocks = 4
        lbytes2 = get_length_bytes(num_ct_blocks*POLY1305_BLOCK_LENGTH)
        lb2_int = le_bytes_to_num(lbytes2+b'\x01')
        lblock2 = poly_field_elt(gfp,lbytes2)
        k1_row = [r1^(num_ct_blocks+1-i) for i in range(num_ct_blocks)]
        k2_row = [r2^(num_ct_blocks+1-i) for i in range(num_ct_blocks)]
        A = Matrix(gfp, [k1_row, k2_row])
        b = vector(gfp, (gfp(-s1)-lblock2*r1, gfp(-s2)-lblock2*r2))
        gfp_ct = A.solve_right(b)



        
    print("Validity for each CT block: " + str(list(map(lambda x:2^128 <= Integer(x) <= 2^129-1, gfp_ct))))
    print("In range? " + str(all(map(lambda x:2^128 <= Integer(x) <= 2^129-1, gfp_ct))))
    #print("SIze of kernel: "+str(A.right_kernel()))
    before = time.time()
    for hs in A.right_kernel():
        if (time.time() - before) > 30.0:
            break
        other_sol = gfp_ct + hs
        if all(map(lambda x:2^128 <= Integer(x) <= 2^129-1, other_sol)):
            print("reassigning ct...")
            gfp_ct = other_sol
            break
    #gfp_ct = gfp_cts_and_tag[:-1]
    print("naive ct:"+str(naive_ct))
    print("gfp ct:"+str(list(map(lambda x:tag_str(Integer(x)), gfp_ct))))
    gfp_tag = gfp(0)#gfp_cts_and_tag[-1]
    #These two values should be equal to s1 and s2, respectively.
    #They are wrong whenever there is a wraparound mod 2^128.
    check1 = sum(gfp_ct[i]*(r1^(len(gfp_ct)+1-i)) for i in range(len(gfp_ct))) + lblock2*r1
    check2 = sum(gfp_ct[i]*(r2^(len(gfp_ct)+1-i)) for i in range(len(gfp_ct))) + lblock2*r2
    print("check1: " + tag_str(Integer(check1)) + " check1 mod 2^128: " + str(zzmod(check1)) + "\ncheck1 + s1 mod 2^128: " + str(Integer(zzmod(check1)+s1)))
    print("check2: " + tag_str(Integer(check2)) + " check2 mod 2^128: " + str(zzmod(check2)) + "\ncheck2 + s2 mod 2^128: " + str(Integer(zzmod(check2)+s2)))
    
    # gfp_ct1 = A.solve_right(b1)
    # gfp_ct2 = A.solve_right(b2)
    # gfp_ct3 = A.solve_right(b3)
    #print("check:\n"+str(list(map(num_to_16_le_bytes, map(Integer,A*gfp_ct + b)))))
    gfp_ct_bytes =  list(map(lambda x:num_to_16_le_bytes(Integer(x)), gfp_ct))
    t1 = poly1305_knowngood(r1_int, s1_int, gfp_ct_bytes + [lbytes2])
    t2 = poly1305_knowngood(r2_int, s2_int, gfp_ct_bytes + [lbytes2])
    print("Tag1: " + t1.hex() + " Tag2: " + t2.hex()) 
    #print("ct bytes:"+ct_bytes.hex())
    gfp_tag_bytes = num_to_16_le_bytes(Integer(gfp_tag))
    #print("tag bytes:"+tag_bytes.hex())
    # ct_bytes1 = list(map(num_to_16_le_bytes, map(Integer, gfp_ct1)))
    # print(ct_bytes1)
    # ct_bytes2 = list(map(num_to_16_le_bytes, map(Integer, gfp_ct2)))
    # print(ct_bytes2)
    # ct_bytes3 = list(map(num_to_16_le_bytes, map(Integer, gfp_ct3)))
    # print(ct_bytes3)
    #assert(len(ct_bytes) == 2)

    return ct_bytes, tag_bytes


def multikey_interpolate_linalg(keyset,nonce=ZEROS_NONCE):
    DEBUG=True
    if DEBUG:
        print("Using the nonce "+nonce.hex()+" and the zeros tag. Attempting solution for " + str(len(keyset)) + " keys.")
    num_ct_blocks = len(keyset)+1
    zerotag = b'\x00'*16
    if DEBUG:
        print("Using " + str(num_ct_blocks) + " blocks.")
    #otks[i][0] is the clamped r int for key i. otks[i][1] is the pad value s for key i
    otks = [get_otk_pair(gen_otkey(keyset[i], nonce)) for i in range(len(keyset))]
    gfp = Integers(POLY_MODULUS, is_field=True)
    zzmod = Integers(2^128)
    #Ciphertext length
    lbytes = get_length_bytes(num_ct_blocks*POLY1305_BLOCK_LENGTH)
    lb_int = le_bytes_to_num(lbytes+b'\x01')
    lblock = poly_field_elt(gfp,lbytes)
    rvals = [gfp(otks[j][0]) for j in range(len(keyset))]
    svals = [zzmod(otks[j][1]) for j in range(len(keyset))]
    rows = [[rval^(num_ct_blocks+1-i) for i in range(num_ct_blocks)] for rval in rvals]
    A = Matrix(gfp, rows)
    b = vector(gfp, [gfp(-svals[i])-lblock*rvals[i] for i in range(len(keyset))])
    ct_blocks = A.solve_right(b)
    #Chosen to give a reasonable probability of success, according to our model
    num_vectors_to_check = (4^(len(keyset)+1))
    if DEBUG:
        print("Sieving " + str(num_vectors_to_check) + " vectors in the kernel.")
    checked = 0
    if DEBUG:
        print(str(list(map(lambda x:2^128 <= Integer(x) <= 2^129-1, ct_blocks))))
    if not all(map(lambda x:2^128 <= Integer(x) <= 2^129-1, ct_blocks)):
        if DEBUG:
            print("Some of the ciphertext blocks are not in the right range.")
            print("Searching matrix kernel for 30 seconds to find valid solution.")
        before = time.time()
        for hs in A.right_kernel():
            checked += 1
            if checked > num_vectors_to_check:
                break
            other_sol = ct_blocks + hs
            if all(map(lambda x:2^128 <= Integer(x) <= 2^129-1, other_sol)):
                if DEBUG:
                    print("ct: " + str(ct_blocks))
                    print("hs: " + str(hs))
                    print("reassigning ct...")
                ct_blocks = other_sol
                break
    if DEBUG:
        print("Sieving " + str(num_vectors_to_check) + " took " + str(time.time() - before) + " seconds.")
    ct_bytes =  list(map(lambda x:num_to_16_le_bytes(Integer(x)), ct_blocks))
    #tags = [poly1305_knowngood(otks[i][0],otks[i][1], ct_bytes + [lbytes]).hex() for i in range(len(keyset))]
    #print(str(tags))
    #if all(tag == tags[0] for tag in tags):
    #   print("We found a colliding ciphertext!")
    return ct_bytes,zerotag
            
def verify_collision(keyset, nonce, ctbytes):
    otks = [get_otk_pair(gen_otkey(keyset[i], nonce)) for i in range(len(keyset))]
    lbytes = get_length_bytes(len(ctbytes)*POLY1305_BLOCK_LENGTH)
    tags = [poly1305_knowngood(otks[i][0],otks[i][1], ctbytes + [lbytes]).hex() for i in range(len(keyset))]
    return all(tag == tags[0] for tag in tags)


def test_colliding_ct(keyset, nonce, ct_bytes, tag):
    correct = True
    for key in keyset:
        cip1 = ChaCha20Poly1305(key)
        try:
            pt1 = cip1.decrypt(nonce, bytes(ct_bytes+tag), None)
        except cryptography.exceptions.InvalidTag as e:
            correct = False
    return correct

        
def poly1305_ietf7539_ext(key, nonce, message):
    otk0 = gen_otkey(key, nonce)
    r0_int, s0_int = get_otk_pair(otk0)
    blocks = make_blocks_rfc7539(message)
    ours = poly1305_linalg(r0_int, s0_int, blocks)
    theirs = poly1305_knowngood(r0_int, s0_int, blocks)
    assert ours.hex() == theirs.hex()
    return ours

#Takes as input a list of byte arrays of at most sixteen bytes,
#and evaluates Poly1305 with the given r and s values.
#Assumes rkey has already been clamped.
def poly1305_knowngood(rkey, skey, message):
    assert len(message) >= 2
    acc = 0
    for i in range(len(message)):
        n = le_bytes_to_num(message[i] + b'\x01')
        acc += n
        acc = (rkey * acc) % POLY_MODULUS
    acc += skey
    return num_to_16_le_bytes(acc)

#Takes as input a list of byte arrays of at most sixteen bytes,
#and evaluates Poly1305 with the given r and s values.
#Assumes rkey has already been clamped.
def poly1305_linalg(rkey, skey, message):
    assert len(message) >= 2
    DEBUG=False
    gfp = Integers(POLY_MODULUS, is_field=True)
    zzmod = Integers(2^128)
    gfp_r = gfp(rkey)
    gfp_s = gfp(skey)
    zz_s = zzmod(skey)
    row = Matrix(gfp, [gfp_r^(len(message)+1-i) for i in range(1, len(message)+1)])
    blocks = vector(gfp, list(map(lambda x:gfp(le_bytes_to_num(x+b'\x01')), message)))
    h = row*blocks
    if DEBUG:
        print(h)
    h = zzmod(h[0])
    zztag = h+zz_s
    if DEBUG:
        print(zztag)
    return num_to_16_le_bytes(Integer(zztag))


def two_key_interpolate_with_nonce(key1, key2, nonce):
    otk1 = gen_otkey(key1, nonce)
    otk2 = gen_otkey(key2, nonce)
    r1_int, s1_int = get_otk_pair(otk1)
    r2_int, s2_int = get_otk_pair(otk2)
    lbytes = get_length_bytes(16)
    gfp = Integers(POLY_MODULUS, is_field=True)
    zzmod = Integers(2^128)
    lblock = poly_field_elt(gfp,lbytes)
    r1 = gfp(r1_int)
    s1 = zzmod(s1_int)
    s1_gfp = gfp(s1_int)
    r2 = gfp(r2_int)
    s2 = zzmod(s2_int)
    s2_gfp = gfp(s2_int)
    topbit = gfp(2^128)
    #The equation we need to hold is
    #[(C* r1^2 + len*r1) mod 2^{130}-5] + s1 \equiv [(C*r2^2 + len*r2) mod 2^{130}-5] + s2 mod 2^{128}
    #Rearranging, we get [(C+2^128)(r1^2-r2^2) + len(r1-r2)] mod 2^130 - 5 \equiv s2-s1 mod 2^{128}
    squaresinv = (r1^2 - r2^2)^-1
    diff = s2-s1
    diff = gfp(diff)
    ct = (diff - lblock*(r1 - r2))*squaresinv #- topbit
    ct_bytes = num_to_16_le_bytes(Integer(ct))
    t1 = poly1305_knowngood(r1_int, s1_int, [ct_bytes, lbytes])
    t2 = poly1305_knowngood(r2_int, s2_int, [ct_bytes, lbytes])

    ct_out = ct_bytes
    tag = t1
    return (ct_out, tag)



#Takes as input two ChaCha20/Poly1305 keys
#and returns a (nonce, ciphertext, tag) triple
#that decrypts correctly under both of them.
def two_key_interpolate(key1, key2):
    assert len(key1) == CHAPOLY_KEY_LENGTH \
    and len(key2) == CHAPOLY_KEY_LENGTH
    #use a fixed nonce and tagfor now
    curr_nonce = bytes(ZEROS_NONCE)
    curr_tag = bytes([0]*16)
    keepgoing = False
    times = 0
    ct, tag = two_key_interpolate_with_nonce_linalg(key1, key2, curr_nonce)
    #print("ct:"+ct.hex())
    #print("tag:"+tag.hex())
    ct1, tag1 = two_key_interpolate_with_nonce(key1, key2, curr_nonce)
    #print("ct1:"+ct1.hex())
    #print("tag1:"+tag1.hex())
    t1 = poly1305_ietf7539_ext(key1, curr_nonce, ct)
    t2 = poly1305_ietf7539_ext(key2, curr_nonce, ct)
    t3 = poly1305_ietf7539_ext(key1, curr_nonce, ct1)
    t4 = poly1305_ietf7539_ext(key2, curr_nonce, ct1)
    print("From linalg. Ciphertext "  + ct.hex() + " should have tag "+tag.hex())
    print("key1 tag:"+t1.hex())
    print("key2 tag:"+t2.hex())
    print("From other. Ciphertext " + ct1.hex() + " should have tag "+tag1.hex())
    print("key1 tag:"+t3.hex())
    print("key2 tag:"+t4.hex())
    return curr_nonce, ct, tag

    
if __name__=='__main__':

    #test_poly_against_ref()
    # arr = [ZEROS_KEY, ONES_KEY]
    # ct, tag = multikey_interpolate_linalg(arr)


    # print(" \n")
    # arr = [TWOS_KEY, ZEROS_KEY]
    # ct, tag = multikey_interpolate_linalg(arr)

    # goodnonces = ['0x5', '0xc', '0xd', '0xe', '0xf', '0x13', '0x1a', '0x1b', '0x1c', '0x1e', \
    #               '0x1f', '0x26', '0x30', '0x34', '0x39', '0x3a', '0x3f', '0x42', '0x44', '0x45', \
    #               '0x47', '0x49', '0x4f', '0x56', '0x57', '0x59', '0x61']
    
    arr = [bytes([i])*CHAPOLY_KEY_LENGTH for i in range(50,60)]
    with open(str(len(arr))+"keys_colliding_cts_moresieving.txt", "w+") as resultfile:
        resultfile.write("keys: "+",".join(list(map(lambda x:x.hex(),arr)))+"\n")

    #print("List of keys we're trying:\n"+str(list(map(lambda x:x.hex(),arr))))
    for i in range(100):
        if i % 10 == 0 and not i == 0:
            print("At nonce " + str(i))
        nonce = bytes([i])*CHAPOLY_NONCE_LENGTH
        _ct_bytes, _tag = multikey_interpolate_linalg(arr,nonce)
        if verify_collision(arr, nonce, _ct_bytes):
            print("We may have a collision for nonce "+hex(i)+"*12. Checking decryption...")
            ctbytes_flattened = _ct_bytes[0]
            for i in range(1, len(_ct_bytes)):
                ctbytes_flattened += _ct_bytes[i]
            success = test_colliding_ct(arr, nonce, ctbytes_flattened, _tag)
            if success:
                print("Decryption succeeds under every key. Storing ciphertext.")
                with open("2keys_colliding_cts.txt", "a+") as resultfile:
                    resultfile.write(str(nonce.hex())+","+ctbytes_flattened.hex()+","+_tag.hex()+"\n")

