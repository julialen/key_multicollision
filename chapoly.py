from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography.exceptions
from chapoly_utils import *
import struct

#Some code in this file is based on the ChaCha20/Poly1305 python
#implementation in this repo: https://github.com/ph4r05/py-chacha20poly1305

POLY1305_BLOCK_LENGTH = 16

#Generate the one-time key (r, s) for Poly1305.
#This essentially just encrypts 32 bytes of zero
#with a zero counter and returns the result as the key.
def gen_otkey(key, nonce):
    counter = bytes([0, 0, 0, 0])
    zeros = b'\x00'*32
    cha = algorithms.ChaCha20(key, counter+nonce)
    enc = Cipher(cha, mode=None,backend=default_backend()).encryptor()
    return enc.update(zeros)


#Takes in 32 bytes and outputs a Poly1305
#one-time key (r, s) with clamped r
def get_otk_pair(otkey):
    assert len(otkey) == 32
    polyr = clamp_poly1305_r(int.from_bytes(otkey[:16], 'little'))
    polys = int.from_bytes(otkey[16:], 'little')
    return (polyr,polys)

#Returns a sixteen-byte encoding of the length block
#for ChaCha20/Poly1305 where length is in BYTES, (see RFC 7539)
def get_length_bytes(ctlen):
    return bytearray([0]*8) + struct.pack('<Q', ctlen)


#Encrypt the message using ChaCha20, per RFC7539
def chacha20_encrypt(key, nonce, message):
    counter = bytes([1, 0, 0, 0])
    #Annoyingly, PyCA only accepts sixteen-byte nonces.
    #Internally, the first four bytes of the nonce are
    #treated as the 32-bit (little-endian) counter input to the block function;
    #concatenating them this way seems to work (per RFC 7539 test vectors)
    cha = algorithms.ChaCha20(key, counter+nonce)
    enc = Cipher(cha, mode=None,backend=default_backend()).encryptor()
    ct = enc.update(message)
    return ct


def make_blocks_rfc7539(message):

    quot, r = divmod(len(message), POLY1305_BLOCK_LENGTH)
    ub = quot + int(bool(r))
    blocks = [message[POLY1305_BLOCK_LENGTH*i : POLY1305_BLOCK_LENGTH*(i+1)] for i in range(0, ub)]

    lblock = get_length_bytes(len(message))
    blocks += [lblock]

    return blocks

#Encrypt the message using ChaCha20/Poly1305, per RFC7539
#Does not support associated data or non-block-aligned messages.
def chacha20_poly1305_encrypt(key, nonce, message):
    ct = chacha20_encrypt(key, nonce, message)
    assert len(ct) % 16 == 0
    #First, derive the pad and key for Poly1305.
    otkey = gen_otkey(key, nonce)
    #print("len otkey: " + str(len(otkey)))
    #print(otkey.hex()[:32] + " " + otkey.hex()[32:])
    polyr,polys = get_otk_pair(otkey)
    #First eight bytes are zeros (no AD), then eight bytes of pt length
    #length_bytes = get_length_bytes(len(ct))
    #ad_length = bytearray([0]*8)
    #ct_length = struct.pack('<Q', len(ct_blocks))
    #Split the ciphertext into chunks
    #ct_blocks = [ct[16*i : 16*(i+1)] for i in range(len(ct)//16)]
    #ct_blocks += [length_bytes]
    ct_blocks = make_blocks_rfc7539(ct)
    #At this point, ct_blocks is an array of at
    #least two sixteen-byte blocks.
    #Convert these blocks to field elements, as described in RFC7539
    tag = poly1305(polyr, polys, ct_blocks)
    return (ct, bytes(tag).hex())

def ref_chapoly_encrypt(key, nonce, message):
    cip = ChaCha20Poly1305(key)
    ct = cip.encrypt(nonce, message, None)
    return ct




#Takes as input a list of byte arrays of at most sixteen bytes,
#and evaluates Poly1305 with the given r and s values.
#Assumes rkey has already been clamped.
def poly1305(rkey, skey, message):
    assert len(message) >= 2
    DEBUG=False
    gfp = Integers(POLY_MODULUS, is_field=True)
    zzmod = Integers(2^128)
    gfp_r = gfp(rkey)
    gfp_s = gfp(skey)
    zz_s = zzmod(skey)
    #field_elements = list(map(lambda x:gfp(le_bytes_to_num(x+b'\x01')), message))
    acc = 0
    gfacc = gfp(0)
    gfacc2 = gfp(0)
    zzacc = 0
    for i in range(len(message)):
        n = le_bytes_to_num(message[i] + b'\x01')
        acc += n
        acc = (rkey * acc) % POLY_MODULUS
        curr_fe = gfp(le_bytes_to_num(message[i]+b'\x01'))
        gfacc += curr_fe
        gfacc *= gfp_r
        if DEBUG:
            print("i="+str(i))
            print("\tref_acc="+str(acc))
            print("\tour_acc="+str(Integer(gfacc)))
            if str(acc) == str(Integer(gfacc)):
                print("\tAccumulators are equal.")
            else:
                print("\tAccumulators are not equal.")
    acc += skey
    gfacc = zzmod(gfacc) + zz_s
    # if DEBUG:
    #     print("Adding pad. Note that we expect ref\n"+\
    #           "and our acc to be different here - ours has\n"+\
    #           "been reduced mod 2^128 already; ref hasn't.")
    #     print("\tref_acc="+str(acc))
    #     print("\tour_acc="+str(Integer(gfacc)))
    #     print("\tmodulus="+str(2^130 - 5))
    TAG_MODULUS = 2^128
    for i in range(1, len(message)+1):
        curr_int = le_bytes_to_num(message[i-1]+b'\x01')
        curr_fe = gfp(le_bytes_to_num(message[i-1]+b'\x01'))
        j = len(message)+1 - i
        gfacc2 = gfacc2 + curr_fe*(gfp_r^j)
        zzacc += (curr_int*(rkey^j) % POLY_MODULUS)%TAG_MODULUS
    gfacc2 = zzmod(gfacc2) + zz_s
    zzacc = ((zzacc % POLY_MODULUS) % TAG_MODULUS + skey) 
    knowngood = num_to_16_le_bytes(acc).hex()
    our_horner = num_to_16_le_bytes(Integer(gfacc)).hex()
    our_poly = num_to_16_le_bytes(Integer(gfacc2)).hex()
    our_zz = num_to_16_le_bytes(acc).hex()
    same = (knowngood == our_horner and our_horner == our_poly)
    if not same:
        print("Different poly1305 impl outputs!")
    if (not same) or DEBUG:
        print("knowngood: "+str(knowngood))
        print("our_horner:"+str(our_horner))
        print("our_poly:  "+str(our_poly))
        print("our_zz:    "+str(our_zz))
    return num_to_16_le_bytes(Integer(gfacc2))
