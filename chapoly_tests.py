#Run poly1305 on RFC 7539 test vectors.
def test_poly1305():
    s_int = 0x1bf54941aff6bf4afdb20dfb8a800301
    clamped_r_int = 0x806d5400e52447c036d555408bed685
    message_bytes = "Cryptographic Forum Research Group".encode()
    message_blocks = [message_bytes[:16], message_bytes[16:32], message_bytes[32:]]
    print(list(map(lambda x:x.hex(), message_blocks)))
    tag = poly1305(clamped_r_int, s_int, message_blocks)
    print(tag.hex())



    
#Test vectors from RFC 7539, page 11.
def test_chacha20_encrypt():
    testkey = binascii.unhexlify(("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f"+\
                                  ":10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f").replace(":", ""))
    testnonce = binascii.unhexlify("00:00:00:00:00:00:00:4a:00:00:00:00".replace(":", ""))
    testplaintext = ("Ladies and Gentlemen of the class of '99: If I could offer"+\
                     " you only one tip for the future, sunscreen would be it.").encode()
    ct = chacha20_encrypt(testkey, testnonce, testplaintext)
    keystream = chacha20_encrypt(testkey, testnonce, b'\x00'*len(testplaintext))
    print("Keystream:")
    print(binascii.hexlify(keystream))
    print("Ciphertext:")
    print(binascii.hexlify(ct))

    
#Test vectors from RFC 7539, page 17
def test_gen_otkey():
    nonce = binascii.unhexlify("00 00 00 00 00 01 02 03 04 05 06 07".replace(" ", ""))
    key = binascii.unhexlify(("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92"\
                              + " 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f").replace(" ", ""))

    print(gen_otkey(key,nonce).hex())
    
#RFC 7539, page 15
def test_clamp():
    before = int.from_bytes(binascii.unhexlify(("85:d6:be:78:57:55:6d:33"+\
                                                ":7f:44:52:fe:42:d5:06:a8").replace(":", "")), 'little')
    print(clamp_poly1305_r(before).hex())

def test_ref():
    ct,tag = chacha20_poly1305_encrypt(ZEROS_KEY, ZEROS_NONCE, b'\x00'*32)
    refct = ref_chapoly_encrypt(ZEROS_KEY, ZEROS_NONCE, b'\x00'*32)
    rh = refct.hex()
    print("Ours:")
    print(ct.hex() + " " + str(tag))
    print("Reference:")
    print(rh[:-32] + " " + rh[-32:])



def test_twokey():
    two_key_interpolate(ZEROS_KEY, ONES_KEY)
    print(" ")
    two_key_interpolate(b'\x22'*32, ZEROS_KEY)
    print(" ")
    two_key_interpolate(b'\x22'*32, ONES_KEY)
    print(" ")
    two_key_interpolate(b'\x33'*32, b'\x22'*32)
    print(" ")
    two_key_interpolate(b'\x33'*32, ONES_KEY)
