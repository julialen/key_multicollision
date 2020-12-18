from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography.exceptions 
import binascii


with open("10keys_colliding_cts.txt", "r+") as ctfile:
    lines = ctfile.readlines()

keyline = lines[0].rstrip()
assert "key" in keyline and len(keyline.split(" "))==2
hexkeys = (keyline.split(" ")[1]).split(",")
assert len(hexkeys) == 10
print(hexkeys)
keys = list(map(binascii.unhexlify, hexkeys))

success = True
for _ctline in lines[1:]:
    ctline = _ctline.rstrip()
    parts = list(map(binascii.unhexlify,ctline.split(",")))
    assert len(parts)==3
    nonce = parts[0]
    ct = parts[1]
    tag = parts[2]
    #All these ciphertexts are exactly five blocks
    for key in keys:
        print("len ct:" + str(len(ct)))
        chapoly = ChaCha20Poly1305(key)
        try:
            chapoly.decrypt(nonce, bytes(ct+tag), None)
        except cryptography.exceptions.InvalidTag as e:
            print("Decrypting line " + ctline + " failed with key " + key.hex())
            success = False
            break

if success:
    print("All ciphertexts successfully decrypt with all keys.")
