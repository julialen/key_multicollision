#Some code in this file is based on the ChaCha20/Poly1305 python
#implementation in this repo: https://github.com/ph4r05/py-chacha20poly1305

def clamp_poly1305_r(polyr):
    assert isinstance(polyr, int)
    return polyr & 0x0ffffffc0ffffffc0ffffffc0fffffff

def fe_poly_to_hex_string(elt):
    out = Integer(elt)
    obytes = [0]*17
    for i, _ in enumerate(obytes):
        obytes[i] = out & 0xff
        out >>= 8
    return bytes(obytes)


def le_bytes_to_num(data):
    """Convert a number from little endian byte format"""
    ret = 0
    for i in range(len(data) - 1, -1, -1):
        ret <<= 8
        ret += data[i]
    return ret


def num_to_16_le_bytes(num):
    """Convert number to 16 bytes in little endian format"""
    ret = [0]*16
    for i, _ in enumerate(ret):
        ret[i] = num & 0xff
        num >>= 8
    return bytearray(ret)


def poly_field_elt(field, ba):
    return field(le_bytes_to_num(ba+b'\x01'))
