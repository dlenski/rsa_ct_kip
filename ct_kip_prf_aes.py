from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.PublicKey import RSA
from Crypto.Util import number

from binascii import hexlify, unhexlify
import importlib
import math
import struct


def cmac(key, msg):
    c = CMAC.new(key, ciphermod=AES)
    c.update(msg)
    return c.digest()


def ct_kip_prf_aes(key, *msg, dslen=16, pad=None):
    assert (dslen // 16) < (2**32)

    msg = b''.join(msg)

    n = math.ceil(dslen / 16)
    j = dslen % 16

    tag = b''
    for i in range(n):
        if i == n - 1 and j != 0:
            reslen = j
        else:
            reslen = 16;

        xi = struct.pack('>I', i + 1)
        tag += cmac(key, msg + xi)
    return tag


def main():
    R_C = xxx
    R_S = yyy
    pubk = zzz
    MAC = eee  # Expected MAC

    k = number.long_to_bytes(pubk.n)
    K_TOKEN = ct_kip_prf_aes(\
            R_C,
            k,
            b"Key generation",
            R_S)
    print("K_TOKEN, modulus only, no padding, key first:", hexlify(K_TOKEN))
    MAC_CALC = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
    print("MAC(calc)", hexlify(MAC_CALC), "MAC(exp)", hexlify(MAC))

if __name__ == "__main__":
    main()
