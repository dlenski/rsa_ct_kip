# Original source:
#   https://gist.github.com/cemeyer/3293e4fcb3013c4ee2d1b6005e0561bf
#
# This is a VARY SPESHUL AES-based pseudorandom function allegedly,
# but very sloppily, documented by RSA in this draft:
# https://tools.ietf.org/html/rfc4758#appendix-D.2
#
# The actual RSA software implements it differently from the
# alleged specification, as noted below.

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

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

        # Difference between RFC4758 Appendix D.2.2 and
        # actual RSA software behavior:
        # --- F (k, s, i) = OMAC1-AES (k, INT (i) || s)
        # +++ F (k, s, i) = OMAC1-AES (k, s || INT (i))

        xi = struct.pack('>I', i + 1)
        tag += cmac(key, msg + xi)
    return tag


def main():
    from binascii import hexlify, unhexlify, a2b_base64
    from Crypto.PublicKey import RSA
    from Crypto.Util import number

    # Known test vector obtained from actual RSA software:
    #   https://github.com/rgerganov/ctkip/blob/master/src/com/xakcop/ctkip/Main.java
    R_C = unhexlify(b"846cd036914f3bf536e7354ece07b35a")
    R_S = unhexlify(b"79956b2fd8502465ad5c5fe99b9e7786")
    pubk = RSA.construct( (number.bytes_to_long(a2b_base64(b"1np1DIf3HOHAK2ahcRzZCJsqIC1QMEqtsdanKSEn5CGtLCdLv9LbLUYo6cQxKSJtwvigpeDgBAb/UYcUNXy/7dY7rA5WpYlsaA9h5C9qzPMBHxVGSIe5k61uUbAwdFhCMfLh776wR//VZ7cuypo5d3cCbvgHGwqw4ZuECbKvONM=")), 65537) )
    MAC = unhexlify(b"eca98d8e5bf211fb5167dada9c262296")  # Expected MAC

    # Difference between RFC4758 Section 3.5 and
    # actual RSA software behavior:
    # --- K_TOKEN = CT-KIP-PRF (R_C, "Key generation" || k || R_S, dsLen)
    # +++ K_TOKEN = CT-KIP-PRF (R_C, k || "Key generation" || R_S, dsLen)

    k = number.long_to_bytes(pubk.n)
    K_TOKEN = ct_kip_prf_aes(R_C, k, b"Key generation", R_S)
    print("K_TOKEN, modulus only, no padding, key first:", hexlify(K_TOKEN))

    # Difference between RFC4758 Section 3.8.6 and
    # actual RSA software behavior:
    # --- MAC = CT-KIP-PRF (K_AUTH, "MAC 2 computation" || R_C, dsLen)
    # +++ MAC = CT-KIP-PRF (K_AUTH, "MAC 2 Computation" || R_C, dsLen)

    MAC_CALC = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
    print("MAC(calc)", hexlify(MAC_CALC), "MAC(exp)", hexlify(MAC))

if __name__ == "__main__":
    main()
