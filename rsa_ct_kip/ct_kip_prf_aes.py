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
