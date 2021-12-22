import os
import signal
import socket
import time
from contextlib import closing
from binascii import hexlify, unhexlify, a2b_base64

from Crypto.PublicKey import RSA
from Crypto.Util import number

from rsa_ct_kip.ct_kip_prf_aes import ct_kip_prf_aes
import rsa_ct_kip.client
import rsa_ct_kip.fakeserver

from nose2.tools.such import helper


def test_ct_kip_prf_aes():
    # Known test vector obtained from actual RSA software:
    #   https://github.com/rgerganov/ctkip/blob/master/src/com/xakcop/ctkip/Main.java
    R_C = unhexlify(b"846cd036914f3bf536e7354ece07b35a")
    R_S = unhexlify(b"79956b2fd8502465ad5c5fe99b9e7786")
    pubk_mod = number.bytes_to_long(a2b_base64(
        b"1np1DIf3HOHAK2ahcRzZCJsqIC1QMEqtsdanKSEn5CGtLCdLv9LbLUYo6cQx"
        b"KSJtwvigpeDgBAb/UYcUNXy/7dY7rA5WpYlsaA9h5C9qzPMBHxVGSIe5k61u"
        b"UbAwdFhCMfLh776wR//VZ7cuypo5d3cCbvgHGwqw4ZuECbKvONM="))
    pubk = RSA.construct((pubk_mod, 65537))
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
    assert MAC_CALC == MAC



def test_full_exchange():
    # Find an open port
    for port in range(40000, 50000):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex(('localhost', port)) != 0:
                break

    pid = os.fork()
    if pid == 0:
        rsa_ct_kip.fakeserver.app.config['auth'] = '12345'  # Required auth code
        rsa_ct_kip.fakeserver.app.run(host='localhost', port=port, debug=True, use_reloader=False, ssl_context=None)
        os._exit(0)

    try:
        # Wait for server to become ready
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex(('localhost', port)) != 0:
                time.sleep(1)

        # Test with bad/wrong auth code
        with helper.assertRaises(RuntimeError):
            rsa_ct_kip.client.exchange('http://localhost:{}'.format(port), '67890')

        # Test with correct auth code
        token = rsa_ct_kip.client.exchange('http://localhost:{}'.format(port), '12345')
        assert isinstance(token.get('K_TOKEN'), bytes)
    finally:
        os.kill(pid, signal.SIGTERM)
