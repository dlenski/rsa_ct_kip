Needs Python **3.x**, Flask, PyCryptoDome, and requests.

`fakeserver.py` needs a trusted `server.pem` certificate (otherwise the
RSA SecurID app won't connect to it).

The `rsapubkey.pem` and `rsaprivkey.pem` shouldn't need to be modified
(included are versions with 1024-bit keys and modulus 65537, similar to
what seem to be used by the "real" RSA server).
