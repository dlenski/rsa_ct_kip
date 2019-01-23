What is this for?
=================

If you need to use an [RSA SecurID](//en.wikipedia.org/wiki/RSA_SecurID) software token
to generate [one-time passwords](//en.wikipedia.org/wiki/One-time_password), and
have been given an activation code and a URL like
`https://XXX.com:443/ctkip/services/CtkipService`, this software will allow you to
provision the token and save it in a format that you can use with
[stoken](//github.com/cernekee/stoken).

If you use the RSA's official software to provision the token, it will obscure the
token seed to prevent you from copying it to another computer.

Requirements
============

Client needs Python **3.x**, PyCryptoDome, and requests. [stoken](//github.com/cernekee/stoken) is needed to actually *do* anything with the resulting tokens.

Server needs Flask as well.

Provision token using client
============================

Provide the client with the activation URL and activation code
(usually 12 digits), and a file in which to save the token template.
It will communicate with the RSA CT-KIP server and provision a token:

```
$ ./client.py https://server.company.com:443/ctkip/services/CtkipService ACTIVATION_CODE template.xml
Sending ClientHello request to server...
Received ServerHello response with server nonce (R_S = 28198dbe2c18a00335179cc5bb4eff3a) and 1024-bit RSA public key
Generated client nonce (R_C = 12bec1a6f4d09470986b485561c4d2b5)
Sending ServerFinished request to server, with encrypted client nonce...
MAC verified (0f103bc63a8819ffdbee657d042144f6)
Received ServerFinished response with token information:
  Service ID: RSA CT-KIP
  Key ID: 838999658504
  Token ID: 838999658504
  Token User:
  Expiration date: 2020-01-23T00:00:00+00:00
  OTP mode: 8 Decimal, every 60 seconds
  Token seed: 30ade1be20b3867d967bd2927c8eb0ca
Saved template to template.xml. Convert to XML format (.sdtid) with:
  stoken export --random --sdtid --template=template.xml > 838999658504.sdtid
```

Convert the template output to an RSA SecurID token in XML format with
`stoken`, as instructed:

```
$ stoken export --random --sdtid --template=template.xml > 838999658504.sdtid
```

Fake server
===========

The server (`fakeserver.py`) mimics a "real" RSA CT-KIP server and can
be used for interoperability testing with a "real" RSA SecurID client.
It accepts the requests sent by the client software at two different
paths: `/` for laziness, and `/ctkip/services/CtkipService`
in case any real client hard-codes this path.

It provisions tokens with randomly-generated 12-digit IDs, which it does
not retain. Official RSA SecurID clients for Windows and Android have
been verified to connect to it, and provision tokens from its output.

The server can run either via HTTP or HTTPS. For HTTPS, create a
`server.pem` file in the same directory. It must contain a trusted,
signed certificate in order for the RSA SecurID app to connect to it.

The `rsaprivkey.pem` is the RSA private key used for token
generation, and shouldn't need to be modified for testing
purposes. (The one included is a 1024-bit key with modulus 65537,
similar to what seem to be used by the "real" RSA CT-KIP server).

Credits
=======

* [@cemeyer](//github.com/cemeyer) for [kicking this off](//github.com/cernekee/stoken/issues/27)
  and doing most of the heavy lifting, including a working
  [`ct_kip_prf_aes` implementation](//gist.github.com/cemeyer/3293e4fcb3013c4ee2d1b6005e0561bf)
  and figuring out [all the mistakes](//github.com/cernekee/stoken/issues/27#issuecomment-456522178)
  in RSA's atrociously sloppy and misleading [RFC4758](//tools.ietf.org/html/rfc4758).
* [@rgerganov](//github.com/rgerganov) for
  [reverse engineering the official client](//github.com/cernekee/stoken/issues/27#issuecomment-456113939) and
  testing.
* [@cernekee](//github.com/cernekee) for writing `stoken` in the first place, and for explaining how to
  [convert a raw seed into a token](https://github.com/cernekee/stoken/issues/27#issuecomment-456473711).

TODO
====

* Convert raw seed into usable token _without_ invoking `stoken`?
* Add tests: verify that `client.py` can talk to `fakeserver.py` and negotiate the same `K_TOKEN`.

License
=======

[MIT](LICENSE.txt)
