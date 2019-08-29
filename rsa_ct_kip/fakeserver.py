#!/usr/bin/env python3
import ssl
import random
import os
from datetime import datetime, timedelta
from flask import Flask, request, abort, Response
from xml.etree import ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from rsa_ct_kip.common import hexlify, unhexlify, d64b, e64b, e64s, e64bs, d64s, d64sb, ns
from rsa_ct_kip.ct_kip_prf_aes import ct_kip_prf_aes

#####
# Yay, encryption
#####

here = os.path.abspath(os.path.dirname(__file__))
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('server.pem')
    port = 4443
except Exception as e:
    print("Couldn't load server.pem from current directory: will run as plain HTTP, not HTTPS")
    context = None
    port = 8080

privk = RSA.importKey(open(os.path.join(here, '..', 'rsaprivkey.pem')).read())
pubk = privk.publickey()

# The XML blobs in the protocol appear to indicate
# RSAES-PKCS1-v1_5 (RFC8017), but it's actually RSAES-OAEP (RFC8017)
cipher = PKCS1_OAEP.new(privk)

########################################

app = Flask(__name__)
app.config.update(
    PORT=port,
    HOST='localhost',
)

########################################

# Handle the gawdaful SOAPy layer on the outside

@app.route('/', methods=('POST',))
@app.route('/ctkip/services/CtkipService', methods=('POST',))
def unsoap():
    auth = request.headers.get('Authorization')
    assert request.content_type == 'application/vnd.otps.ct-kip'

    try:
        x = ET.fromstring(request.data.decode())
        assert x.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Envelope'

        cr = x.find('soapenv:Body/ctkip:ClientRequest', ns)
        ad = cr.find('ctkip:AuthData', ns)
        assert ad.text == auth
        pd = cr.find('ctkip:ProvisioningData', ns)
        r = cr.find('ctkip:Request', ns)

        pdx = d64b(pd.text)
        rx = ET.fromstring(d64b(r.text))

        print("""
Client sent:
  Authorization:
  ====================
  {}

  ProvisioningData:
  ====================
  {}

  Request:
  ====================
  {}""".format(auth, pdx.decode(), ET.tostring(rx).decode()))

        # respond to client
        sess = rx.attrib.get('SessionID')
        if rx.tag == '{http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#}ClientHello':
            res_pd, res_r = handle_ClientHello(sess, pdx, rx)
        elif rx.tag == '{http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#}ClientNonce':
            res_pd, res_r = handle_ClientNonce(sess, pdx, rx)

        r = Response(mimetype='text/xml', response='''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ServerResponse xmlns="http://ctkipservice.rsasecurity.com">
      <AuthData>{auth}</AuthData>
      <ProvisioningData>{pd}</ProvisioningData>
      <Response>{res}</Response>
    </ServerResponse>
  </soapenv:Body>
</soapenv:Envelope>'''.format(auth=auth,pd=e64s(res_pd), res=e64s(res_r))
        )
        r.headers['X-Powered-By'] = 'Servlet/3.0 JSP/2.2'

        print("""
Server will send:
  ProvisioningData:
  ====================
  {}

  Response:
  ====================
  {}

  SOAPified:
  ====================
  {}""".format(res_pd, res_r, r.data.decode()))


        return r

    except Exception as e:
        print(e)
        abort(500)

########################################

def handle_ClientHello(sess, pdx, rx):
    if sess is None:
        sess = hexlify(get_random_bytes(17)).decode() + '-' + e64bs(get_random_bytes(56) + b'\0').rstrip()

    # This is our "server nonce" which the client will parrot back to us, along with its (encrypted) "client nonce"
    R_S = get_random_bytes(16)

    return pdx.decode(), '''<?xml version="1.0" encoding="UTF-8"?><ServerHello xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" SessionID="{sess}" Status="Continue" Version="1.0"><KeyType xmlns="">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/otps-wst#SecurID-AES</KeyType>
<EncryptionAlgorithm xmlns="">http://www.w3.org/2001/04/xmlenc#rsa-1_5</EncryptionAlgorithm>
<EncryptionKey xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ds:KeyValue xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ds:RSAKeyValue xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ds:Modulus>{mod}</ds:Modulus>
<ds:Exponent>{exp}</ds:Exponent>
</ds:RSAKeyValue>
</ds:KeyValue>
</EncryptionKey>
<Payload xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Nonce xmlns="">{R_S}</Nonce>
</Payload>
<Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Extension xmlns:ct-kip="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Data>{R_S}</Data>
</Extension>
</Extensions>
<MacAlgorithm xmlns="">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#ct-kip-prf-aes</MacAlgorithm>
</ServerHello>'''.format(sess = sess, R_S = e64bs(R_S).rstrip(),
                         mod = e64bs(number.long_to_bytes(pubk.n)).rstrip(),
                         exp = e64bs(number.long_to_bytes(pubk.e)).rstrip() )


def handle_ClientNonce(sess, pdx, rx):
    # The client parrots our nonce back to us (a server with REEL SECURITEH would check that it matches, I guess...?)
    R_S = d64b(rx.find('Extensions/Extension/Data', ns).text)

    # Decrypt the ClientNonce (this will be the token secret)
    R_C_enc = d64b(rx.find('EncryptedNonce', ns).text)
    print("ENcrypted ClientNonce: {}".format(hexlify(R_C_enc)))
    R_C = cipher.decrypt(R_C_enc)
    print("DEcrypted ClientNonce: {}".format(hexlify(R_C)))

    tid = '%012d' % random.randint(1, 999999999999)    # Random 12-digit decimal number
    exp = datetime.utcnow() + timedelta(days=365)
    exp = exp.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()+'+00:00'  # ISO9601 datetime

    K_TOKEN = ct_kip_prf_aes(R_C, number.long_to_bytes(pubk.n), b"Key generation", R_S)
    MAC = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
    print("K_TOKEN (hex): ", hexlify(K_TOKEN))
    print("MAC (hex): ", hexlify(MAC))
    print("Token ID: ", tid)
    print("Token expiration date: ", exp)

    pdr = '''<?xml version="1.0"?>\n<ProvisioningData>\n<PinType>0</PinType><AddPIN>1</AddPIN></ProvisioningData>\n'''
    r='''<?xml version="1.0" encoding="UTF-8"?><ServerFinished xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" SessionID="{sess}" Status="Success"><TokenID xmlns="">{tid}</TokenID>
<KeyID xmlns="">{tid}</KeyID>
<KeyExpiryDate xmlns="">{exp}</KeyExpiryDate>
<ServiceID xmlns="">RSA CT-KIP</ServiceID>
<UserID xmlns=""/>
<Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Extension Critical="true" xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><OTPFormat>Decimal</OTPFormat>
<OTPLength>8</OTPLength>
<OTPMode xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Time TimeInterval="60" xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
</OTPMode>
</Extension>
</Extensions>
<Mac xmlns="" MacAlgorithm="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#ct-kip-prf-aes" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{MAC}</Mac>
</ServerFinished>'''.format(tid = e64s(tid).rstrip(), exp=exp, sess=sess,
                            MAC = e64bs(MAC).rstrip())

    return pdr, r


########################################

app.run(host=app.config['HOST'],
        port=app.config['PORT'],
        debug=True,
        ssl_context=context)
