#!/usr/bin/env python3
import ssl
import random
import zlib
from flask import Flask, request, abort, Response
from xml.etree import ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from common import hexlify, unhexlify, d64b, e64b, e64s, e64bs, d64s, d64sb
from ct_kip_prf_aes import ct_kip_prf_aes

#####
# Yay, encryption
#####

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('server.pem')

pubk = RSA.importKey(open('rsapubkey.pem').read())
privk = RSA.importKey(open('rsaprivkey.pem').read())

# The XML blobs in the protocol appear to indicate
# RSAES-PKCS1-v1_5 (RFC8017), but it's actually RSAES-OAEP (RFC8017)
cipher = PKCS1_OAEP.new(privk)

########################################

R_S = get_random_bytes(16)
print('********************************')
print('Using UNCHANGING server "nonce" R_S = {}'.format(hexlify(R_S)))
print('********************************')

app = Flask(__name__)
app.config.update(
    PORT=4443,
    HOST='localhost',
)

ns = {
    'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
    'ctkip': 'http://ctkipservice.rsasecurity.com',
    'ns0': 'http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#',
}

########################################

# Handle the gawdaful SOAPy layer on the outside

@app.route('/', methods=('POST',))
def unsoap():
    auth = request.headers.get('Authorization')
    assert request.content_type == 'application/vnd.otps.ct-kip'

    try:
        x = ET.fromstring(request.data.decode())
        assert x.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Envelope'

        cr = x.find('.//ctkip:ClientRequest', ns)
        ad = cr.find('ctkip:AuthData', ns)
        assert ad.text == auth
        pd = cr.find('ctkip:ProvisioningData', ns)
        r = cr.find('ctkip:Request', ns)

        pdx = ET.fromstring(d64b(pd.text))
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
  {}""".format(auth, ET.tostring(pdx).decode(), ET.tostring(rx).decode()))

        # respond to client
        sess = rx.attrib.get('SessionID')
        if rx.tag == '{http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#}ClientHello':
            res_pd, res_r = handle_ClientHello(sess, pdx, rx)
            compr = False
        elif rx.tag == '{http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#}ClientNonce':
            res_pd, res_r = handle_ClientNonce(sess, pdx, rx)
            compr = True

        r = Response(mimetype='text/xml', response='''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <ServerResponse xmlns="http://ctkipservice.rsasecurity.com">
      <AuthData>{auth}</AuthData>
      <ProvisioningData>{pd}</ProvisioningData>
      <Response>{res}</Response>
    </ServerResponse>
  </soapenv:Body>
</soapenv:Envelope>'''.format(auth=auth, pd=e64s(res_pd), res=e64s(res_r))
        )
        r.headers['X-Powered-By'] = 'Servlet/3.0 JSP/2.2'
        setattr(r, 'allow_compression', compr)

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

    return ET.tostring(pdx).decode(), '''<?xml version="1.0" encoding="UTF-8"?>
<ServerHello xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" SessionID="{sess}" Status="Continue" Version="1.0">
  <KeyType xmlns="">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/otps-wst#SecurID-AES</KeyType>
  <EncryptionAlgorithm xmlns="">http://www.w3.org/2001/04/xmlenc#rsa-1_5</EncryptionAlgorithm>
  <EncryptionKey xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <ds:KeyValue xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <ds:RSAKeyValue xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ds:Modulus>{mod}</ds:Modulus>
        <ds:Exponent>{exp}</ds:Exponent>
      </ds:RSAKeyValue>
    </ds:KeyValue>
  </EncryptionKey>
  <Payload xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <Nonce xmlns="">{R_S}</Nonce>
  </Payload>
  <Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <Extension xmlns:ct-kip="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <Data>{R_S}</Data>
    </Extension>
  </Extensions>
  <MacAlgorithm xmlns="">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#ct-kip-prf-aes</MacAlgorithm>
</ServerHello>'''.format(sess = sess, R_S = e64bs(R_S).rstrip(),
                         mod = e64bs(number.long_to_bytes(pubk.n)).rstrip(),
                         exp = e64bs(number.long_to_bytes(pubk.e)).rstrip() )


def handle_ClientNonce(sess, pdx, rx):
    # Decrypt the ClientNonce (this will be the token secret)
    R_C_enc = d64b(rx.find('.//EncryptedNonce', ns).text)
    print("ENcrypted ClientNonce: {}".format(hexlify(R_C_enc)))
    R_C = cipher.decrypt(R_C_enc)
    print("DEcrypted ClientNonce: {}".format(hexlify(R_C)))

    tid = '%012d' % random.randint(1, 999999999999)    # Random 12-digit decimal number
    exp = '2019-01-01T00:00:00+00:00'                  # ISO9601 datetime

    K_TOKEN = ct_kip_prf_aes(R_C, number.long_to_bytes(pubk.n), b"Key generation", R_S)
    MAC = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
    print("K_TOKEN (hex): ", hexlify(K_TOKEN))
    print("MAC (hex): ", hexlify(MAC))

    pdr = '''<?xml version="1.0"?>\n<ProvisioningData><PinType>0</PinType><AddPIN>1</AddPIN></ProvisioningData>'''
    r='''<?xml version="1.0" encoding="UTF-8"?>
<ServerFinished xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" SessionID="{sess}" Status="Success" Version="1.0">
  <TokenID xmlns="">{tid}</TokenID>
  <KeyID xmlns="">{tid}</KeyID>
  <KeyExpiryDate xmlns="">{exp}</KeyExpiryDate>
  <ServiceID xmlns="">RSA CT-KIP</ServiceID>
  <UserID xmlns=""/>
  <Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <Extension xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Critical="true">
      <OTPFormat>Decimal</OTPFormat>
      <OTPLength>8</OTPLength>
      <OTPMode xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <Time xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" TimeInterval="60"/>
      </OTPMode>
    </Extension>
  </Extensions>
  <Mac xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" MacAlgorithm="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#ct-kip-prf-aes">
    {MAC}
  </Mac>
</ServerFinished>'''.format(tid = e64s(tid).rstrip(), exp=exp, sess=sess,
                            MAC = e64bs(MAC).rstrip())

    return pdr, r


########################################

class Deflate(object):
    def __init__(self, app, compress_level=6, minimum_size=500):
        self.app = app
        self.compress_level = compress_level
        self.minimum_size = minimum_size
        self.app.after_request(self.after_request)

    def after_request(self, response):
        if response.status_code < 200 or \
           response.status_code >= 300 or \
           response.direct_passthrough or \
           not getattr(response, 'allow_compression', True) or \
           len(response.data) < self.minimum_size or \
           'Content-Encoding' in response.headers:
            return response

        response.data = zlib.compress(response.data, self.compress_level)
        response.headers['Content-Encoding'] = 'deflate'
        response.headers['Content-Length'] = len(response.data)
        return response


Deflate(app)
app.run(host=app.config['HOST'],
        port=app.config['PORT'],
        debug=True,
        ssl_context=context)
