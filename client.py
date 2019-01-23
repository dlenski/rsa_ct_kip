#!/usr/bin/env python3
import random
import requests
import argparse
from requests import Request
from xml.etree import ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from common import e64b, e64s, d64s, d64b, d64sb, hexlify, unhexlify
from ct_kip_prf_aes import ct_kip_prf_aes

########################################

class Soapifier(object):
    soap_env_tmpl = '''<?xml version="1.0" encoding="UTF-8"?>
      <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <soapenv:Body>
          <{0} xmlns="http://ctkipservice.rsasecurity.com">
            <AuthData >{2}</AuthData>
            <ProvisioningData>{3}</ProvisioningData>
            <{1}>{4}</{1}>
          </{0}>
        </soapenv:Body>
      </soapenv:Envelope>'''

    def __init__(self, url, auth):
        self.url = url
        self.auth = auth

    def make_ClientRequest(self, action, provisioning_data, body):
        outer, inner = 'ClientRequest', 'Request'
        soap = self.soap_env_tmpl.format(
            outer, inner, self.auth,
            e64s(provisioning_data), e64s(body))
        return Request('POST', self.url, data=soap, headers={
            'Authorization': self.auth,
            'SOAPAction': action,
            'content-type': 'application/vnd.otps.ct-kip'})

    def parse_ServerResponse(self, response):
        outer, inner = 'ServerResponse', 'Response'

        x = ET.fromstring(response.content)
        fault = x.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Fault')
        if fault is not None:
            faultcode = fault.find('faultcode').text
            faultstring = fault.find('faultstring').text
            raise RuntimeError(faultcode, faultstring)

        assert x.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Envelope'
        r = x.find('.//{http://ctkipservice.rsasecurity.com}' + outer)
        ad = r.find('{http://ctkipservice.rsasecurity.com}AuthData')
        assert ad.text == self.auth #== response.headers.get('Authorization')
        pd = r.find('{http://ctkipservice.rsasecurity.com}ProvisioningData')
        rr = r.find('{http://ctkipservice.rsasecurity.com}' + inner)

        return ET.fromstring(d64s(pd.text)), ET.fromstring(d64s(rr.text))

########################################

pd='''<?xml version="1.0"?><ProvisioningData><Version>5.0.2.440</Version><Manufacturer>RSA Security Inc.</Manufacturer><FormFactor/></ProvisioningData>'''
req1='''<ClientHello xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="1.0"><SupportedKeyTypes xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/otps-wst#SecurID-AES</Algorithm></SupportedKeyTypes><SupportedEncryptionAlgorithms xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.w3.org/2001/04/xmlenc#rsa-1_5</Algorithm></SupportedEncryptionAlgorithms><SupportedMACAlgorithms xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#ct-kip-prf-aes</Algorithm></SupportedMACAlgorithms></ClientHello>'''
req2_tmpl='''<?xml version="1.0" encoding="UTF-8"?><ClientNonce xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#" Version="1.0" SessionID="{session_id}"><EncryptedNonce xmlns="">{encrypted_client_nonce}</EncryptedNonce><Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Extension xmlns="" xmlns:ct-kip="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Data>{server_nonce}</Data></Extension></Extensions></ClientNonce>'''

p = argparse.ArgumentParser()
p.add_argument('-v', '--verbose', action='count')
p.add_argument('-k', '--no-verify', dest='verify', action='store_false', default=True, help="Don't verify server TLS cert")
p.add_argument('url')
p.add_argument('activation_code')
args = p.parse_args()

s = requests.session()
s.headers['user-agent'] = 'HTTPPOST'
soap = Soapifier(args.url, args.activation_code)

# send initial request
req1 = soap.make_ClientRequest('StartService', pd, req1)

# get session ID, server key, and server nonce in response
raw_res1 = s.send(s.prepare_request(req1), verify=args.verify)
if args.verbose:
    print(raw_res1.text)
pd_res1, res1 = soap.parse_ServerResponse(raw_res1)
if args.verbose:
    print(res1)

session_id = res1.attrib['SessionID']
k = res1.find('.//{http://www.w3.org/2000/09/xmldsig#}RSAKeyValue')
mod = number.bytes_to_long(d64sb(k.find(
  '{http://www.w3.org/2000/09/xmldsig#}Modulus').text))
exp = number.bytes_to_long(d64sb(k.find(
  '{http://www.w3.org/2000/09/xmldsig#}Exponent').text))
pubk = RSA.construct( (int(mod), int(exp)) )
pl = res1.find('.//Payload')
R_S = server_nonce = d64sb(pl.find('Nonce').text)

print("Got server nonce and RSA pubkey:\n{}\n{}".format(
    hexlify(server_nonce), pubk.exportKey('PEM').decode()))

# generate and encrypt client nonce
R_C = client_nonce = get_random_bytes(16)
cipher = PKCS1_OAEP.new(pubk)
encrypted_client_nonce = cipher.encrypt(client_nonce)
print("Generated client nonce:\n\tplaintext: {}\n\tencrypted: {}".format(
    hexlify(client_nonce), hexlify(encrypted_client_nonce)))

# send second request
req2_filled = req2_tmpl.format(
  session_id=session_id, encrypted_client_nonce=e64b(encrypted_client_nonce).decode(),
  server_nonce=e64b(server_nonce).decode())
req2 = soap.make_ClientRequest('ServerFinished', pd, req2_filled)
pd_res2, res2 = soap.parse_ServerResponse(s.send(s.prepare_request(req2), verify=args.verify))

if args.verbose:
    print(res2)

# get stuff from response
key_id = d64b(res2.find('TokenID').text)
token_id = d64b(res2.find('KeyID').text)
key_exp = res2.find('KeyExpiryDate').text
mac = d64b(res2.find('Mac').text)
print("Got key ID, token ID, key expiration date, and MAC:"
      "\nKeyID: {}\nTokenID: {}\nExpiration: {}".format(
        key_id, token_id, key_exp))

# verify MAC and token
K_TOKEN = ct_kip_prf_aes(R_C, number.long_to_bytes(pubk.n), b"Key generation", R_S)
MAC_VER = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
if MAC_VER==mac:
    print("MAC verified. K_TOKEN is: {}".format(hexlify(K_TOKEN)))
else:
    print("MAC not verified! Expected {} but server sent {}".format(hexlify(MAC_VER), hexlify(mac)))
