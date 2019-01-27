####
# Base64 encode (bytes-to-bytes)   e64b
#        decode (bytes-to-bytes)   d64b
#        encode (string-to-string) e64s
#        encode (bytes-to-string)  e64bs
#        decode (string-to-string) d64s
#        decode (string-to-bytes)  d64sb

from binascii import b2a_base64 as e64b, a2b_base64 as d64b, hexlify, unhexlify
def e64s(x):
  return e64b(x.encode()).decode()
def e64bs(x):
  return e64b(x).decode()
def d64s(x):
  return d64b(x.encode()).decode()
def d64sb(x):
  return d64b(x.encode())
def hexlifys(x):
  return hexlify(x).decode()

# XML namespaces used in exchange:

ns = {
    'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
    'ctkip': 'http://ctkipservice.rsasecurity.com',
    'dsig': 'http://www.w3.org/2000/09/xmldsig#',
    'otps': 'http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#',
}
