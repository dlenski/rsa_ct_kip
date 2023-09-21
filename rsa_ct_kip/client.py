#!/usr/bin/env python3
import requests
import argparse
import shutil
from subprocess import check_call, check_output, CalledProcessError
from tempfile import NamedTemporaryFile
from requests import Request
from xml.etree import ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from .common import e64s, e64bs, d64s, d64b, d64sb, hexlify, hexlifys, ns
from .ct_kip_prf_aes import ct_kip_prf_aes


########################################

def get_text(node, convert=None, default=None, getter=None):
    if node is None:
        return default
    text = getter(node) if getter else node.text
    if convert:
        try:
            return convert(text)
        except Exception:
            return default
    else:
        return text or default


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
        cruft = 'java.rmi.RemoteException: The CT-KIP Web Service failed to process a client request.'
        nested = 'nested exception is:'

        response.raise_for_status()
        x = ET.fromstring(response.content)
        fault = x.find('.//soapenv:Fault', ns)
        if fault is not None:
            faultcode = fault.find('faultcode').text
            faultstring = fault.find('faultstring').text
            if faultcode == 'soapenv:Server.userException' and faultstring.startswith(cruft):
                rest = faultstring[len(cruft):].lstrip()
                if nested in rest:
                    rest = rest[rest.index(nested) + len(nested):].lstrip()
                exc, msg = rest.split(': ', 1)
                raise RuntimeError(exc, msg, faultstring)
            raise RuntimeError(faultcode, faultstring, None)

        assert x.tag == '{http://schemas.xmlsoap.org/soap/envelope/}Envelope'
        r = x.find('soapenv:Body/ctkip:' + outer, ns)
        ad = r.find('ctkip:AuthData', ns)
        assert ad.text == self.auth  # == response.headers.get('Authorization')
        pd = r.find('ctkip:ProvisioningData', ns)
        rr = r.find('ctkip:' + inner, ns)

        return ET.fromstring(d64s(pd.text)), ET.fromstring(d64s(rr.text))


########################################

pd = '''<?xml version="1.0"?><ProvisioningData><Version>5.0.2.440</Version><Manufacturer>RSA Security Inc.</Manufacturer><FormFactor/></ProvisioningData>'''
req1_hello = '''<ClientHello xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="1.0"><SupportedKeyTypes xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/otps-wst#SecurID-AES</Algorithm></SupportedKeyTypes><SupportedEncryptionAlgorithms xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.w3.org/2001/04/xmlenc#rsa-1_5</Algorithm></SupportedEncryptionAlgorithms><SupportedMACAlgorithms xmlns=""><Algorithm xsi:type="xsd:anyURI">http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#ct-kip-prf-aes</Algorithm></SupportedMACAlgorithms></ClientHello>'''
req2_tmpl = '''<?xml version="1.0" encoding="UTF-8"?><ClientNonce xmlns="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/11/ct-kip#" Version="1.0" SessionID="{session_id}"><EncryptedNonce xmlns="">{eR_C}</EncryptedNonce><Extensions xmlns="" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Extension xmlns="" xmlns:ct-kip="http://www.rsasecurity.com/rsalabs/otps/schemas/2005/12/ct-kip#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Data>{R_S}</Data></Extension></Extensions></ClientNonce>'''


def parse_args(args=None):
    stoken = shutil.which('stoken')
    p = argparse.ArgumentParser()
    p.add_argument('-v', '--verbose', action='count')
    p.add_argument('-k', '--no-verify', dest='verify', action='store_false', default=True, help="Don't verify server TLS cert")
    p.add_argument('-s', '--hide-secret', action='store_true', help="Don't print any secret values to console output. (Nonces and seed could be used to clone token.)")
    p.add_argument('url', help='Activation URL provided to you (often ends with /ctkip/services/CtkipService)')
    p.add_argument('activation_code', help='Normally 12 digits long')
    p.add_argument('--no-save', action='store_true', help="Don't save the token, even though any real RSA server will have already committed it.")
    p.add_argument('filename', nargs='?', type=argparse.FileType('w'), help=(
        'Save token in XML/.sdtid format (uses stoken found in path)' if stoken
        else 'Save a template file which can be converted to a token in XML/.sdtid format with stoken'))
    args = p.parse_args(args)

    if not args.filename and not args.no_save:
        p.error("Must specify either --no-save or destination filename")

    return p, args, stoken

def exchange(url, activation_code, verify=None, verbose=None, hide_secret=None, session=None):
    global pd, req1_hello, req2_tmpl

    if session:
        s = session
    else:
        s = requests.session()
        s.verify = verify
        s.headers['user-agent'] = 'HTTPPOST'
    soap = Soapifier(url, activation_code)

    # send initial request
    req1 = soap.make_ClientRequest('StartService', pd, req1_hello)

    # get session ID, server key, and server nonce in response
    print("Sending ClientHello request to server...")
    raw_res1 = s.send(s.prepare_request(req1))
    if verbose:
        print(raw_res1.text)
    pd_res1, res1 = soap.parse_ServerResponse(raw_res1)
    if verbose:
        print(ET.tostring(res1))

    session_id = res1.attrib['SessionID']
    k = res1.find('EncryptionKey/dsig:KeyValue/dsig:RSAKeyValue', ns)
    mod = number.bytes_to_long(d64sb(k.find('dsig:Modulus', ns).text))
    exp = number.bytes_to_long(d64sb(k.find('dsig:Exponent', ns).text))
    pubk = RSA.construct((int(mod), int(exp)))
    R_S = d64sb(res1.find('Payload/Nonce').text)

    print("Received ServerHello response with server nonce (R_S = {}) and {}-bit RSA public key".format(
        'HIDDEN' if hide_secret else hexlifys(R_S), len(number.long_to_bytes(pubk.n)) * 8))

    # generate and encrypt client nonce
    # The XML blobs in the protocol appear to indicate
    # RSAES-PKCS1-v1_5 (RFC8017), but it's actually RSAES-OAEP (RFC8017)
    R_C = get_random_bytes(16)
    print("Generated client nonce (R_C = {})".format('HIDDEN' if hide_secret else hexlifys(R_C)))
    cipher = PKCS1_OAEP.new(pubk)
    eR_C = cipher.encrypt(R_C)
    if verbose:
        print("Encrypted client nonce with server's RSA public key: {}".format(hexlifys(eR_C)))

    # send second request
    req2_filled = req2_tmpl.format(session_id=session_id, eR_C=e64bs(eR_C), R_S=e64bs(R_S))
    req2 = soap.make_ClientRequest('ServerFinished', pd, req2_filled)
    print("Sending ServerFinished request to server, with encrypted client nonce...")
    raw_res2 = s.send(s.prepare_request(req2))
    if verbose:
        print(raw_res2.text)
    pd_res2, res2 = soap.parse_ServerResponse(raw_res2)
    if verbose:
        print(ET.tostring(res2))

    # get details from response
    details = dict(
        service_id=get_text(res2.find('ServiceID')),
        key_id=get_text(res2.find('TokenID'), d64s),
        token_id=get_text(res2.find('KeyID'), d64s),
        key_exp=get_text(res2.find('KeyExpiryDate')),
        user=get_text(res2.find('UserID'), default=''),
        pin_type=get_text(pd_res2.find('PinType'), int, 0),
        add_pin=get_text(pd_res2.find('AddPIN'), int, 1),
        otpformat='Decimal',
        otplength=8,
        otptime=60,
    )
    otpext = res2.find('Extensions/Extension')
    if otpext:
        details.update(
            otpformat=get_text(otpext.find('OTPFormat'), default='Decimal'),
            otplength=get_text(otpext.find('OTPLength'), int, 8),
            otptime=get_text(otpext.find('otps:OTPMode/otps:Time', ns), int, 60, lambda n: n.attrib.get('TimeInterval')),
        )

    # verify MAC and token
    K_TOKEN = details['K_TOKEN'] = ct_kip_prf_aes(R_C, number.long_to_bytes(pubk.n), b"Key generation", R_S)
    MAC_VER = ct_kip_prf_aes(K_TOKEN, b"MAC 2 Computation", R_C)
    mac = get_text(res2.find('Mac'), d64b)
    if MAC_VER == mac:
        print("MAC verified ({})".format(hexlifys(MAC_VER)))
        return details
    else:
        raise IOError("MAC not verified! Expected {} but server sent {}.".format(hexlifys(MAC_VER), hexlify(mac)),
                      details, MAC_VER, mac)


STOKEN_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<TKNBatch>
  <TKNHeader>
    <Origin>{service_id}</Origin>
    <DefPinType>{pin_type}</DefPinType>
    <DefAddPin>{add_pin}</DefAddPin>
    <DefDigits>{otplength}</DefDigits>
    <DefInterval>{otptime}</DefInterval>
    <Secret>{K_TOKEN_b64}</Secret>
  </TKNHeader>
  <TKN>
    <SN>{token_id}</SN>
    <UserLogin>{user}</UserLogin>
    <Death>{key_exp_stoken}</Death>
    <Seed>={K_TOKEN_b64}</Seed>
  </TKN>
</TKNBatch>'''

def main(args=None):
    p, args, stoken = parse_args(args)

    try:
        token = exchange(args.url, args.activation_code, args.verify, args.verbose, args.hide_secret)
    except requests.exceptions.RequestException as e:
        p.exit(1, "Exception in HTTP(S) request: {}\n\t{}\n".format(e.__class__.__name__, '\n\t'.join(e.args)))
    except RuntimeError as e:
        code, msg, raw = e.args
        if raw is None:
            p.exit(1, "Fault from server: {}\n\t{}\n".format(code, msg))
        else:
            p.exit(1, "Fault from server:\n\t{}\n\nParsed exception:\n\t{}: {}\n".format(raw, code, msg))
    except Exception as e:
        p.exit(1, e.args[0] if e.args else e.__class__.__name__)

    # output token information
    token['K_TOKEN_vis'] = 'HIDDEN' if args.hide_secret else hexlifys(token['K_TOKEN'])
    print("Received ServerFinished response with token information:\n"
          "  Service ID: {service_id}\n"
          "  Key ID: {key_id}\n"
          "  Token ID: {token_id}\n"
          "  Token User: {user}\n"
          "  Expiration date: {key_exp}\n"
          "  OTP mode: {otplength} {otpformat}, every {otptime} seconds\n"
          "  Token seed: {K_TOKEN_vis}".format(**token))

    if not args.filename:
        print("WARNING: You requested not to save the token, but it has already been committed on server.")
    else:
        token['K_TOKEN_b64'] = e64bs(token['K_TOKEN']).strip()
        token['key_exp_stoken'] = token['key_exp'][:10].replace('-', '/')
        with (NamedTemporaryFile(mode='w', delete=False) if stoken else args.filename) as f:
            f.write(STOKEN_TEMPLATE.format(**token))
        if stoken:
            try:
                check_call([stoken, 'export', '--random', '--sdtid', '--template', f.name], stdout=args.filename)
            except (OSError, CalledProcessError) as e:
                print("WARNING: Failed to save token to XML/.sdtid format with stoken. See template.\n\t{}".format(e))
            else:
                f = None
                if args.verbose and not args.hide_secret:
                    ctf = check_output([stoken, 'export', '--file', args.filename.name], universal_newlines=True).strip()
                    print("  Token in CTF format: {}".format(ctf))
                print("Saved token in XML/.sdtid format to {}".format(args.filename.name))
        if f:
            print("Saved template to {}. Working stoken is needed to convert it to XML/.sdtid format:".format(f.name))
            print("  stoken export --random --sdtid --template={} > {}".format(
                f.name, args.filename.name if args.filename.name != f.name else token['token_id'] + '.sdtid'))


if __name__ == '__main__':
    main()
