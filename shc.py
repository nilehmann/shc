import json
import base64
import zlib
import sys
import urllib.request
import cryptography
from jwcrypto import jwa, jwk
import cryptography


NUM_OFFSET = 48
SHC_OFFEST = 45


def inflate(compressed_data):
    # -15 for the window buffer will make it ignore headers/footers
    zlibbed_data = zlib.decompress(compressed_data, -15)
    return zlibbed_data


def base64_decode(data):
    return base64.urlsafe_b64decode(data + b'==')


def main():
    if len(sys.argv) != 2:
        print("Usage: python shc.py <shc>")
        sys.exit(1)
    shc = sys.argv[1]

    if not shc.startswith("shc:/"):
        print("Payload must start with shc:/")
        sys.exit(2)

    raw_token = []
    shc = [ord(c) for c in shc[5:]]

    for i in range(0, len(shc) - 1, 2):
        c = (shc[i] - NUM_OFFSET) * 10 + (shc[i + 1] - NUM_OFFSET) + SHC_OFFEST
        raw_token.append(chr(c))
    raw_token = ''.join(raw_token).encode()

    [raw_header, raw_payload, raw_sig] = raw_token.split(b'.')
    header = json.loads(base64_decode(raw_header))
    payload = json.loads(inflate(base64_decode(raw_payload)))
    sig = base64_decode(raw_sig)

    response = urllib.request.urlopen(f"{payload['iss']}/.well-known/jwks.json")

    keys = jwk.JWKSet.from_json(response.read())
    key = keys.get_key(header['kid'])
    alg = jwa.JWA.signing_alg('ES256')

    print("Header:", json.dumps(header))
    print("Payload:", json.dumps(payload))

    try:
        alg.verify(key, raw_header + b'.' + raw_payload, sig)
    except cryptography.exceptions.InvalidSignature:
        print("Invalid signature")


if __name__ == "__main__":
    main()
