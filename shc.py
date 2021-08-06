import json
import base64
import zlib
import sys

NUM_OFFSET = 48
SHC_OFFEST = 45


def inflate(compressed_data):
    # -15 for the window buffer will make it ignore headers/footers
    zlibbed_data = zlib.decompress(compressed_data, -15)
    return zlibbed_data


def base64_decode(data):
    return base64.urlsafe_b64decode(data + '==')


def main():
    if len(sys.argv) != 2:
        print("Usage: python shc.py <shc>")
        sys.exit(1)
    shc = sys.argv[1]

    if not shc.startswith("shc:/"):
        print("Payload must start with shc:/")
        sys.exit(2)

    out = []
    shc = [ord(c) for c in shc[5:]]

    for i in range(0, len(shc) - 1, 2):
        c = (shc[i] - NUM_OFFSET) * 10 + (shc[i + 1] - NUM_OFFSET) + SHC_OFFEST
        out.append(chr(c))

    [header, payload, sig] = ''.join(out).split('.')
    header = json.loads(base64_decode(header))
    payload = json.loads(inflate(base64_decode(payload)))
    sig = base64_decode(sig)

    print(json.dumps(payload, indent=4))


if __name__ == "__main__":
    main()
