from Crypto.Cipher import AES
from flask import Flask, request


app = Flask(__name__)

@app.route("/", methods=['POST', 'GET'])
def decrypt():
    ciphertext = bytes.fromhex(request.args.get('ciphertext'))
    header = bytes.fromhex(request.args.get('header'))
    nonce = bytes.fromhex(request.args.get('nonce'))
    tag = bytes.fromhex(request.args.get('tag'))

    key = b'fE\xfe\x91\xf5%\x16\xf8\xb2\xea\xad\xbd#\xb5\xe4\xb7'
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(header)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext,tag)
        return {'pt':plaintext.hex()}
    except:
        return "MAC check failed",400


if __name__ == "__main__":
    app.run(port=7000)