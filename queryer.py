import json

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

header = b"header"
data = b"secret"
key = b'fE\xfe\x91\xf5%\x16\xf8\xb2\xea\xad\xbd#\xb5\xe4\xb7' # get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CCM)
cipher.update(header)
ciphertext, tag = cipher.encrypt_and_digest(data)

pack = {
    'nonce': cipher.nonce.hex(),
    'header': header.hex(),
    'ciphertext': ciphertext.hex(),
    'tag': '1234'
}
print(pack)

rep = requests.get(url='http://127.0.0.1:7000/', params=pack)
print(rep)
ans = rep.json()['pt']
result_string = ''.join([chr(int(ans[i:i + 2], 16)) for i in range(0, len(ans), 2)])
print(result_string)