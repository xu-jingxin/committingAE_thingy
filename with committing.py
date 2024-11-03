# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


hash_key = get_random_bytes(16)  # for MAC
hash_key2 = get_random_bytes(16)  # for 2nd MAC

def encrypt(K, A, M):  # N is generated inside
    # the making of C
    cipher = AES.new(K, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(M)  # ct = b64encode(ct_bytes).decode('utf-8')
    nonce = cipher.nonce  # nonce = b64encode(cipher.nonce).decode('utf-8')

    # the making of T
    T = HMAC.new(hash_key, nonce+A+ct_bytes, digestmod=SHA256).digest()
    meta_T = HMAC.new(hash_key2, K+nonce+A+T, digestmod=SHA256).digest()
    return (ct_bytes, meta_T), A, nonce

# encrypting
AD = b"AD"
message = b"secret"
enc_key = get_random_bytes(16)

result = encrypt(enc_key, AD, message)


def decrypt(K,N,A,C):
    # check T
    T = HMAC.new(hash_key, N+A+C, digestmod=SHA256).digest()
    check = HMAC.new(hash_key2, K+N+A+T, digestmod=SHA256)
    check.verify(T_expected)

    # get message
    cipher = AES.new(K, AES.MODE_CTR,nonce=N)
    plaintext = cipher.decrypt(C)
    return plaintext

# decrypting
K = enc_key
N = result[2]
C = result[0][0]
T_expected = result[0][1]

print(decrypt(K,N,AD,C))

# making the MAC check fail
message_produced = decrypt(K,N,AD,C)
print("--------------- changing AD --------------")
AD = b"wrong AD"
decrypt(K,N,AD,C)
