from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


hash_key = get_random_bytes(16)  # for MAC

def encrypt(K, A, M):  # N is generated ltr
    # the making of C
    cipher = AES.new(K, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(M)  # ct = b64encode(ct_bytes).decode('utf-8')
    nonce = cipher.nonce  # nonce = b64encode(cipher.nonce).decode('utf-8')

    # the making of T
    T = HMAC.new(hash_key, nonce+AD+ct_bytes, digestmod=SHA256).digest()

    return (ct_bytes, T), AD, nonce

# encrypting
AD = b"AD"
message = b"secret"
enc_key = get_random_bytes(16)

result = encrypt(enc_key, AD, message)
print(result)


def decrypt(K,N,A,C):
    # check T
    check = HMAC.new(hash_key, N+A+C, digestmod=SHA256)
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

message_produced = decrypt(K,N,AD,C)
print(message_produced)


# making the MAC check fail
print("--------------- tripping it --------------")
C = b"wrong ciphertext"
decrypt(K,N,AD,C)
