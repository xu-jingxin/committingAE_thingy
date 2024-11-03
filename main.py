from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes


def E1(K,N,A,M):
    cipher = AES.new(K, AES.MODE_CTR)
    C = cipher.encrypt(M)
    return C

E2_key = get_random_bytes(16)
def E2(K,N,A,M):
    hmac = HMAC.new(E2_key, digestmod=SHA256)
    tag = hmac.update(K+N+A+M).digest()
    return tag

H_key = get_random_bytes(16)
def H(K,N,A,T):
    hmac = HMAC.new(H_key, digestmod=SHA256)
    tag = hmac.update(K+N+A+T).digest()
    return tag
def D1(K,N,A,C):
    cipher = AES.new(K, AES.MODE_CTR, nonce=N)
    return cipher.decrypt(C)
def CTXenc(K, N, A, M):
    C = E1(K, N, A, M)
    T = E2(K,N,A,M)
    T1 = H(K,N,A,T)
    return (C,T1)
# (C,T1) is sent together with N and AD. The other party should already know K, E1_key and H_key

def CTXdec(K,N,A,C_T1):
    C,T1=C_T1
    M = D1(K, N, A, C)
    T = E2(K, N, A, M)
    T2 = H(K, N, A, T)
    if T2 != T1:
        print(T2)
        print(T1)
        return ValueError
    else: return M

K = get_random_bytes(16)  # key
cipher = AES.new(K, AES.MODE_CTR)
N = cipher.nonce
A = 'associated data'.encode()
M = 'secret data to transmit'.encode()  # message


lump = CTXenc(K,N,A,M)
print(CTXdec(K,N,A,lump))