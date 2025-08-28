from secrets import token_bytes
from aes256_gcm import AES256_GCM
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import sha256

file = "./teste2.txt"

# Encrypt
key = urlsafe_b64encode(token_bytes(64))
with open('./key.txt', "wb") as wfile:
    wfile.write(key)
    
aes256 = AES256_GCM(key, token_bytes(16))
aes256.encrypt(file)

# Decrypt
# def coiso():
#     with open(file, "rb") as readfile:
#         return readfile.read(108)

# header = coiso()

# b64_hash = header[:86] + b'=='
# b64_salt = header[86:] + b'=='

# hex_hash = urlsafe_b64decode(b64_hash).decode()
# salt_hash = sha256(b64_salt).hexdigest()
# salt =  urlsafe_b64decode(b64_salt)

# def a():
#     with open('./key.txt', "rb") as rfile:
#         return rfile.read()
# key = a()

# aes256 = AES256_GCM(key, b'')
# aes256.decrypt(file)
