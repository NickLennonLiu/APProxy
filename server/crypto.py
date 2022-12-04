import json
import base64

import rsa.key
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto import Random

def pad(text, mod):
    while len(text) % mod != 0:
        text += '\0'
    return text

def decode_base64(data):
    missing_padding = 4-len(data)%4
    if missing_padding:
        data += b'='*missing_padding
    return data

def preprocess_key(password, length):
    encoded = base64.b64encode(str.encode(password)).decode()
    if len(encoded) > length:
        encoded = encoded[:length]
    return pad(encoded, length)


def encrypt_aes(text, key):
    aes_key = preprocess_key(key, 32)
    aes = AES.new(str.encode(aes_key), AES.MODE_ECB)
    encrypted = str(base64.encodebytes(aes.encrypt(str.encode(pad(text, 16)))),
                       encoding='utf8').replace('\n', '')
    return encrypted

def decrypt_aes(encrypted, key):
    aes_key = preprocess_key(key, 32)
    aes = AES.new(str.encode(aes_key), AES.MODE_ECB)
    decrypted = str(aes.decrypt(base64.decodebytes(bytes(encrypted, encoding='utf8'))).rstrip(b'\0').decode('utf8'))
    return decrypted

def encrypt_des(text, key):
    des_key = preprocess_key(key, 8)
    des = DES.new(str.encode(des_key), DES.MODE_ECB)
    encrypted = str(base64.encodebytes(des.encrypt(str.encode(pad(text, 8)))),
                       encoding='utf8').replace('\n', '')
    return encrypted

def decrypt_des(encrypted, key):
    des_key = preprocess_key(key, 8)
    des = DES.new(str.encode(des_key), DES.MODE_ECB)
    decrypted = str(des.decrypt(base64.decodebytes(bytes(encrypted, encoding='utf8'))).rstrip(b'\0').decode('utf8'))
    return decrypted

def encrypt_des_bytes(data:bytes, key):
    data += bytes([0 for i in range(8-len(data)%8)])
    des_key = preprocess_key(key, 8)
    des = DES.new(str.encode(des_key), DES.MODE_ECB)
    encrypted = base64.encodebytes(des.encrypt(data))
    return encrypted

def decrypt_des_bytes(encrypted:bytes, key):
    des_key = preprocess_key(key, 8)
    des = DES.new(str.encode(des_key), DES.MODE_ECB)
    decrypted = des.decrypt(base64.decodebytes(encrypted)).rstrip(b'\0')
    return decrypted

def gen_random_base64(length):
    return base64.b64encode(Random.get_random_bytes(length))

if __name__ == "__main__":
    pass