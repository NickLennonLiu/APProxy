import base64, random, threading
import struct

from crypto import encrypt_des_bytes, decrypt_des_bytes


def encrypt(ks:bytes, rn_server, rn_client, data:bytes):
	data = struct.pack(">II", rn_server, rn_client) + data
	encrypted = encrypt_des_bytes(data, str(ks))
	return encrypted


def decrypt(ks, encrypted:bytes):
	decrypted = decrypt_des_bytes(encrypted, str(ks))
	(rn_server, rn_client), data = struct.unpack(">II", decrypted[:8]), decrypted[8:]
	return rn_server, rn_client, data
