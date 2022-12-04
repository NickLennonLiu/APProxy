import ast
import base64
import json
import sys

import rsa
import socket
import random
import struct

from crypto import encrypt_aes, encrypt_des, decrypt_des, gen_random_base64, decrypt_aes, encrypt_des_bytes, \
	decrypt_des_bytes
from communication import send_dict, recv_dict

RSA_LENGTH = 1024
NA_LENGTH = 32

def logout(config):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(10)
	s.connect((config['SERVER_HOST'], config['AUTH_PORT']))
	send_dict(s, {"message": "Client logout"})

def login(config):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(10)

	try:
		max_tries = 5
		while max_tries:
			try:
				s.connect((config['SERVER_HOST'], config['AUTH_PORT']))
				break
			except ConnectionRefusedError:
				print(f"Connection failed, retrying... {max_tries}/5")
				max_tries -= 1

		#   STEP 1 Alice
		pk_a, sk_a = rsa.newkeys(RSA_LENGTH)
		e_pka = encrypt_aes(json.dumps({"e": pk_a.e, "n": pk_a.n}), config['PASSWORD'])
		send_dict(s, {"message": "Client login", "username": config['USERNAME'], "epka": e_pka})
		#   STEP 2 Alice
		eeks = recv_dict(s)["eeks"]
		eks = ast.literal_eval(decrypt_aes(eeks, config['PASSWORD']))
		ks = rsa.decrypt(eks, sk_a)
		#   STEP 3 Alice
		na = gen_random_base64(NA_LENGTH)
		ena = encrypt_des(str(na), str(ks))
		send_dict(s, {"ena": ena})
		#   STEP 4 Alice
		enanb = recv_dict(s)["enanb"]
		na_nb = json.loads(decrypt_des(enanb, str(ks)))
		nb = ast.literal_eval(na_nb["nb"])
		assert ast.literal_eval(na_nb["na"]) == na, "NA verification failed!"
		#   STEP 5 Alice
		enb = encrypt_des(str(nb), str(ks))
		send_dict(s, {"enb": enb})

		ern = s.recv(65536)
		rn = int(decrypt_des(ern.decode(), str(ks)))
	except Exception as err:
		print("[*]", err)
		s.close()
		print("[*] Login failed! ")
		sys.exit(1)
	return ks, rn

def encrypt(ks:bytes, rn_server, rn_client, data:bytes):
	data = struct.pack(">II", rn_server, rn_client) + data
	encrypted = encrypt_des_bytes(data, str(ks))
	return encrypted


def decrypt(ks, encrypted:bytes):
	decrypted = decrypt_des_bytes(encrypted, str(ks))
	(rn_server, rn_client), data = struct.unpack(">II", decrypted[:8]), decrypted[8:]
	return rn_server, rn_client, data


if __name__ == "__main__":
	encrypt(bytes(123), 60035, 123, "hello".encode())