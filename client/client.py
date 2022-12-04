import argparse
import random
import socket
import sys
from _thread import *
from security import login, encrypt, decrypt, logout
import json
from config import _config

class Client:

    def __init__(self, config):
        # Load configuration
        listening_port = config['port']
        max_conn = config['max_conn']
        buff_size = config['buff_size']
        self.config = config

        self.lock = allocate_lock()
        # Login for authentication from server
        try:
            self.ks, self.rn_server = login(config)
        except Exception as err:
            print("[*] Failed to authenticate with proxy server")
            print(err)
            sys.exit(2)

        # Listen for connections from browser
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', listening_port))
            sock.listen(max_conn)
            print("[*] Client started successfully at port [ %d ]" % listening_port)
        except Exception:
            print("[*] Unable to Initialize Socket")
            print(Exception)
            sys.exit(2)

        while True:
            try:
                conn, addr = sock.accept()  # Accept connection from browser
                data = conn.recv(buff_size)  # Receive browser data

                start_new_thread(self._Proxy, (config, conn, data, addr))  # Starting a thread
                #self._Proxy(config, conn, data, addr)

            except KeyboardInterrupt:
                sock.close()
                logout(config)
                print("\n[*] Graceful Shutdown")
                sys.exit(1)



    def _Proxy(self, config, conn, data, addr):
        server_ip = config['SERVER_HOST']
        server_port = config['PROXY_PORT']
        buffer_size = config['buff_size']

        if len(data) == 0:
            return
        self.lock.acquire()
        print("[*] Browser request: ", data)
        # Encrypt the request
        rn = random.randint(0, 65536)
        data = encrypt(self.ks, self.rn_server, rn, data)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))
            sock.sendall(data)

            tot = 0
            while 1:
                reply = sock.recv(buffer_size)

                if len(reply)>0:
                    # Decrypt the reply
                    rn_server, rn_client, reply = decrypt(self.ks, reply)
                    if rn_client != rn:
                        print("[*] Server failed to meet with client's random number")
                        print("[*] You need to re-login again")
                        logout(config)
                        sys.exit(1)
                    print("[*] Server return data with correct rn: ", rn)

                    self.rn_server = rn_server
                    conn.sendall(reply)

                    tot += len(reply)
                else:
                    break

            dar = float(tot / 1024)
            dar = "%.3s KB" % (str(dar))
            print("[*] Request Done: %s => %s <=" % (str(addr[0]), str(dar)))

            sock.close()
            conn.close()
        except socket.error:
            sock.close()
            conn.close()
            sys.exit(1)
        self.lock.release()


if __name__== "__main__":
    client = Client(_config)