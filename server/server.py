import json
import signal
import socket
import sys
import threading
import random
import rsa

from communication import recv_dict, send_dict
from config import _config
from crypto import decrypt_aes, gen_random_base64, encrypt_aes, decrypt_des, encrypt_des
from db_demo import USER_DB
from security import decrypt, encrypt

RSA_LENGTH = 1024
KS_LENGTH = 32
NB_LENGTH = 32


class Server:

    def __init__(self, config):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)

        # Create TCP socket for authentication
        self.authSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.authSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.authSocket.bind((config['HOST_NAME'], config['AUTH_PORT']))
        self.authSocket.listen(10)

        # Create TCP socket for proxy
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Re-use the socket
        self.serverSocket.bind((config['HOST_NAME'], config['PROXY_PORT']))
        self.serverSocket.listen(10)

        self.__clients = {}
        self.config = config

        # Start authentication daemon
        self.authDaemon = threading.Thread(name='AuthDaemon', target=self.authDaemon, args=(self.authSocket,))
        self.authDaemon.setDaemon(True)
        self.authDaemon.start()
        print("[*] Start listening for authentication request")

        print("[*] Start listening for proxy request")
        while True:
            (clientSocket, client_address) = self.serverSocket.accept()
            d = threading.Thread(target=self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()

    def authenticate(self, conn, addr):
        message_1 = recv_dict(conn)
        if message_1["message"] == "Client login":
            try:
                #   STEP 1 Bob
                username, e_pka = message_1["username"], message_1["epka"]
                d_pka_str = decrypt_aes(e_pka, USER_DB[username])
                pk_obj = json.loads(d_pka_str)
                pka = rsa.key.PublicKey(pk_obj["n"], pk_obj["e"])
                #   STEP 2 Bob
                ks = gen_random_base64(KS_LENGTH)
                eks = rsa.encrypt(ks, pka)
                eeks = encrypt_aes(str(eks), USER_DB[username])
                send_dict(conn, {"eeks": eeks})
                #   STEP 3 Bob
                ena = recv_dict(conn)["ena"]
                na = decrypt_des(ena, str(ks))
                #   STEP 4 Bob
                nb = gen_random_base64(NB_LENGTH)
                na_nb = json.dumps({"na": str(na), "nb": str(nb)})
                enanb = encrypt_des(na_nb, str(ks))
                send_dict(conn, {"enanb": enanb})
                #   STEP 5 Bob
                enb = recv_dict(conn)["enb"]
                enb_t = decrypt_des(enb, str(ks))
                assert enb_t == str(nb), "NB verification failed!"
            except Exception as err:
                print("[*]", err)
                conn.close()
                print(f"[*] Login from {addr[0]} failed")
                return

            # Generate session
            rn = random.randint(0, 65536)
            self.__clients[addr[0]] = {
                "rn": rn,
                "username": username,
                "ks": ks,
            }

            conn.send(encrypt_des(str(rn), str(ks)).encode())
            print(f"[*] Server done authenticating with address {addr[0]}, starting rn {rn}")
        elif message_1["message"] == "Client logout":
            self._deleteSession(addr[0])
            print(f"[*] Client from {addr[0]} logged out.")

    def _deleteSession(self, client_address):
        self.__clients.pop(client_address)

    def authDaemon(self, s):
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.authenticate, args=(conn, addr))
            t.start()

    def shutdown(self):
        print("[*] Server shutting down...")
        sys.exit(1)

    def _getClientName(self, client_address):
        return self.__clients[client_address]['username']

    def _getSession(self, client_address):
        return self.__clients[client_address]['ks'], self.__clients[client_address]['rn']

    def proxy_thread(self, conn: socket.socket, addr):
        encrypted = conn.recv(self.config['buff_size'])

        try:
            ks, rn = self._getSession(addr[0])
        except Exception as err:
            print("[*] Failed to get session for addr ", addr[0])
            return

        rn_server, rn_client, request = decrypt(ks, encrypted)
        print("[*] Receive request from client, rn: ", rn_server, rn, request)
        if rn_server != rn:
            print("[*] Client failed to meet with server's random number")
            print(f"[*] Removing session from {addr[0]}")
            self._deleteSession(addr[0])
            return

        # parse the first line
        first_line = request.split(b'\n')[0]
        # get url
        url = first_line.split()[1]
        http_pos = url.find(b"://")  # find pos of ://
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + 3):]  # get the rest of url
        port_pos = temp.find(b":")  # find the port pos (if any)

        # find end of web server
        webserver_pos = temp.find(b"/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        webserver = ""
        port = -1
        if port_pos == -1 or webserver_pos < port_pos:
            # default port 
            port = 80
            webserver = temp[:webserver_pos]
        else:  # specific port
            port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
            webserver = temp[:port_pos]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.config['CONNECTION_TIMEOUT'])
        s.connect((webserver, port))
        s.sendall(request)

        new_rn = random.randint(0, 65536)
        tot = 0
        while 1:
            # receive data from web server
            try:
                data = s.recv(self.config['buff_size'])
                tot += len(data)
                if len(data) > 0:
                    print("[*] Web returns: ", data)
                    self.__clients[addr[0]]['rn'] = new_rn
                    encrypted = encrypt(ks, new_rn, rn_client, data)
                    conn.sendall(encrypted)  # send to client
                else:
                    conn.close()
                    break
            except socket.timeout:
                print("[*] Timeout")
                conn.close()
                break

        dar = float(tot / 1024)
        dar = "%.3s KB" % (str(dar))
        print("[*] Request Done: %s => %s <=" % (str(addr[0]), str(dar)))


if __name__ == '__main__':
    server = Server(_config)
