import json

def send_dict(sock, dt):
    sock.send(json.dumps(dt).encode())

def recv_dict(sock):
    s = sock.recv(65536)
    return json.loads(s)