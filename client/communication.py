import json

def send_dict(sock, dt):
    payload = json.dumps(dt).encode()
    sock.send(payload)

def recv_dict(sock):
    s = sock.recv(65536)
    return json.loads(s)