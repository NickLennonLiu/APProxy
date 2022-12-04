客户端和服务端协定密码，注册，登录 （SSH）

客户端登录后，服务端接受来自这个IP的请求转发





```
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind('', listening_port)
sock.listen(max_connection)

conn, addr = sock.accept()
data = conn.recv(buffer_size)
```

