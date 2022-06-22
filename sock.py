#!/usr/bin/env python3

import socket

ip = '127.0.0.1'
port = 8443
server = (ip, port)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(server)

line = ''
while line != 'bye':
    line = input('>>> ')
    packet = bytes.fromhex(line)
    sock.send(packet)
    data = sock.recv(4096)
    print(data.hex())

sock.close()
