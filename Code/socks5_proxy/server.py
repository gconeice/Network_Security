#!/usr/bin/env python

import sys
import socket
import select
import SocketServer
import struct
import string
import hashlib
import os
import json
import logging
import getopt
import ssl

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            #logging.info("handle tcp")
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    #logging.info("receive data from ss local %d " % len(data))
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    #logging.info("receive data from web")
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break 
                    sock.sendall(data) 
                    #logging.info("send data to ss local")
        finally:
            sock.close()
            remote.close()

    def handle(self):
        try:
            sock = self.connection
            ssl_sock = context.wrap_socket(sock, server_side=True)
            addrtype = ord(ssl_sock.recv(1)) #ord(self.decrypt(sock.recv(1)))      # receive addr type
            logging.info("addrtype is %d" % addrtype)
            if addrtype == 1:
                addr = socket.inet_ntoa(ssl_sock.recv(4)) #self.decrypt(self.rfile.read(4)))   # get dst addr
            elif addrtype == 3:
                addr = ssl_sock.recv(ord(ssl_sock.recv(1))) #self.decrypt(self.rfile.read(ord(self.decrypt(sock.recv(1)))))       # read 1 byte of len, then get 'len' bytes name
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', ssl_sock.recv(2)) #self.decrypt(self.rfile.read(2)))    # get dst port into small endian
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((addr, port[0]))         # connect to dst
            except socket.error, e:
                # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(ssl_sock, remote)
        except socket.error, e:
            logging.warn(e)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')

    with open('config.json', 'rb') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(certfile="mycertfile.pem", keyfile="mykeyfile.pem")

    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

