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

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):   # Multiple inheritance
    allow_reuse_address = True

class Socks5Server(SocketServer.StreamRequestHandler):
    username = "test"
    password = "123456"

    ''' RequesHandlerClass Definition '''
    def handle_tcp(self, sock, remote):
        try:
            logging.info("handle tcp  .... ")
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])      # use select I/O multiplexing model
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096)
                    if len(data) <= 0:                      # received all data
                        break
                    remote.sendall(data)

                if remote in r:                             # remote socket(proxy) ready for reading
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()
    
    def verify_credentials(self):  # check username / passwd right or not
        version = ord(self.rfile.read(1))
        assert version == 1
        username_len = ord(self.rfile.read(1))
        username = self.rfile.read(username_len).decode('utf-8')
        passwd_len = ord(self.rfile.read(1))
        passwd = self.rfile.read(passwd_len).decode('utf-8')
        if username == self.username and passwd == self.password:
            response = struct.pack("!2B", version, 0)
            self.wfile.write(response)
            logging.info("username / passwd  auth  successfully")
            return True
        response = struct.pack("!2B", version, 0xFF)
        self.wfile.write(response)
        logging.info("username / passwd  auth  Failed")
        return False



    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            
            header = self.rfile.read(2)   # Sock5 AUTHENTICATION USERNAME/PASSWD
            version, nmethod = struct.unpack("!2B", header)
            assert version == 5
            assert nmethod > 0
            methods = []
            logging.info("nmethod is %d" % nmethod)
            for i in range(nmethod):
                method = ord(self.rfile.read(1))
                methods.append(method)
                logging.info("method : %d " % method)
            if 2 not in methods:
                logging.error(" don't suport username/passwd auth ")
                return  
            self.wfile.write(struct.pack("!2B", 5, 2))  #use username/passwd auth
            if not self.verify_credentials():
                return
            
            # sock.recv(262)                # Sock5 NO AUTHENTICATION REQUIRED
            # sock.send("\x05\x00")         

            # After Authentication negotiation
            data = self.rfile.read(4)     # Forward request format: VER CMD RSV ATYP (4 bytes)
            mode = ord(data[1])           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])       # indicate destination address type
            logging.info("VER %d , CMD %d , RSV %d, ATYP %d" % (ord(data[0]), ord(data[1]), ord(data[2]), ord(data[3])))  #debug info
            addr_to_send = data[3]
            if addrtype == 1:             # IPv4
                addr_ip = self.rfile.read(4)            # 4 bytes IPv4 address (big endian)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)
                addr_len = self.rfile.read(1)           # Domain name's Length
                addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)
                addr_to_send += addr_len + addr
            else:
                logging.warn('addr_type not support')
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            try:
                reply = "\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet

                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                ssl_remote = ssl.wrap_socket(remote, ca_certs="mycertfile.pem", cert_reqs=ssl.CERT_REQUIRED)
                ssl_remote.sendall(addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.info("socket error")
                logging.warn(e)
                return
            self.handle_tcp(sock, ssl_remote)
        except socket.error, e:
            logging.warn(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')  

    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   # build tcp server
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

