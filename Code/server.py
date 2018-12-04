#-*- coding:utf-8 -*-
import sys, os, string, logging
import socket  
from socketserver import *  # tcp通信
import select  # IO多路复用
import struct  # 处理二进制数据
import json 

def load_config(filename):  # 加载配置文件
    with open('config.json', 'rb') as config_file:  
        config = json.load(config_file) 
    server_ip   = config['server_ip']
    server_port = config['server_port']
    passwd      = config['passwd']
    return server_ip, server_port, passwd

class Socks5Handler(StreamRequestHandler):
    def send_data(self, remote_client, addr_data):
        # TODO
        pass

    def send_all(self, socket, data):
        sent_len = 0
        while True:
            bytes_sent = socket.send(data[sent_len:])
            if bytes_sent < 0:  # 发送失败
                return bytes_sent
            sent_len += bytes_sent
            if sent_len == len(data):
                return sent_len

    def encrypt(self, data):
        return data 

    def decrypt(self, data):
        return data

    def handle_forward_tcp(self, remote_server, remote_client):
        try:
            fdset = [remote_server, remote_client]  # 待处理的输入socket
            while True:
                rlist, wlist, execption = select.select(fdset, [], [])
                if remote_server in rlist:
                    data = remote_server.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(remote_client, self.decrypt(data))  # 解密传给目标服务器，例google
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote_client in rlist:
                    data = remote_client.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(remote_server, self.encrypt(data))  # 加密传输给主机的本地服务器
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            remote_server.close()
            remote_client.close()
            


    def handle(self):  # 作为remote server与local server 连接
        #logging.info('Got connection from ' + self.client_address)
        try: 
            remote_server = self.connection
            addrtype = ord(self.decrypt(remote_server.recv(1)))  # addrtype
            if addrtype == 1:  # ipv4
                target_addr = remote_server.inet_ntoa(self.decrypt(self.rfile.read(4)))  # 浏览器所想连接的网站ip
            elif addrtype == 3:  # Domain
                domain_len = self.decrypt(self.rfile.read(1))
                target_addr = self.decrypt(self.rfile.read(ord(domain_len)))
            else:
                logging.error("address type isn't supported ")
                return 
            port = self.decrypt(self.rfile.read(2))
            target_port = struct.unpack('>H', port)  # DST.PORT

            try:
                logging.info("build connection with remote %s:%d" % (target_addr, target_port))
                remote_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 建立新的socket对象，连接ss-server
                remote_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote_client.connect((target_addr, target_port[0]))
            except socket.error as e:
                logging.error(e)
                return 
            self.handle_forward_tcp(remote_server, remote_client)
        except socket.error as e:
            logging.error(e)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    server_ip, server_port, passwd = load_config("config.json")
    logging.basicConfig(level=logging.DEBUG, filemode='a+')

    # TODO 流量加密传输

    try:  # 建立socket本地tcp服务器
        remote_server = ThreadingTCPServer(('', server_port), Socks5Handler)
        logging.info("start ssremote server port %d" % server_port)
        remote_server.serve_forever()
    except socket.error as e:
        logging.error(e)
    