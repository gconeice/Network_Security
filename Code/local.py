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
    local_port  = config['local_port']
    passwd      = config['passwd']
    return server_ip, server_port, local_port, passwd

class Socks5Handler(StreamRequestHandler):
    def send_data(self, local_client, addr_data):
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

    def handle_forward_tcp(self, local_server, local_client):
        try:
            fdset = [local_server, local_client]  # 待处理的输入socket
            while True:
                rlist, wlist, execption = select.select(fdset, [], [])
                if local_server in rlist:
                    data = local_server.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(local_server, self.encrypt(data))  # 加密转发给境外vps
                    if result < len(data):
                        raise Exception('failed to send all data')

                if local_client in rlist:
                    data = local_client.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_all(local_client, self.decrypt(data))  # 解密传输给本地浏览器
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            local_server.close()
            local_client.close()
            


    def handle(self):  # 作为local server与浏览器的socks5的连接
        #logging.info('Got connection from ' + self.client_address)
        try: 
            local_server = self.connection
            local_server.recv(256)  # 采用socks无认证模式
            local_server.send(b"\x05\x00")  # TODO  可以加用户认证机制
            data = self.rfile.read(4)  # VER CMD RSV ATYP
            mode = ord(data[1])
            if mode != 1:  # CMD == 1 TCP连接
                return 
            addrtype = ord(data[3])
            # target_addr = data[3]
            if addrtype == 1:  # ipv4
                addr_info = self.rfile.read(4)
                remote_addr = local_server.inet_ntoa(addr_info)  # 浏览器所想连接的网站ip
                # target_addr += addr_ip
            elif addrtype == 3:  # Domain
                domain_len = self.rfile.read(1)
                remote_addr = self.rfile.read(ord(domain_len))
                addr_info = domain_len + remote_addr
                # target_addr += domain_len + remote_addr
            else:
                return 
            addr_port = self.rfile.read(2)
            remote_port = struct.unpack('>H', addr_port)  # DST.PORT
            target_addr = data[3] + addr_info + addr_port

            try:
                reply = b"\x05\x00\x00\x01"  # sslocal 回应请求
                reply += local_server.inet_aton('0.0.0.0') + struct.pack(">H", 8888)
                self.wfile.write(reply)

                local_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 建立新的socket对象，连接ss-server
                local_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                local_client.connect((server_ip, server_port))
                # self.send_data(local_client, target_addr)  # TODO 这里应该加密传输
                local_client.send(target_addr)
                logging.info("build connection with remote %s:%d" % (remote_addr, remote_port))
            except socket.error as e:
                logging.error(e)
                return 
            self.handle_forward_tcp(local_server, local_client)
        except socket.error as e:
            logging.error(e)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    server_ip, server_port, local_port, passwd = load_config("config.json")
    logging.basicConfig(level=logging.DEBUG, filemode='a+')

    # TODO 流量加密传输

    try:  # 建立socket本地tcp服务器
        local_server = ThreadingTCPServer(('', local_port), Socks5Handler)
        logging.info("start sslocal server port %d" % local_port)
        local_server.serve_forever()
    except socket.error as e:
        logging.error(e)
    