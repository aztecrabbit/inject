import re
import ssl
import socket
import select
import random
import socketserver
from ..log.log import log
from ..utils.utils import utils
from ..redsocks.redsocks import redsocks

class inject(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

class inject_handler(socketserver.BaseRequestHandler):

    def setup(self):
        self.server.utils = utils(__file__)

        self.server.buffer_size = 65535
        self.server.default_log_type = 1
        self.server.socket_server_timeout = 3

        self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_server.settimeout(self.server.socket_server_timeout)

        if not hasattr(self.server, 'stop'):
            self.server.stop = False
        
        if not hasattr(self.server, 'liblog'):
            self.server.liblog = log()

        if not hasattr(self.server, 'libredsocks'):
            self.server.libredsocks = redsocks()

        if not hasattr(self.server, 'rules'):
            self.server.rules = [
                {
                    'target-list': [''],
                    'tunnel-type': '0',
                    'remote-proxies': [''],
                    'direct-payloads': [''],
                    'server-name-indications': [''],
                    'remote-proxies-payloads': [''],
                }
            ]

    def log(self, value, color='[G1]', type=''):
        if self.server.stop:
            return

        type = type if type != '' else self.server.default_log_type

        self.server.liblog.log(value, color=color, type=type)

    def extract_client_request_payload(self):
        try:
            self.client_request_payload = self.request.recv(self.server.buffer_size).decode('charmap')
            self.client_request_payload_find = re.findall(r'([^/]+(\.[^/:]+)+)(:([0-9]+))?', self.client_request_payload.split(' ')[1])[0]
            self.client_request_host = self.client_request_payload_find[0]
            self.client_request_port = self.client_request_payload_find[3] if len(self.client_request_payload_find) >= 4 and \
                len(self.client_request_payload_find[3]) else '80'
        except IndexError:
            return False
        else:
            return True

    def check_client_request_in_rule(self, rule):
        for target in rule['target-list']:
            target_host_port = target.split(':')
            target_host = target_host_port[0] if target_host_port[0] else '*'
            target_port = target_host_port[1] if len(target_host_port) >= 2 and target_host_port[1] else '*'

            if (target_host == '*' or target_host in self.client_request_host) and \
               (target_port == '*' or target_port == self.client_request_port):
                return True

        return False

    def check_client_request(self):
        if not self.extract_client_request_payload():
            return False

        for rule in self.server.rules:
            if not self.check_client_request_in_rule(rule):
                continue

            self.tunnel_type = rule.get('tunnel-type')
            self.remote_proxies = rule.get('remote-proxies')
            self.direct_payloads = rule.get('direct-payloads')
            self.server_name_indications = rule.get('server-name-indications')
            self.remote_proxies_payloads = rule.get('remote-proxies-payloads')

            return True

        return False

    def payload_decode(self, payload):
        payload = payload.replace('[real_raw]', '[raw][crlf][crlf]')
        payload = payload.replace('[raw]', '[method] [host_port] [protocol]')
        payload = payload.replace('[method]', 'CONNECT')
        payload = payload.replace('[host_port]', '[host]:[port]')
        payload = payload.replace('[host]', str(self.client_request_host))
        payload = payload.replace('[port]', str(self.client_request_port))
        payload = payload.replace('[protocol]', 'HTTP/1.0')
        payload = payload.replace('[user-agent]', 'User-Agent: Chrome/1.1.3')
        payload = payload.replace('[keep-alive]', 'Connection: Keep-Alive')
        payload = payload.replace('[close]', 'Connection: Close')
        payload = payload.replace('[crlf]', '[cr][lf]')
        payload = payload.replace('[lfcr]', '[lf][cr]')
        payload = payload.replace('[cr]', '\r')
        payload = payload.replace('[lf]', '\n')

        return payload.encode()

    def send_payload(self, payload):
        payload = payload if payload else '[method] [host_port] [protocol][crlf][crlf]'
        self.log('Payload: \n\n{}\n'.format(('|   ' + self.payload_decode(payload).decode())
            .replace('\r', '')
            .replace('[split]', '$lf\n')
            .replace('\n', '\n|   ')
            .replace('$lf', '\n')
        ), type=2)
        payload_split = payload.split('[split]')
        for i in range(len(payload_split)):
            if i > 0: time.sleep(0.200)
            self.socket_server.sendall(self.payload_decode(payload_split[i]))

    def certificate(self):
        self.log(f'Certificate:\n\n{ssl.DER_cert_to_PEM_cert(self.socket_server.getpeercert(True))}', type=2)

    def convert_response(self, response):
        response = response.replace('\r', '').rstrip() + '\n\n'
        
        if response.startswith('HTTP'):
            return '\n\n|   {}\n'.format(response.replace('\n', '\n|   '))

        return '[W2]\n\n{}\n'.format(re.sub(r'\s+', ' ', response.replace('\n', '[CC][Y1]\\n[W2]')))

    # Direct -> SSH
    def tunnel_type_0(self):
        if not isinstance(self.direct_payloads, list) and self.direct_payloads:
            self.direct_payloads = [self.direct_payloads]

        if not len(self.direct_payloads) or not self.server.utils.xfilter(self.direct_payloads):
            self.direct_payloads = ['[raw][crlf][crlf]']

        try:
            self.payload = random.choice(self.direct_payloads)

            self.server.libredsocks.rule_direct_update(self.client_request_host)
            self.log(f'Connecting to {self.client_request_host} port {self.client_request_port}')
            self.socket_server.connect((str(self.client_request_host), int(self.client_request_port)))
            self.send_payload(self.payload)
            self.handler()
        except socket.timeout:
            self.log('Connection timeout', color='[R1]', type=2)
        except socket.error:
            self.log('Connection closed', color='[R1]', type=2)
        finally:
            self.close_request()

    # Direct -> SSH (SSL/TLS)
    def tunnel_type_1(self):
        if not isinstance(self.server_name_indications, list) and self.server_name_indications:
            self.server_name_indications = [self.server_name_indications]

        if not len(self.server_name_indications) or not self.server.utils.xfilter(self.server_name_indications):
            self.server_name_indications = [self.client_request_host]

        try:
            self.server_name_indication = random.choice(self.server_name_indications)

            self.server.libredsocks.rule_direct_update(self.client_request_host)
            self.log(f'Connecting to {self.client_request_host} port {self.client_request_port}')
            self.socket_server.connect((str(self.client_request_host), int(self.client_request_port)))
            self.log(f'Server name indication: {self.server_name_indication}', type=2)
            self.socket_server = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2).wrap_socket(self.socket_server, server_hostname=self.server_name_indication, do_handshake_on_connect=True)
            self.certificate()
            self.handler()
        except socket.timeout:
            self.log('Connection timeout', color='[R1]', type=2)
        except socket.error:
            self.log('Connection closed', color='[R1]', type=2)
        finally:
            self.close_request()

    # HTTP Proxy -> SSH
    def tunnel_type_2(self):
        if not isinstance(self.remote_proxies, list) and self.remote_proxies:
            self.remote_proxies = [self.remote_proxy]

        if not len(self.remote_proxies) or not self.server.utils.xfilter(self.remote_proxies):
            self.log('Remote proxies not set, tunnel type changed to direct -> server', color='[R1]')
            self.tunnel_type_0()
            return

        if not isinstance(self.remote_proxies_payloads, list) and self.remote_proxies_payloads:
            self.remote_proxies_payloads = [self.remote_proxies_payloads]

        if not len(self.remote_proxies_payloads) or not self.server.utils.xfilter(self.remote_proxies_payloads):
            self.remote_proxies_payloads = ['[raw][crlf][crlf]']

        try:
            self.remote_proxy = random.choice(self.remote_proxies).split(':')
            self.remote_proxy_host = str(self.remote_proxy[0])
            self.remote_proxy_port = int(self.remote_proxy[1]) if len(self.remote_proxy) >= 2 and self.remote_proxy[1] else int('80')

            self.payload = random.choice(self.remote_proxies_payloads)

            self.server.libredsocks.rule_direct_update(self.remote_proxy_host)
            self.log(f'Connecting to remote proxy {self.remote_proxy_host} port {self.remote_proxy_port}', type=2)
            self.socket_server.connect((self.remote_proxy_host, self.remote_proxy_port))
            self.log(f'Connecting to {self.client_request_host} port {self.client_request_port}')
            self.send_payload(self.payload)
            self.proxy_handler()
        except socket.timeout:
            self.log('Connection timeout', color='[R1]', type=2)
        except socket.error:
            self.log('Connection closed', color='[R1]', type=2)
        finally:
            self.close_request()

    def tunnel_type_3(self):
        if not isinstance(self.remote_proxies, list) and self.remote_proxies:
            self.remote_proxies = [self.remote_proxy]

        if not len(self.remote_proxies) or not self.server.utils.xfilter(self.remote_proxies):
            self.remote_proxies = [f'{self.client_request_host}:{self.client_request_port}']

        try:
            self.remote_proxy = random.choice(self.remote_proxies).split(':')
            self.remote_proxy_host = str(self.remote_proxy[0])
            self.remote_proxy_port = int(self.remote_proxy[1]) if len(self.remote_proxy) >= 2 and self.remote_proxy[1] else int('80')

            self.server.libredsocks.rule_direct_update(self.remote_proxy_host)
            #self.log(f'Connecting to remote proxy {self.remote_proxy_host} port {self.remote_proxy_port}', type=2)
            self.socket_server.connect((self.remote_proxy_host, self.remote_proxy_port))
            # self.log(f'Connecting to {self.client_request_host} port {self.client_request_port}')
            self.log(f'Connecting to {self.remote_proxy_host} port {self.remote_proxy_port} -> {self.client_request_host} port {self.client_request_port}', type=2)
            self.handler(type=3)
        except socket.timeout:
            self.log('Connection timeout', color='[R1]', type=2)
        except socket.error:
            self.log('Connection closed', color='[R1]', type=2)
        finally:
            self.close_request()

    def proxy_handler(self):
        i = 0
        while True:
            if i == 1: self.log('Replacing response', type=2)
            response = self.socket_server.recv(self.server.buffer_size).decode('charmap')
            if not response: break
            if re.match(r'^HTTP/\d(\.\d)? 200 (Connection established|OK)(\r?\nConnection: keep-alive)?\r?\n\r?\n$', response, re.IGNORECASE):
                self.log('Response: {}'.format(self.convert_response(response)), type=2)
                self.handler()
                break
            else:
                self.socket_server.sendall(b'HTTP/1.1 200 Connection established\r\nConnection: keep-alive\r\n\r\n')
                self.log('Response: {}'.format(self.convert_response(response)), type=2)
                i += 1

    def handler(self, type=2):
        sockets = [self.request, self.socket_server]
        timeout = 0
        self.request.sendall(b'HTTP/1.0 200 Connection established\r\n\r\n')
        self.log('Connection established', type=type)
        while True:
            timeout += 1
            socket_io, _, errors = select.select(sockets, [], sockets, 3)
            if errors: break
            if socket_io:
                for sock in socket_io:
                    try:
                        data = sock.recv(self.server.buffer_size)
                        if not data: break
                        # SENT -> RECEIVE
                        elif sock is self.request:
                            self.socket_server.sendall(data)
                        elif sock is self.socket_server:
                            self.request.sendall(data)
                        timeout = 0
                    except: break
            if timeout == 30: break

    def close_request(self):
        self.socket_server.close()
        self.server.close_request(self.request)

    def handle(self):
        if not self.check_client_request() or not self.tunnel_type or self.tunnel_type == '#':
            self.request.sendall('HTTP/1.1 403 Forbidden from Brainfuck Tunnel Libraries (inject.py)\r\n\r\n'.encode())
            self.server.close_request(self.request)

        elif self.tunnel_type == '0': self.tunnel_type_0()
        elif self.tunnel_type == '1': self.tunnel_type_1()
        elif self.tunnel_type == '2': self.tunnel_type_2()
        elif self.tunnel_type == '3': self.tunnel_type_3()
