import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading



def execute(cmd: str) -> str:
    """
    The function executes a command and returns an output
    :param cmd: string with a CLI command
    :return: string with an output of the command
    """
    cmd = cmd.strip()
    if not cmd:
        return
    # run command with args and return an output
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()  # output as a string, not bytes


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def send(self):
        self.socket.connect((self.args.target, self.args.port))  # connect
        if self.buffer:  # if there is a buffer send it
            self.socket.send(self.buffer)
        try:
            while True:  # continue before Ctrl+C
                recv_len = 1
                response = ''
                while recv_len:  # get data from target server
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:  # if data is out of stock - stop
                        break
                if response:
                    print(response)  # print received result
                    buffer = input('> ')
                    buffer += '\n'  # add 'push enter'
                    self.socket.send(buffer.encode())  # send the result
        except KeyboardInterrupt:
            print('User terminated') # kill the connection with CTRL+C
            self.socket.close()
            sys.exit()

    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, addr = self.socket.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,)
            )
            client_thread.start()

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def handle(self, client_socket):
        """
        The method executes a command, downloads a file or launches CLI
        :param client_socket:
        :return:
        """
        if self.args.execute:  # if need to execute a command
            output = execute(self.args.execute)
            client_socket.send(output.encode())
        elif self.args.upload:  # if need to download a file
            file_buffer = b''
            while True:  # collect data
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:  # write a file
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())
        elif self.args.command:  # if need to execute a command
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'PBH: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(32)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()

if __name__ == '__main__':
    # argparse is a package for creation of CLI
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # description of --help
        epilog=textwrap.dedent("""Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c # command line
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt
        #load in file
        netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\"
        # execute the command
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135
        #send the text to the port of server 135
        netcat.py -t 192.168.1.108 -p 5555 # connect with the server
        ***
        To know IP addr on Linux: ifconfig | grep "inet" ; nslookup localhost 
        To know IP addr on Windows: ipconfig (see IPv4)
        """)
    )
    # -c prepares the CLI (needs 'l' regime)
    parser.add_argument('-c', '--command', action='store_true',
                        help='command shell')
    # -e execute a command (needs 'l' regime)
    parser.add_argument('-e', '--execute', help='execute specified command')
    # -l prepares listening
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    # -p - port
    parser.add_argument('-p', '--port', type=int, default=5555,
                        help='specified port')
    # -t is target (IP)
    parser.add_argument('-t', '--target', default='192.168.1.203',
                        help='specified IP')
    # -u filename to download (needs 'l' regime)
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    if args.listen:  # if listening regime
        buffer = ''
    else:
        buffer = sys.stdin.read()  # it saves an output in string

    nc = NetCat(args, buffer.encode())
    nc.run()





