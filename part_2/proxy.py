import sys
import socket
import threading

# chr() Преобразует число в символ Юникода, обратная операция ord().
# HEX_FILTER - способ транслирования. Если символ непечатный , выведется точка.
# длина repr(chr(i)) для печатного символа всегда 3
"""
Строчный метод translate:
string = 'таблица преобразования символов'
hex = {'а': 'A', 'п': 'P', 'о': 'O', 'в': 'V', 'ц': 'Z' }
tbl = str.maketrans(hex)
print(tbl)
>>> {1072: 'A', 1087: 'P', 1086: 'O', 1074: 'V', 1094: 'Z'}
print(string.translate(tbl))
>>> 'тAблиZA PреOбрAзOVAния симVOлOV'
"""

HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)]
)


def hexdump(src: bytes, length: int = 16, show: bool = True) -> list:
    """
    Function hexdump gets bytes and shows it in hexadecimal format.
    It shows data as hexadecimal and as ASCII
    Ex.:
    hexdump('python rocks\n and proxies roll\n')
    >>>'0000 70 79 74 68 6F 6E 20 72 6F 63 6B 73 0A 20 61 6E  python rocks. an'
    >>>'0010 64 20 70 72 6F 78 69 65 73 20 72 6F 6C 6C 0A     d proxies roll.'
    """
    if isinstance(src, bytes):
        src = src.decode()
    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])  # word is a part of byte sequence
        # replace raw characters with processed ones
        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length * 3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results


def receive_from(connection, timeout: int = 10) -> bytes:
    """
    Function receive_from gets either local or remote data
    connection - socket object
    timeout: int, tima of waiting an answer
    """
    buffer = b""
    connection.settimeout(timeout)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception:
        pass
    return buffer


def request_handler(buffer: bytes) -> bytes:
    """Function request_handler"""
    # modificate a package
    return buffer


def response_handler(buffer: bytes) -> bytes:
    """Function response_handler"""
    # modificate a package
    return buffer


def proxy_handler(client_socket, remote_host: str,
                  remote_port: int, receive_first: bool,
                  timeout: int = 10) -> None:
    """Function proxy_handler"""
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # Make sure that don't need to init a connection with remote part
    # and ask a data before to go to the main cycle
    if receive_first:
        remote_buffer = receive_from(remote_socket, timeout=timeout)
        hexdump(remote_buffer)

    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print(f"[<==] Sending {len(remote_buffer)} bytes to localhost.")
        client_socket.send(remote_buffer)

    # to keep the connection
    time_before_disconnect = 10
    time_left = 0

    while True:
        local_buffer = receive_from(client_socket, timeout=timeout)
        if len(local_buffer):
            line = f"[==>] Received {len(local_buffer)} bytes from localhost."
            print(line)
            hexdump(local_buffer)
            # send the response to the handler
            local_buffer = request_handler(local_buffer)
            # send the response to the local client
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")
            time_left = time_before_disconnect

        remote_buffer = receive_from(remote_socket, timeout=timeout)
        if len(remote_buffer):
            print(f"[<==] Received {len(remote_buffer)} bytes from remote.")
            hexdump(remote_buffer)
            remote_buffer = request_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")
            time_left = time_before_disconnect

        if not len(local_buffer) or not len(remote_buffer):
            time_left -= 1
            # if there is not data to send
            if time_left > 0:
                print(f"Time left: {time_left}. Type new command, please.")
                continue
            else:
                client_socket.close()
                remote_socket.close()
                print("[*] No more data. Closing connections.")
                break


def server_loop(local_host: str, local_port: int,
                remote_host: str, remote_port: int,
                receive_first: bool, timeout: int = 10) -> None:
    """Function server_loop"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"Problem on bind: {e}")
        print(f"[!!] Failed to listen on: {local_host}:{local_port}")
        print("[!!] Check for other listening " +
              "sockets or correct permissions.")
        sys.exit(0)
    print(f"[*] Listening on: {local_host}:{local_port}")
    # count of connections that the scrypt set in the queue
    # before to deny of new connections
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        line = f"> Received incoming connection from {addr[0]}:{addr[1]}"
        print(line)
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host,
                  remote_port, receive_first, timeout)
        )
        proxy_thread.start()


def main():
    """Function main"""
    if len(sys.argv[1:]) != 6:
        print("Usage: ./proxy.py [local_host] [local_port]", end='')
        print("[remote_host] [remote_port] [receive_first] [timeout]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True 15")
        sys.exit(0)
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5]
    timeout = int(sys.argv[6])

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port,
                remote_host, remote_port, receive_first, timeout)


if __name__ == '__main__':
    main()
