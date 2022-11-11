import socket
import threading
import time

from example.example_protocol import MathProtocol, MathOperation

# IP = "127.0.0.1"
# PORT = 5555
# ADDR = (IP, PORT)
#
# sock = socket.socket(socket.AF_INET, # Internet
#                      socket.SOCK_DGRAM) # UDP
# sock.bind((IP, PORT))
#
# while True:
#     data, addr = sock.recvfrom(1024)
#     print("received message: %s" % data.decode('ascii'))
#     packet: MathProtocol = MathProtocol.from_string(data.decode('ascii'))
#
#     if packet.flag == MathOperation.M:
#         value = 1
#         for number in packet.numbers:
#             value = value * number
#
#     if packet.flag == MathOperation.S:
#         value = 0
#         for number in packet.numbers:
#             value += number
#
#     print(value)


class MathServer:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.addr = (ip, port)

        print("[STARTING] Server is starting...")
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(self.addr)

        except Exception as error:
            print("[UNEXPECTED ERROR] ", error)
            SystemExit(1)

    def handle_client(self, data, addr):
        msg = data.decode('utf-8')
        print(f"[{self.addr}] {msg}")

        packet: MathProtocol = MathProtocol.from_string(msg)

        value = -1

        if packet.flag == MathOperation.M:
            value += 2
            for number in packet.numbers:
                value = value * number

        if packet.flag == MathOperation.S:
            value += 1
            for number in packet.numbers:
                value += number

        time.sleep(5)
        self.udp_socket.sendto(str(value).encode('utf-8'), addr)

    def start(self):
        print(f"[LISTENING] Server is listening on {self.ip}:{self.port}")

        while True:
            data, addr = self.udp_socket.recvfrom(1024)
            print(f"[NEW CONNECTION] {self.addr} connected.")
            self.handle_client(data, addr)

            # thread = threading.Thread(target=self.handle_client, args=(data, addr))
            # thread.start()
            
            # print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


def main():
    server = MathServer("127.0.0.1", 20001)
    server.start()


if __name__ == "__main__":
    SystemExit(main())