import socket
from example.example_protocol import MathProtocol


class MathClient:

    def __init__(self, ip, port, query: MathProtocol):
        self.query = query
        self.query_bytes = str(self.query).encode('utf-8')
        self.ip = ip
        self.port = port
        self.addr = (ip, port)

        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((self.ip, 0))
        except Exception as error:
            print("[UNEXPECTED ERROR] ", error)

    def send_query(self):

        self.udp_socket.sendto(self.query_bytes, self.addr)

        result = self.udp_socket.recv(1024).decode('utf-8')
        print(f"[RESULT] {result}")

        self.udp_socket.close()


def main():

    query: MathProtocol = MathProtocol.from_string("1;S;2 2 2")
    client: MathClient = MathClient("127.0.0.1", 20001, query)
    client.send_query()


if __name__ == "__main__":
    SystemExit(main())


