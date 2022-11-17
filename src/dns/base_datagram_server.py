import socket
import threading

from dns.dns_packet import DNSPacket


class BaseDatagramServer:

    def __init__(self, ip_address: str, port: int, read_size: int = 1024):

        self.socket_address: tuple[str, int] = (ip_address, port)
        self.read_size = read_size

        print("[STARTING] Server is starting...")

        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(self.socket_address)
        except Exception as error:
            print("[UNEXPECTED ERROR] ", error)
            SystemExit(1)

    def handle(self, data: bytes, address: tuple[str, int]):

        data: str = data.strip().decode("utf-8")
        received_dns_packet: DNSPacket = DNSPacket.from_string(data)

        encoded_reply: bytes = str(received_dns_packet.header).encode("utf-8")
        self.udp_socket.sendto(encoded_reply, address)

    def start(self):
        print(f"[LISTENING] Server is listening on {self.socket_address[0]}:{self.socket_address[1]}")

        while True:
            encoded_data, address = self.udp_socket.recvfrom(self.read_size)
            print(f"[NEW CONNECTION] {self.socket_address} connected.")

            thread = threading.Thread(target=self.handle, args=(encoded_data, address))
            thread.start()

            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
