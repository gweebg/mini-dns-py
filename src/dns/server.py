import socket
import threading
import os
import errno

from dns.dns_packet import DNSPacket
from parser.parser_factory import FileParserFactory
from parser.abstract_parser import Mode


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

        # Now do stuff with received_dns_packet. #
        print(received_dns_packet)

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


class PrimaryServer(BaseDatagramServer):

    def __init__(self, ip_address: str, port: int, database_path: str,
                 configuration_path: str, root_list: str, read_size: int = 1024):

        super().__init__(ip_address, port, read_size)

        if not os.path.isfile(configuration_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), configuration_path)

        if not os.path.isfile(root_list):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), root_list)

        if not os.path.isfile(database_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), database_path)

        self.configuration = FileParserFactory(configuration_path, Mode.CONFIG).get_parser().parse()
        self.database = FileParserFactory(database_path, Mode.DB).get_parser().parse()
        self.root_list = None  # TODO: Root file list parser.

    def handle(self, data: bytes, address: tuple[str, int]):
        ...


def main():
    server = BaseDatagramServer("127.0.0.1", 20001)
    server.start()


if __name__ == "__main__":
    SystemExit(main())

