import socket
import threading
import logging

from dns.dns_packet import DNSPacket


class BaseDatagramServer:

    def __init__(self, ip_address: str, port: int, read_size: int = 1024):

        self.socket_address: tuple[str, int] = (ip_address, port)
        self.read_size = read_size

        self.logger = logging.getLogger('all')  # It's mandatory for this to exist according to the requirements.

        self.logger.info(f'EV | {ip_address} | UDP server is starting...')
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(self.socket_address)

        except Exception as error:
            self.logger.error(f'FL | {ip_address} |An error occurred while starting UDP server:\n{error}')
            raise

    def udp_handle(self, data: bytes, address: tuple[str, int]):

        data: str = data.strip().decode("ascii")
        received_dns_packet: DNSPacket = DNSPacket.from_string(data)

        encoded_reply: bytes = str(received_dns_packet.header).encode("ascii")
        self.udp_socket.sendto(encoded_reply, address)

    def udp_start(self):

        self.logger.info(f'EV | {self.socket_address[0]} | UDP Server is listening on {self.socket_address[0]}:{self.socket_address[1]}')

        while True:
            encoded_data, address = self.udp_socket.recvfrom(self.read_size)
            self.logger.debug(f'EV | {self.socket_address[0]} | New UDP connection, {address} connected.')

            thread = threading.Thread(target=self.udp_handle, args=(encoded_data, address))
            thread.start()

            self.logger.debug(f'EV | {self.socket_address[0]} | Active UDP connections: {threading.active_count() - 1}')
