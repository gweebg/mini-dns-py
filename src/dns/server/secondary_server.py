import errno
import os
import socket

from dns.dns_database import Database
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.base_segment_server import BaseSegmentServer
from dns.server.server_config import ServerConfiguration
from dns.utils import recv_msg
from models.dns_resource import DNSValueType, DNSResource
from models.zone_transfer_packet import ZoneTransferPacket, ZoneTransferMode
from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class SecondaryServer(BaseDatagramServer, BaseSegmentServer):

    def __init__(self, port: int, configuration_path: str, timeout: int, debug: bool = False, read_size: int = 1024):

        if not os.path.isfile(configuration_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), configuration_path)

        self.configuration: ServerConfiguration = FileParserFactory(configuration_path,
                                                                    Mode.CONFIG).get_parser().parse()

        super().__init__("127.0.0.1", port, read_size)
        super(BaseDatagramServer, self).__init__("127.0.0.1", port, read_size)

        self.database_version = 0
        self.database = self.try_zone_transfer(self.get_primary_server_address())

    def get_primary_server_address(self):
        address = self.configuration.primary_server.value

        if ":" in address:
            address = address.split(":")
            return address[0], address[1]

        print(address[0], address[1])
        return address, 53

    def try_zone_transfer(self, address: tuple[str, int]):

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 20023))

        # Send the initialization packet for the transfer zone process.
        transfer_zone_msg = "DOM;example.com;0"
        client.send(transfer_zone_msg.encode('ascii'))

        # Receiving the response from server containing the number of entries on the database.
        received_msg = client.recv(self.read_size).decode('ascii')
        packet = ZoneTransferPacket.from_string(received_msg)

        # Sending the acknowledgment packet if database version is greater else send connection termination packet.
        number_of_entries = packet.num_value
        database_version = packet.value

        if self.database_version != 0:
            if database_version <= self.database_version:
                end_connection_packet = ZoneTransferPacket(
                    mode=ZoneTransferMode.ACK,
                    domain=packet.domain,
                    num_value=0
                )
                client.send(end_connection_packet.as_byte_string())

                return

        ack_packet = ZoneTransferPacket(
            mode=ZoneTransferMode.ACK,
            domain=packet.domain,
            num_value=number_of_entries
        )
        client.send(ack_packet.as_byte_string())

        # Receiving the lines of the database.

        self.database_version = database_version
        database: dict[DNSValueType, list[DNSResource]] = {}

        for i in range(number_of_entries):
            data = recv_msg(client).decode('ascii')
            data_as_packet = DNSResource.from_string(data)

            if data_as_packet.type not in database:
                database[data_as_packet.type] = []

            database[data_as_packet.type].append(data_as_packet)

        return Database(database=database)

    def tcp_handle(self, conn: socket, address: tuple[str, int]):
        ...

    def udp_handle(self, data: bytes, address: tuple[str, int]):
        ...


# ss = SecondaryServer(20024, '/home/guilherme/Documents/repos/mini-dns-py/tests/config_ss.conf', 0, True)
