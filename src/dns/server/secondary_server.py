import errno
import os
import socket

from dns.dns_database import Database
from dns.dns_packet import DNSPacket, DNSPacketHeaderFlag, DNSPacketQueryData, DNSPacketHeader
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.server_config import ServerConfiguration
from dns.utils import recv_msg
from exceptions.exceptions import InvalidDNSPacket
from models.dns_resource import DNSValueType, DNSResource
from models.zone_transfer_packet import ZoneTransferPacket, ZoneTransferMode
from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class SecondaryServer(BaseDatagramServer):

    def __init__(self, port: int, configuration_path: str, timeout: int, debug: bool = False, read_size: int = 1024):

        if not os.path.isfile(configuration_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), configuration_path)

        self.configuration: ServerConfiguration = FileParserFactory(configuration_path,
                                                                    Mode.CONFIG).get_parser().parse()

        self.timeout = timeout

        super().__init__("127.0.0.1", port, read_size)

        self.database_version = 0
        self.database = self.zone_transfer()

    def get_primary_server_address(self):
        address = self.configuration.primary_server.value

        if ":" in address:
            address = address.split(":")
            return address[0], int(address[1])

        return address, 53

    def zone_transfer(self):

        address = self.get_primary_server_address()

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(address)

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

    def is_authority(self, name: str):
        """
        Checks if the server (self) is an authority to the domain name provided in name.

        :param name: Domain name to check.
        :return: True if it is an authority, otherwise False.
        """

        name = name[:-1]

        p_server = self.configuration.primary_server

        if p_server and name == p_server.parameter:
            return True

        for snd_server in self.configuration.secondary_servers:
            if name == snd_server.parameter:
                return True

        return False

    def match(self, packet: DNSPacket):
        """
        This function only runs if this server is an authority to the domain specified in the query.
        It matches the query with the database, giving as output every matched value (response values,
        authorities values and extra values).

        Logic:
            if response values found (full matches):
                look for authorities by searching given domain name
                get extras by getting ips
            else:
                look for authorities by searching for given domain's superdomain (example.com -> .com)
                get extras by getting ips

            if no authorities nor extras nor response values:
                domain does not exist

        :param packet: DNSPacket object containing the received query.
        :return:
        """

        name: str = packet.query_info.name
        type_of_value: DNSValueType = packet.query_info.type_of_value

        response_values: [DNSResource] = self.database.response_values(name, type_of_value)

        authorities_values: [DNSResource] = self.database.authorities_values(name, response_values)

        extra_values: [DNSResource] = self.database.extra_values(response_values + authorities_values)

        return Database.values_as_string(response_values), Database.values_as_string(
            authorities_values), Database.values_as_string(extra_values)

    def is_whitelisted(self, name: str):
        """
        Check if a domain is white listed on the (self) server.

        :param name: Domain name to check.
        :return: True if its whitelisted, otherwise False.
        """
        return name[:-1] in self.configuration.allowed_domains

    def udp_handle(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Handle the data received from the socket.
        In this case, it processes the query.

        :param data: Data received from the socket.
        :param address: (ip_address, port) tuple that represents the socket address.
        :return: An integer representing the query error code.
        """

        data: str = data.strip().decode("utf-8")
        # self.log('all', f'QR | {address[0]}:{address[1]} | {data}', 'info')

        # Check if the received data is a DNSPacket. If it isn't than reply to client with response code 3.
        try:
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:

            # self.log('all', f'ER | {address[0]}:{address[1]} |\n{error}', 'error')
            bad_format_packet: DNSPacket = DNSPacket.generate_bad_format_response()

            # self.log('all', f'RP | {address[0]}:{address[1]} |\n{bad_format_packet}', 'info')
            self.udp_socket.sendto(bad_format_packet.as_byte_string(), address)
            return 3

        # Check if the domain name received on the query is whitelisted (has a DD entry).
        is_whitelisted = self.is_whitelisted(packet.query_info.name)

        # Check if the current instance of server is an authority of the domain name (is a PS or SS).
        if self.is_authority(packet.query_info.name) and is_whitelisted:

            # self.log('example.com.',
            #          f'EV | {address[0]}:{address[1]} | Searching on database for {packet.query_info.name}, {packet.query_info.type_of_value}',
            #          'info')
            database_results = self.match(packet)  # Check the database for entries.

            # Check if there were any actual matches on the database, if not reply to client with.
            if len(database_results[0]) == 0:

                if len(database_results[1]) == 0 and len(database_results[2]) == 0:

                    # Domain name does not exist.
                    new_header = packet.header
                    new_header.response_code = 2
                    new_header.flags = [DNSPacketHeaderFlag.A]

                    not_found = DNSPacket(
                        header=new_header,
                        query_info=packet.query_info,
                        query_data=DNSPacketQueryData.empty()
                    )

                    # self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{not_found}', 'info')
                    self.udp_socket.sendto(not_found.as_byte_string(), address)
                    return 2

                else:

                    # Domain does exist but not here.
                    header = DNSPacketHeader(
                        message_id=packet.header.message_id,
                        flags=[DNSPacketHeaderFlag.A],
                        response_code=1,
                        number_values=0,
                        number_authorities=len(database_results[1]),
                        number_extra=len(database_results[2])
                    )

                    query_data = DNSPacketQueryData(
                        response_values=[],
                        authorities_values=database_results[1],
                        extra_values=database_results[2]
                    )

                    exists_response = DNSPacket(
                        header=header,
                        query_info=packet.query_info,
                        query_data=query_data
                    )

                    # self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{exists_response}', 'info')
                    self.udp_socket.sendto(exists_response.as_byte_string(), address)
                    return 1

            else:

                # Direct match on the database.
                header = DNSPacketHeader(
                    message_id=packet.header.message_id,
                    flags=[DNSPacketHeaderFlag.A],
                    response_code=0,
                    number_values=len(database_results[0]),
                    number_authorities=len(database_results[1]),
                    number_extra=len(database_results[2])
                )

                query_data = DNSPacketQueryData(
                    response_values=database_results[0],
                    authorities_values=database_results[1],
                    extra_values=database_results[2]
                )

                found_response = DNSPacket(
                    header=header,
                    query_info=packet.query_info,
                    query_data=query_data
                )

                # self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{found_response}', 'info')
                self.udp_socket.sendto(found_response.as_byte_string(), address)
                return 0


ss = SecondaryServer(20024, '/home/guilherme/Documents/repos/mini-dns-py/tests/config_ss.conf', 0, True)
ss.udp_start()
