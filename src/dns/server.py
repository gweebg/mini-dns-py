from dns.server_config import ServerConfiguration
from dns.dns_packet import DNSPacket, DNSPacketQueryData, DNSPacketHeaderFlag
from dns.base_datagram_server import BaseDatagramServer

from exceptions.exceptions import InvalidDNSPacket

from models.dns_resource import DNSResource, DNSValueType

from parser.parser_factory import FileParserFactory
from parser.abstract_parser import Mode

from cache.cache import Cache

import os
import errno

"""
TODOS: 
Implement cache lookup.
Check if found anything.
If didn't find anything, contact root server.
PrimaryServer has to inherit from BaseSegmentServer.
On run, create two threads, one for UDP listening and other for TCP.
Do not repeat variable names!
Change BaseDatagramServer::start() to BaseDatagramServer::dstart().
And define BaseSegmentServer::sstart().
"""


class PrimaryServer(BaseDatagramServer):
    """
    This class represents a DNS primary server. It answers queries based on its
    configuration file and database.
    """

    def __init__(self, port: int, configuration_path: str, debug: bool = False, read_size: int = 1024):
        """
        PrimaryServer constructor.

        :param port: Socket port to listen to.
        :param configuration_path: File path configuration to the servers configuration file.
        :param debug: Run in debug mode (logging to stdout) if True.
        :param read_size: Number of bytes read from a datagram socket at a time.
        """

        if not os.path.isfile(configuration_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), configuration_path)

        self.configuration: ServerConfiguration = FileParserFactory(configuration_path,
                                                                    Mode.CONFIG).get_parser().parse()

        self.database: dict[DNSValueType, list[DNSResource]] = FileParserFactory(self.configuration.database_path,
                                                                                 Mode.DB).get_parser().parse()

        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()

        self.cache = Cache(maxsize=1000)

        super().__init__("127.0.0.1", port, read_size)

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

        :param packet: DNSPacket object containing the received query.
        :return:
        """

        name: str = packet.query_info.name
        type_of_value: DNSValueType = packet.query_info.type_of_value

        above_values = []

        response_values = []
        authorities_values = []
        extra_values = []

        # Response Values : Match on NAME and TYPE OF VALUE.
        same_type_values: list[DNSResource] = self.database.get(type_of_value)

        for entry in same_type_values:
            if entry.type == type_of_value and entry.parameter == name:
                above_values.append(entry)
                response_values.append(entry)

        # Authorities Values : Match no NAME and type NS.
        nameservers = self.database.get(DNSValueType["NS"])

        for entry in nameservers:
            if entry.parameter == name:
                above_values.append(entry)
                authorities_values.append(entry)

        # Extra Values : Match all of the above on type A.
        addresses = self.database.get(DNSValueType["A"])

        for old_value in above_values:
            for address in addresses:

                updated_value = old_value
                if not old_value.value.endswith("."):
                    updated_value = old_value.value + "."

                if updated_value == address.parameter:
                    extra_values.append(address)

        response_values = list(map(lambda x: x.as_log_string(), response_values))
        authorities_values = list(map(lambda x: x.as_log_string(), authorities_values))
        extra_values = list(map(lambda x: x.as_log_string(), extra_values))

        return response_values, authorities_values, extra_values

    def is_whitelisted(self, name: str):
        """
        Check if a domain is white listed on the (self) server.

        :param name: Domain name to check.
        :return: True if its whitelisted, otherwise False.
        """
        return name[:-1] in self.configuration.allowed_domains

    def handle(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Handle the data received from the socket.
        In this case, it processes the query.

        :param data: Data received from the socket.
        :param address: (ip_address, port) tuple that represents the socket address.
        :return: An integer representing the query error code.
        """

        data: str = data.strip().decode("utf-8")

        # Check if the received data is a DNSPacket. If it isn't than reply to client with response code 3.
        try:
            received_dns_packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:
            bad_format_packet: DNSPacket = DNSPacket.generate_bad_format_response()
            self.udp_socket.sendto(bad_format_packet.as_byte_string(), address)
            return 3

        # Check if the domain name received on the query is whitelisted (has a DD entry).
        is_whitelisted = self.is_whitelisted(received_dns_packet.query_info.name)

        # Check if the current instance of server is an authority of the domain name (is a PS or SS).
        if self.is_authority(received_dns_packet.query_info.name) and is_whitelisted:
            database_results = self.match(received_dns_packet)  # Check the database for entries.

            # Check if there were any actual matches on the database, if not reply to client with.
            if len(database_results[0]) == 0:

                if len(database_results[1]) == 0 and len(database_results[2]) == 0:
                    # Domain name does not exist.

                    new_header = received_dns_packet.header
                    new_header.response_code = 2
                    new_header.flags = [DNSPacketHeaderFlag.A]

                    not_found = DNSPacket(
                        header=new_header,
                        query_info=received_dns_packet.query_info,
                        query_data=DNSPacketQueryData.empty()
                    )

                    self.udp_socket.sendto(not_found.as_byte_string(), address)
                    return 2

                else:
                    # Domain does exist but not here.

                    new_header = received_dns_packet.header
                    new_header.response_code = 1
                    new_header.flags = [DNSPacketHeaderFlag.A]

                    query_data = DNSPacketQueryData(
                        response_values=[],
                        authorities_values=database_results[1],
                        extra_values=database_results[2]
                    )

                    exists_response = DNSPacket(
                        header=new_header,
                        query_info=received_dns_packet.query_info,
                        query_data=query_data
                    )

                    self.udp_socket.sendto(exists_response.as_byte_string(), address)
                    return 1

            else:

                new_header = received_dns_packet.header

                new_header.response_code = 0
                new_header.flags = [DNSPacketHeaderFlag.A]
                new_header.number_values = len(database_results[0])
                new_header.number_authorities = len(database_results[1])
                new_header.number_extra = len(database_results[2])

                query_data = DNSPacketQueryData(
                    response_values=database_results[0],
                    authorities_values=database_results[1],
                    extra_values=database_results[2]
                )

                found_response = DNSPacket(
                    header=new_header,
                    query_info=received_dns_packet.query_info,
                    query_data=query_data
                )

                print(found_response.prettify())

                self.udp_socket.sendto(found_response.as_byte_string(), address)
                return 0


def main():
    server = PrimaryServer(20001, "../../tests/config.conf")
    server.start()


if __name__ == "__main__":
    SystemExit(main())
