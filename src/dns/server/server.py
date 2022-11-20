import logging
from multiprocessing import Process

from dns.dns_database import Database
from dns.server.base_segment_server import BaseSegmentServer
from dns.server.server_config import ServerConfiguration
from dns.dns_packet import DNSPacket, DNSPacketQueryData, DNSPacketHeaderFlag, DNSPacketHeader
from dns.server.base_datagram_server import BaseDatagramServer

from exceptions.exceptions import InvalidDNSPacket
from models.config_entry import ConfigEntry

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

Care with duplicate entries!
"""


class PrimaryServer(BaseDatagramServer, BaseSegmentServer):
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

        self.loggers: dict[str, logging.Logger] = self.create_loggers(self.configuration.logs_path, debug)
        self.log('all', f'EV | 127.0.0.1 |Loaded configuration @ "{configuration_path}" and loggers', 'info')

        self.database: Database = Database(database=FileParserFactory(self.configuration.database_path,
                                           Mode.DB).get_parser().parse())
        self.log('all', f'EV | 127.0.0.1 |Loaded database @ "{self.configuration.database_path}"', 'info')

        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()
        self.log('all', f'EV | 127.0.0.1 | Loaded root ip address list @ "{self.configuration.root_servers_path}"', 'info')

        self.cache = Cache(maxsize=1000)

        super().__init__("127.0.0.1", port, read_size)
        super(BaseDatagramServer, self).__init__("127.0.0.1", port, read_size)

    @staticmethod
    def create_loggers(logs_list: list[ConfigEntry], debug_flag: bool):

        loggers: dict[str, logging.Logger] = {}

        for entry in logs_list:

            logger_name = entry.parameter
            logger_loc = entry.value

            # Create logger.
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.INFO)

            # Configure the handler and formatter.
            logger_handler = logging.FileHandler(logger_loc, mode='a')
            logger_formatter = logging.Formatter("%(filename)s %(levelname)s | %(asctime)s | %(message)s")

            # Add formatter to the handler and handler to the logger.
            logger_handler.setFormatter(logger_formatter)
            logger.addHandler(logger_handler)

            # Enable console output if debug is active.
            if debug_flag:

                logger_console_handler = logging.StreamHandler()
                logger_console_handler.setLevel(logging.INFO)
                logger_console_handler.setFormatter(logger_formatter)
                logger.addHandler(logger_console_handler)

            loggers[logger_name] = logger

        return loggers

    def log(self, logger_name: str, content: str, mode: str):

        if logger_name in self.loggers:
            func = getattr(self.loggers.get(logger_name), mode)
            func(content)

        if 'all' in self.loggers and logger_name != 'all':
            func = getattr(self.loggers.get('all'), mode)
            func(content)

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

        authorities_values: [DNSResource] = self.database.authorities_values(name, len(response_values) <= 0)

        extra_values: [DNSResource] = self.database.extra_values(response_values + authorities_values)

        return Database.values_as_string(response_values), Database.values_as_string(authorities_values), Database.values_as_string(extra_values)

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
        self.log('all', f'QR | {address[0]}:{address[1]} | {data}', 'info')

        # Check if the received data is a DNSPacket. If it isn't than reply to client with response code 3.
        try:
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:

            self.log('all', f'ER | {address[0]}:{address[1]} |\n{error}', 'error')
            bad_format_packet: DNSPacket = DNSPacket.generate_bad_format_response()

            self.log('all', f'RP | {address[0]}:{address[1]} |\n{bad_format_packet}', 'info')
            self.udp_socket.sendto(bad_format_packet.as_byte_string(), address)
            return 3

        # Check if the domain name received on the query is whitelisted (has a DD entry).
        is_whitelisted = self.is_whitelisted(packet.query_info.name)

        # Check if the current instance of server is an authority of the domain name (is a PS or SS).
        if self.is_authority(packet.query_info.name) and is_whitelisted:

            self.log('example.com.', f'EV | {address[0]}:{address[1]} | Searching on database for {packet.query_info.name}, {packet.query_info.type_of_value}', 'info')
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

                    self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{not_found}', 'info')
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

                    self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{exists_response}', 'info')
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

                self.log('all', f'RP | {address[0]}:{address[1]} |\n\t{found_response}', 'info')
                self.udp_socket.sendto(found_response.as_byte_string(), address)
                return 0

    def run(self):

        udp_listener = Process(target=self.udp_start)
        tcp_listener = Process(target=self.tcp_start)

        udp_listener.start()
        tcp_listener.start()

        udp_listener.join()
        tcp_listener.join()


def main():
    server = PrimaryServer(20001, "/home/guilherme/Documents/repos/mini-dns-py/tests/config.conf", debug=True)
    server.run()


if __name__ == "__main__":
    SystemExit(main())
