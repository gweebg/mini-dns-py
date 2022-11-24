import argparse
from multiprocessing import Process
import logging
import errno
import os
import socket

from dns.dns_packet import DNSPacket, DNSPacketQueryData, DNSPacketHeaderFlag, DNSPacketHeader
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.base_segment_server import BaseSegmentServer
from dns.server.server_config import ServerConfiguration
from dns.dns_database import Database
from dns.utils import send_msg, recv_msg

from exceptions.exceptions import InvalidDNSPacket, InvalidZoneTransferPacket

from models.zone_transfer_packet import ZoneTransferPacket, ZoneTransferMode
from models.dns_resource import DNSResource, DNSValueType
from models.config_entry import ConfigEntry

from parser.parser_factory import FileParserFactory
from parser.abstract_parser import Mode


class Server(BaseDatagramServer, BaseSegmentServer):
    """
    This class represents a DNS server. It answers queries based on its
    configuration file and database.
    """

    def __init__(self, configuration_path: str, port: int = 53, timeout: int = 1600, debug: bool = False):
        """
        DNS Server constructor.

        :param port: Socket port to listen to.
        :param configuration_path: File path configuration to the servers configuration file.
        :param timeout: Milliseconds timeout value for the connection.
        :param debug: Run in debug mode (logging to stdout) if True.
        """

        if not os.path.isfile(configuration_path):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), configuration_path)

        self.configuration: ServerConfiguration = FileParserFactory(configuration_path,
                                                                    Mode.CONFIG).get_parser().parse()

        self.loggers: dict[str, logging.Logger] = self.create_loggers(self.configuration.logs_path, debug)
        self.log('all', f'EV | 127.0.0.1 | Loaded configuration at "{configuration_path}".', 'info')

        if self.configuration.primary_server is None:
            # If the server is a primary server.
            self.log('all', f'EV | 127.0.0.1 | Im a primary server!', 'info')

            self.database: Database = Database(database=FileParserFactory(self.configuration.database_path,
                                                                          Mode.DB).get_parser().parse())

            self.log('all', f'EV | 127.0.0.1 | Loaded database at "{self.configuration.database_path}"', 'info')

        else:
            # If the server is a secondary server.
            self.log('all', f'EV | 127.0.0.1 | Im a secondary server!', 'debug')

            self.database_version = 0
            self.database = self.zone_transfer()

        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()

        self.log('all', f'EV | 127.0.0.1 | Loaded root list at "{self.configuration.root_servers_path}"', 'info')

        super().__init__("127.0.0.1", port, 1024)
        super(BaseDatagramServer, self).__init__("127.0.0.1", port, 1024)

    @staticmethod
    def create_loggers(logs_list: list[ConfigEntry], debug_flag: bool):
        """
        Given a list of every log file that's supposed to exist, this function creates a logger for each entry
        and stores the logger inside a dictionary using its name as a key.

        :param logs_list: List of ConfigEntry of type LG.
        :param debug_flag: If debug_flag is enabled, we should add a handler to print to stdout.
        :return: None
        """

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
        """
        We use this function to log 'content' to 'logger_name' in mode 'mode'.
        If a 'all' logger exists, then it will always log to 'all' independently of the provided 'logger_name'.

        :param logger_name: Which logger to use.
        :param content: What content to write to the log file.
        :param mode: In which mode we want to log (info, debug, warning, error, ...)
        :return: None
        """

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

        if p_server and p_server.parameter in name:
            return True

        for s_server in self.configuration.secondary_servers:
            if s_server.parameter in name:
                return True

        return False

    def get_primary_server_address(self):
        address = self.configuration.primary_server.value

        if ":" in address:
            address = address.split(":")
            return address[0], int(address[1])

        return address, 53

    def get_primary_server_domain(self):
        return self.configuration.primary_server.parameter

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
        :return: Tuple containing the three different kind of responses.
        """

        name: str = packet.query_info.name
        type_of_value: DNSValueType = packet.query_info.type_of_value

        response_values: [DNSResource] = self.database.response_values(name, type_of_value)

        authorities_values: [DNSResource] = self.database.authorities_values(name, type_of_value, response_values)

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
        # is_whitelisted = self.is_whitelisted(packet.query_info.name)

        # Check if the current instance of server is an authority of the domain name (is a PS or SS).
        if self.is_authority(packet.query_info.name):  # and is_whitelisted:

            self.log('example.com.',
                     f'EV | {address[0]}:{address[1]} | Searching on database for {packet.query_info.name}, {packet.query_info.type_of_value}',
                     'info')
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

    def tcp_handle(self, conn: socket, address: tuple[str, int]):
        """
        Function that handles the TCP connection, in this case, since only zone transfer requests are done using TCP,
        it tries to convert the message into a ZoneTransferPacket object to process it and accomplish it.

        :param conn: Socket connection.
        :param address: Client connection (in this case secondary server's).
        :return: None
        """

        message = conn.recv(self.tcp_read_size).decode('ascii')

        try:
            # Receive DOM
            received_packet = ZoneTransferPacket.from_string(message)

            if received_packet.mode == ZoneTransferMode.DOM:

                self.log(received_packet.domain,
                         f'ZT | {address[0]} | Started a zone transfer process for {received_packet.domain} @ {address}',
                         'info')

                sender_ip: str = address[0]
                match = [address for address in map(lambda x: x.value, self.configuration.secondary_servers) if
                         address == sender_ip]

                if len(match) == 0:
                    self.log(received_packet.domain,
                             f'EZ | {sender_ip} | Received a zone transfer request but sender is not my secondary server.',
                             'error')
                    return

                if received_packet.domain not in self.configuration.get_secondary_servers_domains():
                    self.log(received_packet.domain,
                             f'EZ | {sender_ip} | Received a zone transfer request for {received_packet.domain} but I dont own the domain.',
                             'error')
                    return

                database_version: str = self.database.database[DNSValueType.SOASERIAL][0].value
                database_entries: int = self.database.get_total_entries()

                response = ZoneTransferPacket(
                    mode=ZoneTransferMode.ENT,
                    domain=received_packet.domain,
                    num_value=database_entries,
                    value=database_version
                )

                # Send ENT
                conn.send(response.as_byte_string())

                # Receive ACK
                response_ack_string = conn.recv(self.tcp_read_size).decode('ascii')
                ack_packet = ZoneTransferPacket.from_string(response_ack_string)

                if ack_packet.num_value != database_entries:
                    self.log(received_packet.domain,
                             f'EZ | {address[0]} | {address} has an updated database, aborting...',
                             'warning')
                    return

                # Send LIN
                for line in self.database.entry_string_generator():
                    send_msg(conn, line.as_log_string().encode('ascii'))

                self.log(received_packet.domain,
                         f'ZT | {address[0]} | Zone transfer process for {received_packet.domain} @ {address} concluded.',
                         'info')

        except InvalidZoneTransferPacket:
            self.log('all',
                     f'ER | {address[0]} | Received a TCP message but it was not a zone transfer request, ignoring...',
                     'warning')

        finally:
            conn.close()

    def zone_transfer(self):

        address = self.get_primary_server_address()

        self.log('all', f'ZT | {address[0]} | A zone transfer process has been started.', 'info')

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(address)

        domain = self.get_primary_server_domain()

        # Send the initialization packet for the transfer zone process.
        transfer_zone_query = ZoneTransferPacket(
            mode=ZoneTransferMode.DOM,
            domain=domain,
            num_value=0
        )
        client.send(str(transfer_zone_query).encode('ascii'))
        self.log(domain, f'QE | {address[0]} | {transfer_zone_query}', 'info')

        # Receiving the response from server containing the number of entries on the database.
        received_msg = client.recv(1024).decode('ascii')
        packet = ZoneTransferPacket.from_string(received_msg)
        self.log(domain, f'RR | {address[0]} | {packet}', 'info')

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
                self.log(domain, f'EZ | {address[0]} | My database is more recent than the PS\'s, aborting zone transfer...', 'error')

                return

        ack_packet = ZoneTransferPacket(
            mode=ZoneTransferMode.ACK,
            domain=packet.domain,
            num_value=number_of_entries
        )
        client.send(ack_packet.as_byte_string())
        self.log(domain, f'QE | {address[0]} | {ack_packet}', 'info')

        # Receiving the lines of the database.

        self.database_version = database_version
        database: dict[DNSValueType, list[DNSResource]] = {}

        for i in range(number_of_entries):
            data = recv_msg(client).decode('ascii')
            data_as_packet = DNSResource.from_string(data)
            self.log(domain, f'RR | {address[0]} | {data}', 'info')

            if data_as_packet.type not in database:
                database[data_as_packet.type] = []

            database[data_as_packet.type].append(data_as_packet)

        return Database(database=database)

    def run(self):
        """
        This function is responsible for running both TCP and UDP listeners by using a process for each.
        Since the TCP process won't need any local variables but only information from a file, we don't need to worry
        about synchronizing.

        :return: None
        """

        listeners = [self.udp_start]

        if self.configuration.primary_server is None:
            listeners.append(self.tcp_start)

        active = []

        for listener in listeners:
            proc = Process(target=listener)
            proc.start()
            active.append(proc)

        for proc in active:
            proc.join()


def main():

    parser = argparse.ArgumentParser(prog="mini-dns-server",
                                     description="mini-dns-py server application",
                                     epilog="project made by gweebg")

    parser.add_argument('-c', '--configuration',
                        required=True,
                        help='Absolute path to the configuration file.')

    parser.add_argument('-p', '--port',
                        required=False,
                        help='Socket port to listen to.')

    parser.add_argument('-t', '--timeout',
                        required=False,
                        help='Milliseconds timeout value for the connection.')

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Run in debug mode.')

    args: argparse.Namespace = parser.parse_args()

    server = Server(args.configuration, int(args.port), int(args.timeout), args.debug)
    server.run()


if __name__ == "__main__":
    SystemExit(main())


