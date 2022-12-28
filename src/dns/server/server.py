import argparse
import socket
import time

from multiprocessing import Process
from typing import Optional

from dns.common.timer import RepeatedTimer
from dns.common.logger import Logger

from dns.models.dns_packet import DNSPacket, DNSPacketQueryData, DNSPacketHeaderFlag, DNSPacketHeader
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.base_segment_server import BaseSegmentServer
from dns.server.root_server import RootServer
from dns.server.server_config import ServerConfiguration
from dns.models.dns_database import Database
from dns.utils import send_msg, recv_msg, get_ip_from_interface

from exceptions.exceptions import InvalidDNSPacket, InvalidZoneTransferPacket

from dns.models.zone_transfer_packet import ZoneTransferPacket, ZoneTransferMode
from dns.models.dns_resource import DNSResource, DNSValueType

from parser.parser_factory import FileParserFactory
from parser.abstract_parser import Mode


class Server(BaseDatagramServer, BaseSegmentServer, Logger):
    """
    This class represents a DNS server. It answers queries based on its
    configuration file and database.
    """

    def __init__(self, config_path: str, port: int = 53, timeout: int = 1600, debug: bool = False, root: bool = False):
        """
        DNS Server constructor.

        :param port: Socket port to listen to.
        :param config_path: File path configuration to the servers configuration file.
        :param timeout: Milliseconds timeout value for the connection.
        :param debug: Run in debug mode (logging to stdout) if True.
        """

        # Initializing both the UDP and TCP listeners.
        super().__init__(get_ip_from_interface(localhost=True), port, timeout, 1024)  # UDP
        super(BaseDatagramServer, self).__init__(get_ip_from_interface(localhost=True), port, timeout, 1024)  # TCP

        # Storing the flag that indicates whether the server is a root server or not.
        self.is_root = root

        # Loading and storing the server configuration.
        self.configuration: ServerConfiguration = FileParserFactory(config_path,
                                                                    Mode.CONFIG).get_parser().parse()

        # Setting up the logging 'module'.
        super(BaseSegmentServer, self).__init__(self.configuration.logs_path, debug)
        self.log('all', f'EV | {self.socket_address} | Loaded configuration file.', 'info')

        # If the server is a primary server.
        if self.configuration.primary_server is None:
            self.log('all', f'EV | {self.socket_address} | Setting up as a Primary Server.', 'info')

            self.database: Database = Database(database=FileParserFactory(self.configuration.database_path,
                                                                          Mode.DB).get_parser().parse())

            self.log('all', f'EV | {self.socket_address} | Loaded database file.', 'info')

        # If the server is a secondary server.
        else:
            self.log('all', f'EV | {self.socket_address} | Setting up as a Secondary Server.', 'info')

            # This stores the database version for the secondary server and the last time it was updated.
            self.database_version = 0
            self.database_updated_at = 0

            # Let's start with an empty database, and then run the zone transfer process.
            self.database: Optional[Database] = None
            self.zone_transfer()

            # Now we will schedule the zone transfer process to run every
            time_interval = self.database.database.get(DNSValueType.SOAEXPIRE)[0].value  # Getting the time interval.
            self.zone_transfer_timer = RepeatedTimer(int(time_interval), self.zone_transfer)

        # Loading and storing the list of addresses of the root servers.
        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()

        self.log('all', f'EV | {self.socket_address}| Loaded root list file.', 'info')

        self.log('all', f'EV | {self.socket_address} | Finished setting up the server.', 'info')

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

        if not p_server or not len(self.configuration.secondary_servers) == 0:
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

    def is_whitelisted(self, name: str):
        """
        Check if a domain is white listed on the (self) server.

        :param name: Domain name to check.
        :return: True if its whitelisted, otherwise False.
        """

        for allowed_domain in self.configuration.allowed_domains:

            if allowed_domain.parameter in name:

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
                look for authorities by searching for given domain's super-domain (example.com -> .com)
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

    def udp_handle(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Handle the data received from the socket.
        In this case, it processes the query.

        :param data: Data received from the socket.
        :param address: (ip_address, port) tuple that represents the socket address.
        :return: An integer representing the query error code.
        """

        # Receiving and decoding the binary encoded data from the UDP socket.
        data: str = data.strip().decode("utf-8")
        self.log('all', f'QR | {address} | Received and decoded a query: {data}', 'info')

        try:
            # Check if the received data is a DNSPacket.
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket:

            # Generating the error packet.
            self.log('all', f'ER | {address} | Failed to parse the data into a DNSPacket: {data}', 'error')
            bad_format_packet = DNSPacket.generate_bad_format_response()

            # Sending the error packet to the client.
            self.log('all', f'RP | {address} | Sent to address "invalid dns packet" packet.', 'info')
            self.udp_socket.sendto(bad_format_packet.as_byte_string(), address)

            return 3

        # Check if the domain name received on the query is whitelisted (has a DD entry).
        is_whitelisted = self.is_whitelisted(packet.query_info.name)

        # Check if the current instance of server is an authority of the domain name (is a PS or SS).
        # A primary server will only act uppon a query if the domain its about is the server itself or
        # a subdomain and if the domain is whitelisted on the configuration file.
        if self.is_authority(packet.query_info.name) and is_whitelisted:

            self.log(packet.query_info.name,
                     f'EV | {address} | Searching on database for '
                     f'{packet.query_info.name}, {packet.query_info.type_of_value}',
                     'info')

            # Check the database for entries.
            database_results = self.match(packet)

            # Check if there were any actual matches on the database, if not reply to client with.
            # The Server::match() method returns a tuple with the 3 kinds of values, we still need to
            # construct the packet.

            # Building the query data part, it is used on the DNSPacket::build_packet() method.
            response_data = DNSPacketQueryData(
                response_values=database_results[0],
                authorities_values=database_results[1],
                extra_values=database_results[2]
            )

            # Building the response packet.
            response_packet = DNSPacket.build_packet(packet, response_data)
            response_code = response_packet.header.response_code

            # Logging the results.
            if response_code == 2:

                self.log('all', f'RP | {address} | Domain {packet.query_info.name} does not exist.', 'info')

            elif response_code == 1:

                self.log('all', f'RP | {address} | Domain {packet.query_info.name} exists but its my subdomain.', 'info')

            else:

                self.log('all', f'RP | {address} | Perfect match on {packet.query_info.name}, {packet.query_info.type_of_value}', 'info')

            self.udp_socket.sendto(response_packet.as_byte_string(), address)
            return response_code

        # Worst case scenario, I have no authority over the domain.
        new_header = packet.header
        new_header.response_code = 2
        new_header.flags = [DNSPacketHeaderFlag.A]

        not_found_packet = DNSPacket(
            header=new_header,
            query_info=packet.query_info,
            query_data=DNSPacketQueryData.empty()
        )

        self.log('all', f'RP | {address} | Domain {packet.query_info.name} does not exist.', 'info')
        self.udp_socket.sendto(not_found_packet.as_byte_string(), address)
        return 2

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
                             f'EZ | {sender_ip} | Received a zone transfer request but sender is not my secondary '
                             f'server.',
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
        """
        Method responsible fot the process of zone transfer.
        :return: None
        """

        # Alright, first let's check if the server can request a database update.
        # We can do that by checking the last updated time and checking if a delay as passed.

        # Checking if this is not the first run.
        if self.database is not None:

            self.log('all', f'EZ | 127.0.0.1 | Tried to zone transfer but RETRY hasnt passed.', 'error')

            # Getting the retry delay value from the database, SOARETRY.
            retry_delay = int(self.database.database.get(DNSValueType.SOARETRY)[0].value)

            # If the current time is less than the last updated time plus the retry delay, then the delay has not passed
            # in this case, we exit from the function.
            if time.time() < self.database_updated_at + retry_delay:
                self.database_updated_at = time.time()
                return

        # Retrieving the address of the servers primary server.
        address = self.get_primary_server_address()

        self.log('all', f'ZT | {address[0]} | A zone transfer process has been started.', 'info')

        # Establishing and connecting to a TCP connection with the primary server.
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

            # Checking if the database version of the server is less updated than mine.
            # If so we abort the process by sending a special end connection packet.
            if database_version <= self.database_version:

                # End connection packet to terminate the connection.
                end_connection_packet = ZoneTransferPacket(
                    mode=ZoneTransferMode.ACK,
                    domain=packet.domain,
                    num_value=0
                )

                client.send(end_connection_packet.as_byte_string())
                self.log(domain, f'EZ | {address[0]} | My database is more recent than the PS\'s, aborting zone '
                                 f'transfer...', 'error')

                return

        # If the version is superior to ours, we confirm that we want the database.
        ack_packet = ZoneTransferPacket(
            mode=ZoneTransferMode.ACK,
            domain=packet.domain,
            num_value=number_of_entries
        )
        client.send(ack_packet.as_byte_string())
        self.log(domain, f'QE | {address[0]} | {ack_packet}', 'info')

        # Now everything is prepared for us to receive the lines of the database.

        self.database_version = database_version  # Updating the database version.
        database: dict[DNSValueType, list[DNSResource]] = {}  # Empty database.

        # Reading the exact number of lines of the database.
        for i in range(number_of_entries):

            data = recv_msg(client).decode('ascii')
            data_as_packet = DNSResource.from_string(data)
            self.log(domain, f'RR | {address[0]} | {data}', 'info')

            if data_as_packet.type not in database:
                database[data_as_packet.type] = []

            # Adding the resource to the database.
            database[data_as_packet.type].append(data_as_packet)

        # Setting the database acquired and the update time.
        self.database = Database(database=database)
        self.database_updated_at = time.time()

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

    parser.add_argument('-r', '--root',
                        action='store_true',
                        help='Flag that indicates whether the server is root or not.')

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='Run in debug mode.')

    args: argparse.Namespace = parser.parse_args()

    if args.root:

        server = RootServer(args.configuration, int(args.port), int(args.timeout), args.debug)

    else:

        server = Server(args.configuration, int(args.port), int(args.timeout), args.debug)

    server.run()


if __name__ == "__main__":
    SystemExit(main())

