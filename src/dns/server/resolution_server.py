import argparse
import socket

from typing import Optional

from dns.common.cache import Cache
from dns.common.logger import Logger
from dns.common.recursive import Recursive

from dns.models.dns_packet import DNSPacket, DNSPacketHeaderFlag
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.server_config import ServerConfiguration
from dns.common.utils import split_address, get_ip_from_interface

from exceptions.exceptions import InvalidDNSPacket

from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class ResolutionServer(BaseDatagramServer, Logger, Recursive, Cache):
    """
    A resolution server must be able to both receive and execute queries,
    it does not have a database, only a configuration file.
    On start, the server must cache the DD values found in its configuration
    file. The DD entries indicate the address for the given IP, for example:
        lycoris.maki. DD 10.8.10.12
        ^- Domain        ^- Where is located

    Since it is both a responder and an executer, we must determine when the answer we are reading
    is a final response or a relay request. By adding to the DNS Packet a new flag F, final, we can easily
    determine the queries objective.

    The resolution server will only communicate via UDP, thus extending BaseDatagramServer. It is also responsible
    for relaying the query to other servers that will, via long prefix match, respond back.
    """

    def __init__(self, config_file: str, port: int = 53, timeout: int = 120, debug: bool = False):

        # First, let's get our IP address.
        self.ip_address = get_ip_from_interface(localhost=True)

        # Initializing the UDP server, dns.server.base_datagram_server::BaseDatagramServer()
        super().__init__(self.ip_address, port, timeout)

        # Reading and parsing the configuration file.
        self.configuration: ServerConfiguration = FileParserFactory(config_file, Mode.CONFIG).get_parser().parse()

        # Setting up the logger.
        super(BaseDatagramServer, self).__init__(self.configuration.logs_path, debug)

        self.log('all', f'ST | localhost |\nResolution Server information:\n'
                        f' +address:{self.socket_address[0]}\n'
                        f' +port:{self.socket_address[1]}\n'
                        f' +timeout:{timeout}', 'info')

        self.log('all', 'EV | localhost | Loaded configuration file.', 'info')

        # Getting the list with the root servers.
        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()
        self.log('all', 'EV | localhost | Loaded root list file.', 'info')

        # Storing the timeout value for later use while relaying the message.
        self.timeout = timeout

        # Initializing cache.
        super(Recursive, self).__init__()
        self.log('all', 'EV | localhost | Cache initialized.', 'info')

        self.log('all', 'EV | localhost | Finished setting up the resolution server!', 'info')

    @staticmethod
    def get_max_hops_from_name(name: str):
        return name.count(".")

    def relay(self, packet: DNSPacket, address: tuple[str, int]) -> Optional[DNSPacket]:
        """
        This method is responsible for obtaining the query result by
        relaying possibly multiple times the query through the servers.

        :param packet: The packet we will transmit.
        :param address: The address we're going to relay to.
        :return: None
        """

        max_hops: int = self.get_max_hops_from_name(packet.query_info.name)
        current_hop: int = 0

        # While the answer we receive is not final, we will keep trying.
        while True:

            self.log('all', f'EV | localhost | Asking {address[0]}:{address[1]} for {str(packet.query_info)}', 'info')

            # We need to relay the message to another socket, else there will
            # be conflict with the main listening thread.
            relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Setting the same timeout value as for the normal queries.
            relay_socket.settimeout(self.timeout // 2)

            try:

                # Binding the socket to the given address and to a random available port (value 0 does that).
                # relay_socket.bind((address[0], 0))

                # Relaying the packet to the intended server at 'relay_ip_address'.
                relay_socket.sendto(packet.as_byte_string(), address)

                # Waiting, receiving, decoding and parsing the response.
                data: str = relay_socket.recv(self.read_size).decode('utf-8')

                self.log('all', f'EV | localhost | Established connection with {address[0]}:{address[1]}.', 'info')

            except (socket.error, socket.timeout, TimeoutError):

                # If there's an error when sending to the server, we abort and try another address.
                relay_socket.close()

                self.log('all', f'TO | localhost | Connection with {address[0]}:{address[1]} timed out.', 'warning')

                return None  # This will trigger the 'udp_handle' to choose another root server address.

            try:
                received_packet: DNSPacket = DNSPacket.from_string(data)

            except InvalidDNSPacket as error:

                self.log('all',
                         f'ER | {address[0]}:{address[1]} | Failed to parse the data into a DNSPacket:\n{error}\n',
                         'error')

                # Ups, the query received is wrongfully formatted, let's warn the user.
                return DNSPacket.generate_bad_format_response()

            current_hop += 1

            if current_hop >= max_hops:
                return received_packet

            # Let's check if the answer is already final.
            if received_packet.header.response_code == 0:

                self.add_from_query_data(received_packet.query_data)
                self.log('all', f'EV | localhost | Added to cache:\n{str(received_packet)}', 'info')

                return received_packet

            # Ouch, it was not final, let's relay it to somewhere else specified on the received packet!

            # First of all, let's check the response code, if it is 2 the domain does not exist.
            # The packet may come as an error message, but we still need to communicate it to the client.
            if received_packet.header.response_code in [2, 3]:
                return received_packet

            # Now, let's update our address to the one indicated on the received_packet.
            # To do this, let's use the method 'get_next_address' with the split_address,
            # so we can already have the address divided into the address and port tuple.
            address = split_address(self.get_next_address(received_packet, packet.query_info.name))

            relay_socket.close()  # Closing the socket before starting all over again.

    def udp_handle(self, data: bytes, address: tuple[str, int]):
        """
        Handle the data received from the socket.
        In this case, it processes the query.

        :param data: Data received from the socket.
        :param address: (ip_address, port) tuple that represents the socket address.
        :return: An integer representing the query error code.
        """

        # Decoding the received binary data.
        data: str = data.strip().decode("utf-8")
        self.log('all', f'QR | {address[0]}:{address[1]} | Received and decoded a query: {data}', 'info')

        try:

            # Parsing 'data' into a DNS Packet, in order to process the query.
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:

            # Creating and sending a packet with the information for a parsing error (response code = 3).
            self.log('all', f'ER | {address[0]}:{address[1]} | Failed to parse the data into a DNSPacket:\n{error}\n',
                     'error')
            bad_format_response: DNSPacket = DNSPacket.generate_bad_format_response()

            self.log('all', f'RP | {address[0]}:{address[1]} | Sent to address:\n{str(bad_format_response)}\n', 'info')
            self.udp_socket.sendto(bad_format_response.as_byte_string(), address)

            return 3  # Returning the response code.

        if DNSPacketHeaderFlag.Q not in packet.header.flags:
            # If the query isn't of type Q then we shall ignore it.
            self.log('all', f'EV | localhost | Received a query but it does not contain flag Q.', 'warning')

            return 4  # Let's just return 4, as the time of being.

        # Before executing the query, let's see if its cached.
        cached_data = self.cache_match(packet.query_info)
        if cached_data:

            # The variable 'cached_data' is an object of type DNSPacketQueryData.
            # Building the packet with the obtained data.
            response = DNSPacket.build_packet(packet, cached_data, True)

            self.log('all', f'EV | localhost | Found a response in cache for:\n{str(packet)}', 'info')

        else:

            # We need to know where to relay the query, it will be either to a root server, or if there's a
            # DD match, we can ask directly to the indicated address.

            # Let's check our DD records to see if we can match any suffix.
            # We are keeping a 'next_root' variable in case the root server fails to answer.
            next_root: int = 0

            if match := self.configuration.match_dd(packet):

                # Now we can contact this address instead of the root.
                relay_ip_address: tuple[str, int] = split_address(match.value)
                self.log('all', f'EV | localhost | Found a match in DD entries for the next hop!', 'info')

            # We didn't find anything, so we will be asking the root server.
            else:

                # Retrieving a root server address.
                relay_ip_address = split_address(self.root_servers[next_root])
                self.log('all', f'EV | localhost | Relay address set to one of the root servers.', 'info')

            # Now let's relay the query to 'relay_ip_address'!
            response: DNSPacket = self.relay(packet, relay_ip_address)

            # If the destination is a root server, and the root server is not responding, we will try another one!
            string_address: str = f'{relay_ip_address[0]}:{relay_ip_address[1]}'
            if string_address in self.root_servers:

                while response is None:

                    self.log('all', f'FL | localhost | Failed to contact root server {self.root_servers[next_root]}, '
                                    f'trying next!', 'warning')

                    next_root += 1

                    # When we reach the final root server we can't do anything more, thus we end the connection.
                    if next_root + 1 >= len(self.root_servers):
                        self.log('all', f'FL | localhost | Could not find a root server that was available.', 'error')
                        return 5

                    relay_ip_address = split_address(self.root_servers[next_root])
                    response = self.relay(packet, relay_ip_address)

        # Now that we have our response, let's reply to the client!
        self.udp_socket.sendto(response.as_byte_string(), address)
        self.log('all', f'RR | {address[0]}:{address[1]} | Sent the final query response to the client:\n{str(response)}\n', 'info')

    def run(self):

        try:
            self.udp_start()

        except KeyboardInterrupt:

            self.udp_socket.close()
            self.log('all', f'SP | localhost | Shutting down!', 'info')


# Setting up the launch part of the server.
def main():

    # Setting up the command line argument parser.
    parser = argparse.ArgumentParser(prog="mini-dns-resolution-server",
                                     description="mini-dns-py resolution server application",
                                     epilog="project made by gweebg")

    # Adding the four possible arguments, self-descriptive.
    parser.add_argument('-c', '--configuration',
                        required=True,
                        help='absolute path to the configuration file.')

    parser.add_argument('-p', '--port',
                        required=False,
                        help='socket port to listen to.')

    parser.add_argument('-t', '--timeout',
                        required=False,
                        help='milliseconds timeout value for the connection.')

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help='run in debug mode.')

    # Parsing the arguments.
    args: argparse.Namespace = parser.parse_args()

    # Initializing and running the resolution server on the specified arguments.
    res_server = ResolutionServer(args.configuration, int(args.port), int(args.timeout), args.debug)
    res_server.run()


if __name__ == "__main__":
    SystemExit(main())
