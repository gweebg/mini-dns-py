from dns.dns_packet import DNSPacket, DNSPacketHeaderFlag
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.server_config import ServerConfiguration

from exceptions.exceptions import InvalidDNSPacket

from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class ResolutionServer(BaseDatagramServer):
    """
    A resolution server must be able to both receive and execute queries,
    it does not have a database, only a configuration file.
    On start, the server must cache the DD values found in its configuration
    file. The DD entries indicate the address for the given IP, for example:
        lycoris.maki. DD 10.8.10.12
        ^- Domain        ^- Where is located

    Since it is both a responder and an executer, we must determine when the answer we are reading
    is a final response or a relay request. By adding to the DNS Packet a new flag F, final, we can easily
    determine the querie's objective.

    The resoulution server will only communicate via UDP, thus extending BaseDatagramServer. It is also responsible
    for relaying the query to other servers that will, via long prefix match, respond back.
    """

    def __init__(self, config_file: str, ip_address: str, port: int = 53, timeout: int = 120, debug: bool = False):
        # Initializing the UDP server, dns.server.base_datagram_server::BaseDatagramServer()
        super().__init__(ip_address, port, timeout)

        # Reading and parsing the configuration file.
        self.configuration: ServerConfiguration = FileParserFactory(config_file, Mode.CONFIG).get_parser().parse()

        # Getting the list with the root servers.
        self.root_servers: list[str] = FileParserFactory(self.configuration.root_servers_path,
                                                         Mode.RT).get_parser().parse()

        # Todo #
        # Loading database/configuration values into cache.
        # self.cache = Cache()
        # self.cache.from_configuration(self.configuration, "R")

    def relay(self, packet: DNSPacket, address: str):
        """
        This method is responsible for obtaining the query result by
        relaying possibly multiple times the query through the servers.

        :param packet: The packet we will transmit.
        :param address: The address we're going to relay to.
        :return: None
        """

        # While the answer we receive is not final, we will keep trying.
        while DNSPacketHeaderFlag.F not in packet.header.flags:

            # Relaying the packet to the intendend server at 'relay_ip_address'.
            self.udp_socket.sendto(packet.as_byte_string(), address)

            # Waiting, receving, decoding and parsing the response.
            data: str = self.udp_socket.recvfrom(self.read_size).decode('utf-8')

            try:
                received_packet: DNSPacket = DNSPacket.from_string(data)

            except InvalidDNSPacket as error:

                # Todo: Handle the exception. #
                raise

            # Let's check if the answer is already final.
            if DNSPacketHeaderFlag.F in received_packet:
                return received_packet

            # Ouch, it was not final, let's relay it to somewhere else specified on the received packet!
            # Todo #

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

        try:

            # Parsing 'data' into a DNS Packet, in order to process the query.
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:

            # Todo: Handle the exception. #
            print("Invalid DNS Packet", error)
            return 3

        # Todo #
        # Before executing the query, let's see if its cached.
        # if self.cache.match(...):
        #     ...

        # We need to know where to relay the query, it will be either to a root server, or if there's a
        # DD match, we can ask directly to the indicated address.

        # Let's check our DD records to see if we can match any sufix.
        # We are keeping a 'next_root' variable in case the root server fails to answer.
        next_root = 0

        if match := self.configuration.match_dd(packet):

            # Now we can contact this address instead of the root.
            relay_ip_address: str = match.value

        # We didn't find anything, so we will be asking the root server.
        else:

            # Todo #
            # Turn root servers into queue and pop each time ?
            # Retrieving a root server address.
            relay_ip_address: str = self.root_servers[next_root]

        # Now let's relay the query to 'relay_ip_address'!
        response: DNSPacket = self.relay(packet, relay_ip_address)

        # If the destination is a root server, and the root server is not responding, we will try another one!
        if relay_ip_address in self.root_servers:

            while response is None:

                next_root += 1
                relay_ip_address = self.root_servers[next_root]
                response = self.relay(packet, relay_ip_address)

        # Now that we have our response, let's reply to the client!
        self.udp_socket.sendto(response.as_byte_string(), address)
