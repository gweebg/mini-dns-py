import socket
from typing import Optional

from common.logger.logger import Logger
from dns.dns_packet import DNSPacket, DNSPacketHeaderFlag, DNSPacketQueryInfo
from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.server_config import ServerConfiguration

from exceptions.exceptions import InvalidDNSPacket
from models.dns_resource import DNSValueType, DNSResource

from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class ResolutionServer(BaseDatagramServer, Logger):
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

        # Storing the timeout value for later use while realying the message.
        self.timeout = timeout

        # Todo #
        # Loading database/configuration values into cache.
        # self.cache = Cache()
        # self.cache.from_configuration(self.configuration, "R")

    @staticmethod
    def get_next_address(received_packet: DNSPacket, domain_name: str) -> Optional[str]:
        """
        The get_next_address method is used to determine the next address we will be contacting.
        At this point we already know that there will only exist values on authority values and extra values.
        We need to get the 'longest' suffix match out of every authority value, not forgetting to check and replace
        the name if there's a CNAME entry for any authority, and then retrive its corresponding address from
        the extra values.

        :param received_packet: The answer obtained from one of the servers, where we will look for.
        :param domain_name: The domain name we want and need to match.
        :return: Returns the address that matched the longest suffix.
        """

        matched_authority: Optional[DNSResource] = None
        closest_index: int = -1

        # Let's first check if we can find the match without having to replace any CNAME entry.
        for auth_entry in received_packet.query_data.authorities_values:

            # Converted the string entry to a DNSResource object, for the ease of use.
            entry = DNSResource.from_string(auth_entry)

            # Here we check if the entry parameter is a substring for the domain.
            if entry.type == DNSValueType.NS and entry.parameter in domain_name:

                # If it is, we check if it is the closest substring of the authority values.
                if domain_name.index(entry.parameter) > closest_index:
                    matched_authority = entry

        # If there's still no match, then we will need to look for the CNAME entries.
        if matched_authority is None:
            # Todo, replace CNAME's like macros. #
            ...

        # Now that we're sure that we found a match, we will get it address!
        for extra_value in received_packet.query_data.extra_values:

            # Parsing the string value into a DNSResource.
            extra_entry = DNSResource.from_string(extra_value)

            # Matching the resource value and the extra value parameter to check if we got the correct address.
            if matched_authority.value == extra_entry.parameter:

                # This will be the next address we will be realying the packet to!
                return extra_entry.value

        # This function should never return None, if it does, then the server that created 'received_packet'
        # is not well-built!
        return None

    def relay(self, packet: DNSPacket, address: str) -> Optional[DNSPacket]:
        """
        This method is responsible for obtaining the query result by
        relaying possibly multiple times the query through the servers.

        :param packet: The packet we will transmit.
        :param address: The address we're going to relay to.
        :return: None
        """

        # While the answer we receive is not final, we will keep trying.
        while DNSPacketHeaderFlag.F not in packet.header.flags:

            # We need to relay the message to another socket, else there will
            # be conflict with the main listening thread.
            relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Setting the same timeout value as for the normal queries.
            relay_socket.settimeout(self.timeout)

            # Binding the socket to the given address and to a random available port (value 0 does that).
            relay_socket.bind((address, 0))

            # Relaying the packet to the intendend server at 'relay_ip_address'.
            relay_socket.sendto(packet.as_byte_string(), address)

            # Waiting, receving, decoding and parsing the response.
            data: str = relay_socket.recv(self.read_size).decode('utf-8')

            try:
                received_packet: DNSPacket = DNSPacket.from_string(data)

            except InvalidDNSPacket as error:

                # Todo: Handle the exception. #
                raise

            # Let's check if the answer is already final.
            if DNSPacketHeaderFlag.F in received_packet:
                return received_packet

            # Ouch, it was not final, let's relay it to somewhere else specified on the received packet!

            # First of all, let's check the response code, if it is 2 the domain does not exist.
            # The packet may come as an error message, but we still need to communicate it to the client.
            if received_packet.header.response_code in [2, 3]:
                return received_packet

            # Now, let's update our address to the one indicated on the received_packet.
            # To do this, let's use the method 'get_next_address'.

            address = self.get_next_address(received_packet, packet.query_info.name)

            relay_socket.close()

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

        if DNSPacketHeaderFlag.Q not in packet.header.flags:
            return 4

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
