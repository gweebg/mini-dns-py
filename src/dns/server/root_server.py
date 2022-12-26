from typing import Optional

from dns.common.logger import Logger

from dns.models.dns_database import Database
from dns.models.dns_packet import DNSPacket, DNSPacketQueryData
from dns.models.dns_resource import DNSResource, DNSValueType

from dns.server.base_datagram_server import BaseDatagramServer
from dns.server.server_config import ServerConfiguration

from dns.utils import get_ip_from_interface

from exceptions.exceptions import InvalidDNSPacket

from parser.abstract_parser import Mode
from parser.parser_factory import FileParserFactory


class RootServer(BaseDatagramServer, Logger):
    """
    Due to the not so modular implementation of the class Server, it is needed
    an individual class for the Root Server. The only major difference is that
    the root server only tries to match the NS entries and not the ones.
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
        self.log('all', f'EV | {self.socket_address} | Loaded configuration file.', 'info')

        # Reading and parsing the database file.
        self.database: Database = Database(database=FileParserFactory(self.configuration.database_path, Mode.DB).get_parser().parse())
        self.log('all', f'EV | {self.socket_address} | Loaded database file.', 'info')

        # Storing the timeout value for later use while relaying the message.
        self.timeout = timeout

        self.log('all', f'EV | {self.socket_address} | Finished setting up the root server!', 'info')

    def match_address_to_nameserver(self, nameserver: DNSResource) -> Optional[DNSResource]:
        """
        Given a nameserver entry of the database, this method tries to match
        the nameserver to an 'A' entry of the database.

        :param nameserver: Nameserver to match.
        :return: If found the address, else None.
        """

        # Retrieving the addresses from the database.
        address_entries = self.database.database.get(DNSValueType.A)

        if address_entries:  # Check whether there's values inside the list.
            for address_entry in address_entries:

                if address_entry.parameter == nameserver.value:
                    return address_entry

        return None  # This shall never happen, for god's sake.

    def match(self, packet: DNSPacket) -> DNSPacketQueryData:
        """
        This method matches a packet to its coorresponding authorities and extra values, since
        this is a root server, we won't have any response values.

        # Todo: Ignore queries for the root domain.

        :param packet: Packet to match.
        :return: Query data used to build a response.
        """

        # The type of the query doesn't really matter, since we are the root server.
        looking_for: str = packet.query_info.name

        # Getting every NS entry on the database.
        nameservers: list[DNSResource] = self.database.database[DNSValueType.NS]
        matched_nameserver: Optional[DNSResource] = None

        if nameservers:  # Checking if we found any match.

            # Variables used to get the longest suffix match.
            closest_index: int = 100

            # Iterating over the NS entries found in the database.
            for entry in nameservers:

                # If it is a substring, we check if it is a larger suffix.
                if entry.parameter in looking_for:

                    if (index := looking_for.index(entry.parameter)) <= closest_index:

                        # Updating closest_index and the matched nameserver.
                        closest_index = index
                        matched_nameserver = entry

        # Check if we actually got a nameserver.
        if matched_nameserver:

            # Matching the nameserver got with its address.
            address: Optional[DNSResource] = self.match_address_to_nameserver(matched_nameserver)

            if address:

                return DNSPacketQueryData(
                    response_values=[],
                    authorities_values=[matched_nameserver.as_log_string()],
                    extra_values=[address.as_log_string()]
                )

        return DNSPacketQueryData.empty()  # If there was a match not found, we return an empty query data.

    def udp_handle(self, data: bytes, address: tuple[str, int]):
        """
        This method is the handle for every UDP packets that are sent to this server.
        Since it is a root server, it does not descriminate any domains, so we just look
        for the domain in our database and if there's an answer we send it, else we just
        tell the client that the domain does not exist.

        :param data: Recevied binary encoded data from the socket.
        :param address: The addres from which the data came from.
        :return: Final response code of the found/created answer.
        """

        # Decoding the received binary encoded data.
        data: str = data.strip().decode("utf-8")
        self.log('all', f'QR | {address} | Received and decoded a query: {data}', 'info')

        try:

            # Parsing 'data' into a DNS Packet, in order to process the query.
            packet: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket as error:

            # Creating and sending a packet with the information for a parsing error (response code = 3).
            bad_format_response: DNSPacket = DNSPacket.generate_bad_format_response()
            self.udp_socket.sendto(bad_format_response.as_byte_string(), address)

            self.log('all', f'ER | {address} | Received bad query packet.', 'error')

            return 3  # Returning the response code.

        self.log('all',
                 f'EV | {address} | Searching for {packet.query_info.name}, {packet.query_info.type_of_value}',
                 'info')

        database_results: DNSPacketQueryData = self.match(packet)  # Check the database for entries.

        # Build a DNS packet based on the database results found.
        response_packet: DNSPacket = DNSPacket.build_packet(packet, database_results)

        # Send the found response to the original sender.
        self.udp_socket.sendto(response_packet.as_byte_string(), address)

        self.log('all', f'RP | {address} | Found and sent an answer to the query:\n\n{response_packet}\n', 'info')

        return response_packet.header.response_code  # Response code from the 'response_packet', never used.

    def run(self):

        try:
            self.udp_start()

        except KeyboardInterrupt:
            self.log('all', f'EV | {self.socket_address} | Shutting down!', 'info')