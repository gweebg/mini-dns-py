import socket
from typing import Optional

from dns.models.dns_packet import DNSPacket
from dns.models.dns_resource import DNSResource, DNSValueType
from dns.common.utils import split_address
from exceptions.exceptions import InvalidDNSPacket


class Recursive:
    """
    This class gives possibility for a server to handle and process recursive queries by
    providing them with the followed methods.
    """

    @staticmethod
    def get_next_address(received_packet: DNSPacket, domain_name: str) -> Optional[str]:
        """
        The get_next_address method is used to determine the next address we will be contacting.
        At this point we already know that there will only exist values on authority values and extra values.
        We need to get the 'longest' suffix match out of every authority value, not forgetting to check and replace
        the name if there's a CNAME entry for any authority, and then retrieve its corresponding address from
        the extra values.

        :param received_packet: The answer obtained from one of the servers, where we will look for.
        :param domain_name: The domain name we want and need to match.
        :return: Returns the address that matched the longest suffix.
        """

        matched_authority: Optional[DNSResource] = None
        closest_index: int = 100

        # Let's first check if we can find the match.
        for auth_entry in received_packet.query_data.authorities_values:

            # Converted the string entry to a DNSResource object, for the ease of use.
            entry = DNSResource.from_string(auth_entry)

            # Here we check if the entry parameter is a substring for the domain.
            if entry.type == DNSValueType.NS and entry.parameter in domain_name:

                # If it is, we check if it is the closest substring of the authority values.
                if (idx := domain_name.index(entry.parameter)) <= closest_index:
                    closest_index = idx
                    matched_authority = entry

        # Now that we're sure that we found a match, we will get it address!
        for extra_value in received_packet.query_data.extra_values:

            # Parsing the string value into a DNSResource.
            extra_entry = DNSResource.from_string(extra_value)

            # Matching the resource value and the extra value parameter to check if we got the correct address.
            if matched_authority.value == extra_entry.parameter:
                # This will be the next address we will be relaying the packet to!
                return extra_entry.value

        # This function should never return None, if it does, then the server that created 'received_packet'
        # is not well-built!
        return None

    @staticmethod
    def single_relay(relay_address: str, original_query: DNSPacket, timeout: int, read_size: int) \
            -> Optional[DNSPacket]:
        """
        This method is responsible for relaying a packet ('original_packet'), one time, to a destination server
        defined as 'relay_address'. Then, it waits for a response and returns it.

        :param relay_address: Server address to relay to.
        :param original_query: Query to be made to the server pointed by 'relay_address'.
        :param timeout: Timeout value for the connection.
        :param read_size: Socket read size.
        :return: DNSPacket response if there were no errors, None otherwise.
        """

        # First we check whether the address has a specified port or not.
        # The 'split_address' also parses it into a tuple of address and port.
        next_address = split_address(relay_address)

        # We need to relay the message to another socket, else there will
        # be conflict with the main listening thread.
        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Setting the same timeout value as for the normal queries.
        relay_socket.settimeout(timeout)

        try:

            # Binding the socket to the given address and to a random available port (value 0 does that).
            relay_socket.bind((next_address[0], 0))

            # Relaying the packet to the intended server at 'next_address'.
            relay_socket.sendto(original_query.as_byte_string(), next_address)

            # Waiting, receiving and decoding the response.
            data: str = relay_socket.recv(read_size).decode('utf-8')

        except (TimeoutError, socket.error):

            # If there's an error when sending to the server, we abort and try another address.
            relay_socket.close()

            return None  # There was an error, we return None.

        # Now we're checking to see if the packet is valid.
        try:
            next_response: DNSPacket = DNSPacket.from_string(data)

        except InvalidDNSPacket:

            # Ups, the query received is wrongfully formatted, we set the packet to contain that information.
            next_response = DNSPacket.generate_bad_format_response()

        relay_socket.close()
        return next_response


