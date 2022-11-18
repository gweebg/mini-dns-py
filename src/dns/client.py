import socket
import argparse
import time

from dns.dns_packet import DNSPacket
from exceptions.exceptions import InvalidQueryValue
from dns.utils import __ipv4_type_validator__, __load_latest_id__


class Client:
    """
    This class represents a mini-dns client.
    A client is able to send queries to a server by providing a query, destination ip address,
    and destination port.
    """

    def __init__(self, ip_address: str, port: int, read_size: int = 1024):

        """
        Client constructor.

        :param ip_address: Destination IPv4 address.
        :param port: Destination port.
        :param read_size: Optional parameter that sets the number of bytes read from a socket.
        """

        self.query: DNSPacket | None = None
        self.address: tuple[str, int] = (ip_address, port)
        self.read_size = read_size

        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((self.address[0], 0))

        except Exception as error:
            print("[UNEXPECTED ERROR] ", error)

    def set_query(self, query: DNSPacket | str):
        """
        Method used to set the query we're going to send.

        :param query: Query we want to send.
        :return: None
        """

        if isinstance(query, DNSPacket):
            self.query = query

        elif isinstance(query, str):
            self.query = DNSPacket.from_string(query)

        else:
            raise InvalidQueryValue("Query must be a string or a DNSPacket.")

    def send(self):
        """
        Send the query previously defined.
        :return: None
        """

        if self.query is not None:
            # self.udp_socket.sendto(self.query.as_byte_string(), self.address)
            # self.udp_socket.sendto("120,Q,0,0,0,0;abc.example.com.,MX".encode("utf-8"), self.address)
            self.udp_socket.sendto("ola".encode("utf-8"), self.address)

    def receive(self):
        """
        Receive and print to the terminal
        the query response by listening on the socket address.
        :return: None
        """

        result = self.udp_socket.recv(self.read_size).decode("utf-8")
        decoded_packet = DNSPacket.from_string(result)

        print(decoded_packet.prettify())
        self.udp_socket.close()


def main():

    current_message_id: int = __load_latest_id__()

    parser = argparse.ArgumentParser(prog="mini-dns-cl",
                                     description="mini-dns-py client application",
                                     epilog="project made by gweebg")

    parser.add_argument('destination',
                        help='IP[:PORT] address of the DNS server to query, ex. "192.168.1.2" ',
                        type=__ipv4_type_validator__)

    parser.add_argument('-n', '--name',
                        required=True,
                        help='Domain name to query, ex. "example.com."')

    parser.add_argument('-t', '--type',
                        required=True,
                        help='Type of value for the query, ex. "MX", "NS"')

    parser.add_argument('-r', '--recursive',
                        action='store_true',
                        help='Run in recursive mode.')

    parser.add_argument('-b', '--binary',
                        action='store_true',
                        help='Use the binary representation of the query instead of strings.')
    
    args: argparse.Namespace = parser.parse_args()
    flags: str = "Q+R" if args.recursive else "Q"

    port: int = 53
    if ":" in args.destination:
        parts: list[str] = args.destination.split(":")
        port = int(parts[1])
        args.destination = parts[0]

    query_string: str = f"{current_message_id},{flags},0,0,0,0;{args.name},{args.type}"
    query: DNSPacket = DNSPacket.from_string(query_string)

    client: Client = Client(args.destination, port)
    client.set_query(query)

    client.send()
    client.receive()


if __name__ == "__main__":
    SystemExit(main())
