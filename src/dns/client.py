import socket
import argparse

from dns.dns_packet import DNSPacket
from exceptions.exceptions import InvalidQueryValue
from dns.utils import __ipv4_type_validator__, __load_latest_id__


class Client:

    def __init__(self, ip_address: str, port: int, read_size: int = 1024):

        self.query: DNSPacket | None = None
        self.address: tuple[str, int] = (ip_address, port)
        self.read_size = read_size

        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((self.address[0], 0))

        except Exception as error:
            print("[UNEXPECTED ERROR] ", error)

    def set_query(self, query: DNSPacket | str):

        if isinstance(query, DNSPacket):
            self.query = query

        elif isinstance(query, str):
            self.query = DNSPacket.from_string(query)

        else:
            raise InvalidQueryValue("Query must be a string or a DNSPacket.")

    def send(self):

        if self.query is not None:
            self.udp_socket.sendto(self.query.as_byte_string(), self.address)

            encoded_answer: bytes = self.udp_socket.recv(self.read_size)
            print(encoded_answer.decode("utf-8"))

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

    query_string: str = f"{current_message_id},{flags},0,0,0,0;{args.name},{args.type}"
    query: DNSPacket = DNSPacket.from_string(query_string)

    # client: Client = Client(args.destination, 20001)  # TODO: Extract port from IP or default it to 53.
    # client.set_query(query)
    # client.send()


if __name__ == "__main__":
    SystemExit(main())
