import socket
import argparse
import logging

from dns.models.dns_packet import DNSPacket
from exceptions.exceptions import InvalidQueryValue, InvalidDNSPacket
from dns.utils import __ipv4_type_validator__, __load_latest_id__


# Get a custom logger & set the logging level.
client_logger = logging.getLogger("client")
client_logger.setLevel(logging.INFO)

# Configure the handler and formatter.
client_handler = logging.FileHandler("C:\\Users\\Guilherme\\Documents\\PyCharm\\mini-dns-py\\core\\logs\\client.log", mode='a')
client_formatter = logging.Formatter("%(name)s %(asctime)s %(message)s")

# Add formatter to the handler and handler to the logger.
client_handler.setFormatter(client_formatter)
client_logger.addHandler(client_handler)


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
            client_logger.info(f"EV 127.0.0.1 Created and bound socket to {self.address[0]}:{self.address[1]}.")

        except Exception as error:
            client_logger.error(f"SP 127.0.0.1 Could not create/bind socket to IP address {self.address[0]}:{self.address[1]} : {error}")
            raise

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
            client_logger.error(f"SP 127.0.0.1 Invalid query value, Client::set_query().")
            raise InvalidQueryValue("Query must be a string or a DNSPacket.")

    def send(self):
        """
        Send the query previously defined.
        :return: None
        """

        if self.query is not None:

            try:
                self.udp_socket.sendto(self.query.as_byte_string(), self.address)

            except Exception as error:
                client_logger.error(f"SP 127.0.0.1 Could not send query to {self.address[0]}:{self.address[1]} : {error}")
                raise

    def receive(self):
        """
        Receive and print to the terminal
        the query response by listening on the socket address.
        :return: None
        """

        try:
            result = self.udp_socket.recv(self.read_size).decode("utf-8")
            decoded_packet = DNSPacket.from_string(result)
            client_logger.info(f"EV 127.0.0.1 Received and parsed query response from server:\n\t{result}")

            print(decoded_packet.prettify())

        except InvalidDNSPacket as inv_dns_packet_err:
            client_logger.error(f"SP 127.0.0.1 Received an invalid query pdu string, Client::receive().")
            raise

        except Exception as error:
            client_logger.error(f"SP 127.0.0.1 Could not receive from server, Client::receive() : {error}")

        finally:
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
