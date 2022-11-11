import socket

from dns.dns_packet import DNSPacket
from exceptions.exceptions import InvalidQueryValue


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

    query = """3874,R+A,0,2,3,5;example.com.,MX;
    example.com. MX mx1.example.com 86400 10,
    example.com. MX mx2.example.com 86400 20;
    example.com. NS ns1.example.com. 86400,
    example.com. NS ns2.example.com. 86400,
    example.com. NS ns3.example.com. 86400;
    mx1.example.com. A 193.136.130.200 86400,
    mx2.example.com. A 193.136.130.201 86400,
    ns1.example.com. A 193.136.130.250 86400,
    ns2.example.com. A 193.137.100.250 86400,
    ns3.example.com. A 193.136.130.251 86400;"""

    query_packet: DNSPacket = DNSPacket.from_string(query)
    client: Client = Client("127.0.0.1", 20001)
    client.set_query(query_packet)
    client.send()


if __name__ == "__main__":
    SystemExit(main())
