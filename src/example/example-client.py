import socket
from example.example_protocol import MathProtocol

example_query: MathProtocol = MathProtocol.from_string("1;M;10 20 30 40")
example_query_bytes = bytes(str(example_query), 'ascii')

ip_address = "127.0.0.1"
udp_port = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.bind(("127.0.0.1", 0))

sock.sendto(example_query_bytes, (ip_address, udp_port))
sock.close()

