import socket
from example.example_protocol import MathProtocol, MathOperation

ip_address = "127.0.0.1"
listen_from_port = 5555

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((ip_address, listen_from_port))

while True:
    data, addr = sock.recvfrom(1024)
    print("received message: %s" % data.decode('ascii'))
    packet: MathProtocol = MathProtocol.from_string(data.decode('ascii'))

    if packet.flag == MathOperation.M:
        value = 1
        for number in packet.numbers:
            value = value * number

    if packet.flag == MathOperation.S:
        value = 0
        for number in packet.numbers:
            value += number

    print(value)
