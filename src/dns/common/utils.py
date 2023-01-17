import struct
import os

from argparse import ArgumentTypeError

import netifaces

from parser.regex_compiles import RE_IVP4


def get_ip_from_interface(interface: str = 'eth0', localhost: bool = False) -> str:
    """
    This helper function returns the IP address from a given interface.
    The default interface used is 'eth0'.

    :param interface: Interface to get the ip from.
    :param localhost: Boolean that represents whether we want the real address or just localhost.
    :return: The obtained ip address or the localhost address if 'localhost' is set to true.
    """
    if localhost:
        return '127.0.0.1'

    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']


def __ipv4_type_validator__(arg_value, pat=RE_IVP4):
    """
    This functions validates if a value is an IPv4 address using a regex expression.

    :param arg_value: Value to check.
    :param pat: Regex expression.
    :return: Value if it's valid.
    :raises: ArgumentTypeError if it's not an IPv4 address.
    """

    if not pat.match(arg_value):
        raise ArgumentTypeError("Expected value type of IPv4 Address.")

    return arg_value


def __load_latest_id__() -> int:
    """
    Function that loads and increments the latest message stored on file.
    Its value is used to determine a client query's message id.

    :return: Latest message id.
    """

    if not os.path.exists("../../../msgid.dat"):
        with open("../../../msgid.dat", "w") as file:
            file.write('1')

        return 0

    with open("../../../msgid.dat", "r") as file:
        current_message_id: int = int(file.read())

    with open("../../../msgid.dat", "w") as file:
        incremented_id = current_message_id + 1

        if current_message_id == 65335:
            incremented_id = 0

        file.write(str(incremented_id))

    return current_message_id


def __get_latest_id__() -> str:
    """
    Function that only reads the latest id written on the file.

    :return: Returns the id as string instead of integer.
    """

    with open("../../../msgid.dat", "r") as file:
        return file.read()


def send_msg(sock, msg) -> None:
    """
    This function prefixes a message ('msg') with a 4-byte length (network byte order).
    Then it sends through the socket ('sock').

    :param sock: Socket to send the 'encoded' message.
    :param msg: Message to encode and send.
    :return: None
    """

    msg = struct.pack('>I', len(msg)) + msg  # Adding the 4-byte length.
    sock.sendall(msg)  # Sending the message.


def recv_msg(sock):
    """
    Read a message from a given socket and unpack it into an integer
    in order to obtain the message length.

    :param sock: Socket to read from.
    :return: Read data.
    """

    # Read message length and unpack it into an integer.
    raw_msglen = recvall(sock, 4)

    if not raw_msglen:
        return None

    msglen = struct.unpack('>I', raw_msglen)[0]  # Unpacking the message.

    # Read the message data.
    return recvall(sock, msglen)


def recvall(sock, n):
    """
    Helper function to receive 'n' bytes or until hits EOF from 'sock'.

    :param sock: Socket to read from.
    :param n: Number of bytes to read.
    :return: Read data from socket.
    """

    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()

    while len(data) < n:  # Reading 'n' bytes.

        packet = sock.recv(n - len(data))

        if not packet:
            return None

        data.extend(packet)

    return data


def split_address(address: str) -> tuple[str, int]:
    """
    This function, when given a string of an IPv4 address (10.0.1.12:2002) parses the address into
    a tuple of the IP address and port (10.0.1.12, 2002).

    :param address: Given address to parse.
    :return: Tuple containing the obtained values.
    """

    addr: list[str] = address.split(":")
    port: int = 53

    if len(addr) > 1:
        port = int(addr[1])

    return addr[0], port
