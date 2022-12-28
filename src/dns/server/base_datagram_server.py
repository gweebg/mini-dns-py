import socket
import threading
import logging


class BaseDatagramServer:
    """
    Class that represent a simple and basic UDP server.
    The method BaseDatagramServer::udp_handle() must be overwritten by a subclass of BaseDatagramServer.
    Use the method BaseDatagramServer::udp_start() to run the server.
    """

    def __init__(self, ip_address: str, port: int, timeout: int, read_size: int = 1024):
        """
        BaseDatagramServer constructor.

        :param ip_address: IP Address to listen to.
        :param port: Port to listen to.
        :param read_size: Amount of bytes read from the socket at a time.
        """

        self.socket_address: tuple[str, int] = (ip_address, port)
        self.read_size = read_size

        self.logger = logging.getLogger('all')  # It's mandatory for this to exist according to the requirements.

        try:
            self.logger.info(f'EV | {ip_address} | UDP server is starting...')
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.settimeout(timeout)  # Todo: Fix Timeout.
            self.udp_socket.bind(self.socket_address)

        except Exception as error:
            self.logger.error(f'FL | {ip_address} |An error occurred while starting UDP server:\n{error}')
            raise

    def udp_handle(self, data: bytes, address: tuple[str, int]):
        """
        This function must be overwritten to actually do something. Its purpose is to handle the incoming data
        read on the BaseDatagramServer::udp_start() method.

        :param data: Received data in bytes, needs to be decoded.
        :param address: (IP,PORT) tuple of the sender.
        :return: None
        """
        pass

    def udp_start(self):
        """
        This function starts the listening process, on an infinite loop it listens to the specified ip address and port
        and for each message received it creates a processing thread that runs BaseDatagramServer::udp_handle().

        :return: None
        """

        self.logger.info(f'EV | {self.socket_address[0]} | UDP Server is listening on {self.socket_address[0]}:{self.socket_address[1]}')

        while True:
            encoded_data, address = self.udp_socket.recvfrom(self.read_size)
            self.logger.debug(f'EV | {self.socket_address[0]} | New UDP connection, {address} connected.')

            thread = threading.Thread(target=self.udp_handle, args=(encoded_data, address), daemon=True)
            thread.start()

            self.logger.debug(f'EV | {self.socket_address[0]} | Active UDP connections: {threading.active_count() - 1}')
