import socket
import threading
import logging


class BaseSegmentServer:
    """
    Class that represent a simple and basic TCP server.
    The method BaseSegmentServer::tcp_handle() must be overwritten by a subclass of BaseSegmentServer.
    Use the method BaseSegmentServer::tcp_start() to run the server.
    """

    def __init__(self, ip_address: str, port: int, timeout, read_size: int = 1024):
        """
        BaseSegmentServer constructor.

        :param ip_address: IP Address to listen to.
        :param port: Port to listen to.
        :param read_size: Amount of bytes read from the socket at a time.
        """

        self.tcp_socket_address: tuple[str, int] = (ip_address, port)
        self.tcp_read_size = read_size

        self.tcp_logger = logging.getLogger('all')  # It's mandatory for this to exist according to the requirements.

        try:
            self.tcp_logger.info(f'EV | {ip_address} | TCP server is starting...')
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.settimeout(timeout)
            self.tcp_socket.bind(self.tcp_socket_address)
            self.tcp_socket.listen()

        except Exception as error:
            self.tcp_logger.error(f'FL | {ip_address} | An error occurred while starting the TCP server:\n{error}')
            raise

    def tcp_handle(self, conn: socket, address: tuple[str, int]):
        """
        This function must be overwritten to actually do something. Its purpose is to handle the incoming data
        read on the BaseDatagramServer::udp_start() method.

        :param conn: 'socket' object that can be used to receive data.
        :param address: (IP,PORT) tuple of the sender.
        :return: None
        """
        pass

    def tcp_start(self):
        """
        This function starts the listening process, on an infinite loop it listens to the specified ip address and port
        and for each message received it creates a processing thread that runs BaseSegmentServer::tcp_handle().

        :return: None
        """

        self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | TCP Server is listening on {self.tcp_socket_address[0]}:{self.tcp_socket_address[1]}')

        while True:

            conn, address = self.tcp_socket.accept()
            self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | New connection, {address} connected.')

            thread = threading.Thread(target=self.tcp_handle, args=(conn, address))
            thread.start()

            self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | TCP Active connections: {threading.active_count() - 1}')
