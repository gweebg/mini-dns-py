import socket
import threading
import logging


class BaseSegmentServer:

    def __init__(self, ip_address: str, port: int, read_size: int = 1024):

        self.tcp_socket_address: tuple[str, int] = (ip_address, port)
        self.tcp_read_size = read_size

        self.tcp_logger = logging.getLogger('all')  # It's mandatory for this to exist according to the requirements.

        try:
            self.tcp_logger.info(f'EV | {ip_address} | TCP server is starting...')
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.bind(self.tcp_socket_address)
            self.tcp_socket.listen()

        except Exception as error:
            self.tcp_logger.error(f'FL | {ip_address} | An error occurred while starting the TCP server:\n{error}')
            raise

    def tcp_handle(self, conn: socket, address: tuple[str, int]):

        message = conn.recv(self.tcp_read_size).decode('ascii')
        conn.send(message.encode('ascii'))

        conn.close()

    def tcp_start(self):

        self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | TCP Server is listening on {self.tcp_socket_address[0]}:{self.tcp_socket_address[1]}')

        while True:

            conn, address = self.tcp_socket.accept()
            self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | New connection, {address} connected.')

            thread = threading.Thread(target=self.tcp_handle, args=(conn, address))
            thread.start()

            self.tcp_logger.info(f'EV | {self.tcp_socket_address[0]} | TCP Active connections: {threading.active_count() - 1}')


# if __name__ == '__main__':
#
#     x = BaseSegmentServer('localhost', 20001)
#     x.tcp_start()