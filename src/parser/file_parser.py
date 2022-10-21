from parser.mode import Mode
from exceptions.exceptions import InvalidConfigFileException

import os
import errno
import re


class FileParser:
    def __init__(self, file_path_str: str, mode: Mode):

        if not os.path.isfile(file_path_str):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_path_str)

        self.path: str = file_path_str
        self.mode: Mode = mode

        self.call: dict = {
            Mode.CONFIG: self.parse_config,
            Mode.DB: self.parse_database
        }

        self.re_domain = re.compile(r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}")
        self.re_ipv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,4})?\b")

    def parse_config(self, path: str):
        """
        Function that parses a given configuration file for either an SP, SS or SR server.

        :param path: Path to where the configuration file is.
        :return: Configuration object containing the file information.
        """

        with open(path, "r") as file:

            # Extract content lines, excluding all comments (including in-line) and blank lines.
            content_lines = [row.partition("#")[0].rstrip() for row in file]
            content_lines = [row for row in content_lines if row]
            content_lines = [row.split(" ") for row in content_lines]

        # Checking lines for invalid parameters, value types and values.
        for line in content_lines:

            parameter: str = line[0]
            value_type: str = line[1]
            value: str = line[2]

            if value_type == "DB":

                if self.re_domain.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name:\n\n{line}")

                if not os.path.isfile(value):
                    raise InvalidConfigFileException(f"File '{value}' does not exits:\n\t{line}")

            elif value_type == "LG":

                if self.re_domain.fullmatch(parameter) is None or parameter != "all":
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name or keyword 'all':\n\n{line}")

            elif value_type == "ST":

                if parameter != "root":
                    raise InvalidConfigFileException(f"Parameter for 'ST' has to be 'root':\n\t{line}")

            elif value_type in ["SP", "SS", "DD"]:

                if self.re_domain.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name:\n\t{line}")

                if self.re_ipv4.fullmatch(value) is None:
                    raise InvalidConfigFileException(f"Address '{value}' is not a valid IP address:\n\t{line}")

            else:

                raise InvalidConfigFileException(f"Invalid value type on file '{path}'.\n{line}")

            return "webhook-test"

    def parse_database(self, path: str):
        print("Parse Database!" + path)

    def parse(self):
        parse_function = self.call[self.mode]
        parse_function(self.path)
