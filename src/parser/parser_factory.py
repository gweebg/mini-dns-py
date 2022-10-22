from __future__ import annotations

from parser.mode import Mode, ValueType
from exceptions.exceptions import InvalidConfigFileException
from models.config import Config, ConfigElement

from pathlib import Path
from abc import ABC, abstractmethod
import os
import errno
import re
from ipaddress import IPv4Address


class FileParser(ABC):

    def __init__(self, file_path_str: str, mode: Mode):
        self.path: str = file_path_str
        self.mode: Mode = mode

    @abstractmethod
    def parse(self):
        """ Abstract method that will do the parsing of the file and the creation of an equivalent object."""


class ConfigFileParser(FileParser):

    """
    Concrete class responsible for parsing a configuration file for either an SP, SS or SR server.
    Inherits from FileParser since it acts like one.
    """

    def __init__(self, file_path_str: str, mode: Mode):
        super(ConfigFileParser, self).__init__(file_path_str, mode)

        self._re_domain = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}")
        self._re_ipv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,4})?\b")

    def parse(self):
        """
        Function that parses a given configuration file for either an SP, SS or SR server.

        :return: Configuration object containing the file information.
        """

        result: Config = Config()

        with open(self.path, "r") as file:

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

                if self._re_domain.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name:\n\n{line}")

                if not os.path.isfile(value):
                    raise InvalidConfigFileException(f"File '{value}' does not exits:\n\t{line}")

            elif value_type == "LG":

                if self._re_domain.fullmatch(parameter) is None and (parameter != "all"):
                    raise InvalidConfigFileException(
                        f"Value '{parameter}' is not a domain name or keyword 'all':\n\n{line}")

            elif value_type == "ST":

                if parameter != "root":
                    raise InvalidConfigFileException(f"Parameter for 'ST' has to be 'root':\n\t{line}")

            elif value_type in ["SP", "SS", "DD"]:

                if self._re_domain.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name:\n\t{line}")

                if self._re_ipv4.fullmatch(value) is None:
                    raise InvalidConfigFileException(f"Address '{value}' is not a valid IP address:\n\t{line}")

            else:

                raise InvalidConfigFileException(f"Invalid value type on file '{self.path}'.\n{line}")

            element: ConfigElement = ConfigElement(mode=ValueType[value_type], value=value)

            if parameter not in result.config:
                result.config[parameter] = []

            result.config[parameter].append(element)

        return result


class DatabaseFileParser(FileParser):

    def __init__(self, file_path_str: str, mode: Mode):
        super(DatabaseFileParser, self).__init__(file_path_str, mode)

    def parse(self):
        print("Not yet implemented.")


class FileParserFactory:

    """
    Factory that creates a FileParser object given an operation mode.
    The factory does not maintain any instace of any object that creates.
    """

    def __init__(self, file_path_str: str, mode: Mode):
        if not os.path.isfile(file_path_str):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_path_str)

        self.path: str = file_path_str
        self.mode: Mode = mode

        self.call: dict = {
            Mode.CONFIG: ConfigFileParser,
            Mode.DB: DatabaseFileParser
        }

    @abstractmethod
    def get_parser(self) -> FileParser:
        """
        Provides the correct parser for the given operation mode (mode.Mode).
        :return: Correct parser object.
        """
        return self.call[self.mode](self.path, self.mode)


