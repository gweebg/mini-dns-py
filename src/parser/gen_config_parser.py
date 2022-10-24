from models.mode import Mode, ValueType
from exceptions.exceptions import InvalidConfigFileException
from models.config import Config, ConfigElement
from parser.abstract_parser import FileParser

import os
import re


class ConfigFileParser(FileParser):
    """
    Concrete class responsible for parsing a configuration file for either an SP, SS or SR server.
    Inherits from FileParser since it acts like one.

    Parser rules:\n
    - Lines started by '#' are considered comments and therefore ignored;
    - Empty lines must be ignored;
    - There must be a definition of a configuration parameter for each line following the syntax:
        {parameter} {value_type} {value}

        where:
            parameter: domain name | 'all' | 'root'
            value_type: 'DB' | 'SP' | 'SS' | 'DD' | 'LG' | 'ST'
            value: path | ipv4(:port)
    """

    def __init__(self, file_path_str: str, mode: Mode):
        super(ConfigFileParser, self).__init__(file_path_str, mode)

        self._re_domain = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}")
        self._re_ipv4 = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,4})?\b")

    def parse(self):
        """
        Function that parses a given configuration file for either an SP, SS or SR server.

        :return: Configuration object containing the file information.
        """

        result: Config = Config()

        content_lines = self.clean_up(self.path)

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
                        f"Value '{parameter}' is not a domain name or keyword 'all':\n\t{line}")

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
