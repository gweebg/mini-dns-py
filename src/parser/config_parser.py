from exceptions.exceptions import InvalidConfigFileException

from models.config_entry import ConfigEntry

from dns.server.server_config import ServerConfiguration

from parser.regex_compiles import RE_DOMAIN, RE_IVP4
from parser.abstract_parser import FileParser
from parser.abstract_parser import Mode

import os


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

    def parse(self) -> ServerConfiguration:
        """
        Function that parses a given configuration file for either an SP, SS or SR server.

        :return: Configuration object containing the file information.
        """

        configuration = ServerConfiguration()

        content_lines = self.clean_up(self.path)

        # Checking lines for invalid parameters, value types and values.
        for line in content_lines:

            parameter: str = line[0]
            value_type: str = line[1]
            value: str = line[2]

            if value_type == "DB":

                if RE_DOMAIN.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"DB: Value '{parameter}' is not a domain name: {line}")

                if not os.path.isfile(value):
                    raise InvalidConfigFileException(f"File '{value}' does not exits: {line}")

                configuration.database_path = value

            elif value_type == "LG":

                if RE_DOMAIN.fullmatch(parameter) is None and (parameter != "all"):
                    raise InvalidConfigFileException(
                        f"Value '{parameter}' is not a domain name or keyword 'all': {line}")

                configuration.logs_path.append(ConfigEntry(line))

            elif value_type == "ST":

                if parameter != "root":
                    raise InvalidConfigFileException(f"Parameter '{parameter}' has to be 'root': {line}")

                configuration.root_servers_path = value

            elif value_type in ["SP", "SS", "DD"]:

                if RE_DOMAIN.fullmatch(parameter) is None:
                    raise InvalidConfigFileException(f"Value '{parameter}' is not a domain name: {line}")

                if RE_IVP4.fullmatch(value) is None:
                    raise InvalidConfigFileException(f"Address '{value}' is not a valid IP address: {line}")

                if value_type == "SP":
                    configuration.primary_server = ConfigEntry(line)

                elif value_type == "SS":
                    configuration.secondary_servers.append(ConfigEntry(line))

                else:
                    configuration.allowed_domains.append(ConfigEntry(line))

            else:
                raise InvalidConfigFileException(f"Invalid value type on file '{self.path}': {line}")

        return configuration

