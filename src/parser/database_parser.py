from parser.abstract_parser import Mode
from parser.abstract_parser import FileParser
from exceptions.exceptions import InvalidDatabaseFileException
from parser.regex_compiles import *
from models.dns_resource import DNSResource, DNSValueType

import re
from typing import Callable


class DatabaseFileParser(FileParser):

    def __init__(self, file_path_str: str, mode: Mode):
        super(DatabaseFileParser, self).__init__(file_path_str, mode)

        self.operations = {
            'DEFAULT': self._parse_default,
            'SOASP': self._parse_soasp,
            'SOAADMIN': self._parse_soaadmin,
            'SOASERIAL': self._parse_soa_srl_rfr_rtr_exp,
            'SOAREFRESH': self._parse_soa_srl_rfr_rtr_exp,
            'SOARETRY': self._parse_soa_srl_rfr_rtr_exp,
            'SOAEXPIRE': self._parse_soa_srl_rfr_rtr_exp,
            'NS': self._parse_ns_mx,
            'MX': self._parse_ns_mx,
            'A': self._parse_a,
            'CNAME': self._parse_cname,
            'PTR': self._parse_ptr
        }

        self.macros = {}
        self.alias = {}
        # self.dns_entries = None

    @staticmethod
    def _check_ttl_value(value_string: str) -> bool:

        if value_string.isnumeric() and int(value_string) in range(0, 255):
            return True

        return False

    def _replace_macros(self, line: list[str], ignore_index: int | None = None) -> list[str]:

        for macro in self.macros:
            if ignore_index is not None:
                for idx, line_slice in enumerate(line):
                    if macro in line_slice and ignore_index != idx:
                        line[idx] = line[idx].replace(macro, self.macros[macro])
            else:
                for idx, line_slice in enumerate(line):
                    if macro in line_slice:
                        line[idx] = line[idx].replace(macro, self.macros[macro])

        if not line[0].endswith('.'):
            line[0] = line[0] + f".{self.macros.get('@')}"

        if not line[2].endswith('.') and line[1] == 'CNAME':
            line[2] = line[2] + f".{self.macros.get('@')}"

        return line

    def _parse_default(self, line: list[str]) -> None:
        """
        DEFAULT value type defines a name as a macro that must be replaced by its literal associated value.
        The parameter '@' is reserved and used to identify a prefix by default that is added every time a domain name
        doesn't appear on a full completer form.

        Parameter must be an alphanumeric string.
        Value must be valid domain name if parameter is '@'.

        This field does not accept priority values.

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        if len(line) != 3:
            raise InvalidDatabaseFileException(f"Macro setting must have an assigned value:\n\t{line}")

        if line[0] == '@' and not re.fullmatch(RE_DOMAIN_DOT, line[2]):
            raise InvalidDatabaseFileException(
                f"Restricted macro '@' must have a valid domain name as value: {line[2]}")

        self.macros[line[0]] = line[2]

    def _parse_soasp(self, line: list[str]) -> DNSResource:
        """
        Value indicates the full name of the domain primary server (or zone) given on the parameter.

        Parameter must be a valid macro or domain name.
        Time to live must be a valid macro of integer.

        Example: '@ SOASP ns1.example.com. TTL'

        This field does not accept priority values.

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        if len(line) != 4:
            raise InvalidDatabaseFileException(f"SOASP: Not enough values were provided: {line}")

        # Macro replacement.
        line = self._replace_macros(line)

        if not re.fullmatch(RE_DOMAIN_DOT, line[0]):
            raise InvalidDatabaseFileException(f"SOASP: Invalid domain name: {line[0]}")

        if not re.fullmatch(RE_DOMAIN_DOT, line[2]):
            raise InvalidDatabaseFileException(f"SOASP: Invalid domain name: {line[2]}")

        if not line[3].isnumeric():
            raise InvalidDatabaseFileException(f"SOASP: Time-to-Live must be a number: {line[3]}")

        return DNSResource(line)

    def _parse_soaadmin(self, line: list[str]) -> DNSResource:
        """
        Value indicates e-mail address of domain administrator (or zone).
        The symbol '@' must be replaced by a dot, '.' and dots before the '@' must be preceded by a '\'.

        Parameter must be a valid macro or domain name.
        Time to live must be a valid macro or integer.

        This field does not accept priority values.

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        if len(line) != 4:
            raise InvalidDatabaseFileException(f"SOAADMIN: Not enough values were provided.\n\t{line}")

        # Macro replacement.
        line = self._replace_macros(line, 2)

        if not re.fullmatch(RE_DOMAIN_DOT, line[0]):
            raise InvalidDatabaseFileException(f"SOAADMIN: Invalid domain name: {line[0]}")

        if re.fullmatch(RE_EMAIL, line[2]):

            at_index = line[2].rfind('@')
            new_email_value = line[2][:at_index].replace('.', '\\.')
            new_email_value = f"{new_email_value}{line[2][at_index:].replace('@', '.')}"
            line[2] = new_email_value

        else:
            raise InvalidDatabaseFileException(f"SOAADMIN: Invalid e-mail address.\n\t{line[2]}")

        if not line[3].isnumeric():
            raise InvalidDatabaseFileException(f"SOAADMIN: Time-to-Live must be a number.\n\t{line[3]}")

        return DNSResource(line)

    def _parse_soa_srl_rfr_rtr_exp(self, line: list[str]) -> DNSResource:
        """
        SOASERIAL: Value indicates serial number of database of the primary server (SP) given on parameter.
                   Everytime time that the database is changed this value has to increment.

        SOAREFRESH: Value indicates a time interval in seconds for a secondary server (SS) to ask a primary server
                    (SP) what is the SOASERIAL value.

        SOARETRY: Value defines a time interval for the SS to re-ask SP what the SOASERIAL value is (after a timeout).

        SOAEXPIRE: Value defines a time interval to let a SS to stop giving a fuck about its database replica.

        Examples:
            @ SOASERIAL 0117102022 TTL
            @ SOAREFRESH 14400 TTL
            @ SOARETRY 3600 TTL
            @ SOAEXPIRE 604800 TTL

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        if len(line) != 4:
            raise InvalidDatabaseFileException(f"{line[0]}: Not enough values were provided.\n\t{line}")

        line = self._replace_macros(line)

        if not re.fullmatch(RE_DOMAIN_DOT, line[0]):
            raise InvalidDatabaseFileException(f"{line[0]}: Invalid domain name: {line[0]}")

        if not line[3].isnumeric() or not line[2].isnumeric():
            raise InvalidDatabaseFileException(f"{line[0]}: Time-to-Live/Value must be a number: {line[3], line[2]}")

        return DNSResource(line)

    def _parse_ns_mx(self, line: list[str]) -> DNSResource:
        """
        NS Value represents the name of an authoritative server for the domain indicated on the parameter.
        NS value type supports priority argument.

        Examples:
            @ NS ns1.example.com. TTL
            @ NS ns2.example.com. TTL
            @ NS ns3.example.com. TTL

        # Has to assume TTL value of sp (aka. ns1).

        As for MX, value indicates an e-mail server name for the domain given on the parameter.
        This type supports a priority value.

        Examples:
            @ MX mx1.example.com TTL 10
            @ MX mx2.example.com TTL 20

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        line = self._replace_macros(line)

        line_args_len: int = len(line)

        if line_args_len in range(4, 6):

            if line_args_len == 5 and not line[4].isnumeric() or (line_args_len == 5 and not self._check_ttl_value(line[4])):
                raise InvalidDatabaseFileException(f"{line[1]}: Priority must be an integer value bellow 255: {line[4]}")

            if not re.fullmatch(RE_DOMAIN_DOT, line[0]):
                raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line[0]}")

            if not re.fullmatch(RE_DOMAIN_DOT, line[2]):
                raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line[2]}")

            if not line[3].isnumeric():
                raise InvalidDatabaseFileException(f"{line[1]}: Time-to-Live/Value must be a valid integer: {line[2]}")

        else:
            raise InvalidDatabaseFileException(f"{line[1]}: Not enough values were provided: {line}")

        has_priority = True if len(line) == 5 else False
        return DNSResource(line, has_priority)

    def _parse_a(self, line: list[str]) -> DNSResource:

        line = self._replace_macros(line)

        line_args_len: int = len(line)
        if line_args_len in range(4, 6):

            if line_args_len == 5 and not line[4].isnumeric() or (line_args_len == 5 and not self._check_ttl_value(line[4])):
                raise InvalidDatabaseFileException(f"{line[1]}: Priority must be an integer value bellow 255: {line[4]}")

            if not re.fullmatch(RE_IVP4, line[2]):
                raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line[2]}")

            if not line[3].isnumeric():
                raise InvalidDatabaseFileException(f"{line[1]}: Time-to-Live/Value must be a valid integer: {line[2]}")

        else:
            raise InvalidDatabaseFileException(f"{line[1]}: Not enough values were provided: {line}")

        has_priority = True if len(line) == 5 else False
        return DNSResource(line, has_priority)

    def _parse_cname(self, line: list[str]) -> DNSResource:

        line = self._replace_macros(line)
        line_length: int = len(line)

        if line_length == 4:
            line.append('0')
            if not line[3].isnumeric():
                raise InvalidDatabaseFileException(f"{line[1]}: Time to live must be a numeric value: {line[3]}")

        if not re.fullmatch(RE_DOMAIN_DOT, line[2]) and re.fullmatch(RE_DOMAIN_DOT, line[0]):
            raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line}")

        return DNSResource(line)

    def _parse_ptr(self, line: list[str]) -> DNSResource:
        # Todo, implement this. #
        ...

    def parse(self) -> dict[DNSValueType, list[DNSResource]]:
        """
        Function that parses a given configuration file for an SP database file.

        :return: Database object containing the file information.

        TODO: Default TTL to 0 when parameter is non existent.
        """

        content_lines = self.clean_up(self.path)
        # self.dns_entries: list[DNSResource] = []

        result: dict[DNSValueType, list[DNSResource]] = {}

        line: list[str]
        for line in content_lines:

            operation: Callable[[list[str]], ...] = self.operations.get(line[1])
            dns_resource = operation(line)

            # if dns_resource is not None:
            #     self.dns_entries.append(dns_resource)

            if dns_resource is not None:

                if dns_resource.type not in result:
                    result[dns_resource.type] = []

                result[dns_resource.type].append(dns_resource)

        # return self.dns_entries
        # print(result)
        return result
