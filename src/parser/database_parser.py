from models.mode import Mode
from parser.abstract_parser import FileParser
from exceptions.exceptions import InvalidDatabaseFileException

import re
from typing import Callable


class DatabaseFileParser(FileParser):

    def __init__(self, file_path_str: str, mode: Mode):
        super(DatabaseFileParser, self).__init__(file_path_str, mode)

        self.re_domain_dot = re.compile(
            "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}.")
        self.re_ipv4 = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,4})?\b")
        self.re_hostname = re.compile(
            r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
        self.re_email = re.compile(
            r"^[a-z0-9]+[._]?[a-z0-9]+@\w+[.]\w{2,3}$")

        self.operations = {
            'DEFAULT': self._parse_default,
            'SOASP': self._parse_soasp,
            'SOAADMIN': self._parse_soaadmin,
            'SOASERIAL': self._parse_soa_srl_rfr_rtr_exp,
            'SOAREFRESH': self._parse_soa_srl_rfr_rtr_exp,
            'SOARETRY': self._parse_soa_srl_rfr_rtr_exp,
            'SOAEXPIRE': self._parse_soa_srl_rfr_rtr_exp,
            'NS': self._parse_ns,
            'MX': self._parse_mx,
            'A': self._parse_a,
            'CNAME': self._parse_cname,
            'PTR': self._parse_ptr
        }

        self.macros = {}

    def _parse_default(self, line: list[str]):
        """
        DEFAULT value type defines a name as a macro that must be replaced by it's literal associated value.
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

        if line[0] == '@' and not re.fullmatch(self.re_domain_dot, line[2]):
            raise InvalidDatabaseFileException(
                f"Restricted macro '@' must have a valid domain name as value: {line[2]}")

        self.macros[line[0]] = line[2]

    def _parse_soasp(self, line: list[str]):
        """
        Value indicates the full name of the domain primary server (or zone) given on the parameter.

        Parameter must be a valid macro or domain name.
        Time to live must be a valid macro of integer.

        Example: '@ SOASP ns1.example.com. TTL'

        This field does not accept priority values.

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        has_at_symbol = False

        if len(line) != 4:
            raise InvalidDatabaseFileException(f"SOASP: Not enough values were provided: {line}")

        for macro in self.macros:
            for idx, line_slice in enumerate(line):
                if macro in line_slice and idx != 2:

                    if macro == '@':
                        has_at_symbol = True

                    line[idx] = line[idx].replace(macro, self.macros[macro])

        if not re.fullmatch(self.re_domain_dot, line[0]) and not has_at_symbol:
            raise InvalidDatabaseFileException(f"SOASP: Invalid domain name: {line[0]}")

        if not re.fullmatch(self.re_domain_dot, line[2]):
            raise InvalidDatabaseFileException(f"SOASP: Invalid domain name: {line[2]}")

        if not line[3].isnumeric():
            raise InvalidDatabaseFileException(f"SOASP: Time-to-Live must be a number: {line[3]}")

    def _parse_soaadmin(self, line: list[str]):
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

        for macro in self.macros:
            for idx, line_slice in enumerate(line):
                if macro in line_slice and idx != 2:
                    line[idx] = line[idx].replace(macro, self.macros[macro])

        if not re.fullmatch(self.re_domain_dot, line[0]):
            raise InvalidDatabaseFileException(f"SOAADMIN: Invalid domain name: {line[0]}")

        if re.fullmatch(self.re_email, line[2]):
            at_index = line[2].rfind('@')

            new_email_value = line[2][:at_index].replace('.', '\\.')
            new_email_value = f"{new_email_value}{line[2][at_index:].replace('@', '.')}"

        else:
            raise InvalidDatabaseFileException(f"SOAADMIN: Invalid e-mail address.\n\t{line[2]}")

        if not line[3].isnumeric():
            raise InvalidDatabaseFileException(f"SOAADMIN: Time-to-Live must be a number.\n\t{line[3]}")

        # print(f'{line[0], line[1], new_email_value, line[3]}')
        # return new_email_value

    def _parse_soa_srl_rfr_rtr_exp(self, line: list[str]):
        """
        SOASERIAL: Value indicates serial number of database of the primary server (SP) given on parameter.
                   Everytime time that the database is changed this value has to increment.

        SOAREFRESH: Value indicates a time interval in seconds for an secondary server (SS) to ask a primary server
                    (SP) what is the SOASERIAL value.

        SOARETRY: Value defines a time interval for the SS to re-ask SP what the SOASERIAL value is (after a timeout).

        SOAEXPIRE: Value defines a time interval to let a SS to stop giving a fuck about it's database replica.

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

        for macro in self.macros:
            for idx, line_slice in enumerate(line):
                if macro in line_slice and idx != 2:
                    line[idx] = line[idx].replace(macro, self.macros[macro])

        if not re.fullmatch(self.re_domain_dot, line[0]):
            raise InvalidDatabaseFileException(f"{line[0]}: Invalid domain name: {line[0]}")

        if not line[3].isnumeric() or not line[2].isnumeric():
            raise InvalidDatabaseFileException(f"{line[0]}: Time-to-Live/Value must be a number: {line[3], line[2]}")

    def _parse_ns(self, line: list[str]):
        """
        Value represents the name of an authoritative server for the domain indicated on the parameter.
        NS value type supports priority argument.

        Examples:
            @ NS ns1.example.com. TTL
            @ NS ns2.example.com. TTL
            @ NS ns3.example.com. TTL

        # Has to assume TTL value of sp (aka. ns1).

        :param line: Inputted line to be checked and parsed.
        :return:
        """

        for macro in self.macros:
            for idx, line_slice in enumerate(line):
                if macro in line_slice:
                    line[idx] = line[idx].replace(macro, self.macros[macro])

        line_args_len: int = len(line)

        if line_args_len in range(4, 6):

            if line_args_len == 5 and not line[4].isnumeric():
                raise InvalidDatabaseFileException(f"{line[1]}: Priority must be an integer value: {line[4]}")
            elif line_args_len == 5:
                priority: int = int(line[4])

            if not re.fullmatch(self.re_domain_dot, line[0]):
                raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line[0]}")

            if not re.fullmatch(self.re_domain_dot, line[2]):
                raise InvalidDatabaseFileException(f"{line[1]}: Invalid domain name: {line[2]}")

            if not line[3].isnumeric():
                raise InvalidDatabaseFileException(f"{line[1]}: Time-to-Live/Value must be a valid integer: {line[2]}")

        else:
            raise InvalidDatabaseFileException(f"{line[1]}: Not enough values were provided: {line}")

    def _parse_mx(self, line: list[str]):
        print("MX")

    def _parse_a(self, line: list[str]):
        print("A")

    def _parse_cname(self, line: list[str]):
        print("CNAME")

    def _parse_ptr(self, line: list[str]):
        print("PTR")

    def parse(self):
        """
        Function that parses a given configuration file for an SP database file.

        :return: Database object containing the file information.
        """

        content_lines = self.clean_up(self.path)

        line: list[str]
        for line in content_lines:
            if line[1]:
                operation: Callable[[list[str]], None] = self.operations.get(line[1], lambda: "Not Implemented")
                operation(line)

        print(f'Macros: {self.macros}')
