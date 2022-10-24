from typing import List

from models.mode import Mode
from parser.abstract_parser import FileParser
from exceptions.exceptions import InvalidDatabaseFileException

import re


class DatabaseFileParser(FileParser):

    def __init__(self, file_path_str: str, mode: Mode):
        super(DatabaseFileParser, self).__init__(file_path_str, mode)

        self.re_domain_dot = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}[.]$')
        self.re_ipv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,4})?\b")

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
        print("MACRO")
        # if len(line) != 3:
        #     raise InvalidDatabaseFileException(f"Macro setting must have an assigned value:\n\t{line}")
        #
        # if not (line[0] == '@' and re.fullmatch(self.re_domain_dot, line[2])):
        #     raise InvalidDatabaseFileException(f"Restricted macro '@' must have a valid domain name as value:\n\t{line[2]}")
        #
        # self.macros[line[0]] = line[2]

    def _parse_soasp(self, line: list[str]):
        print("SOASP")

        # if len(line) != 3:
        #     raise InvalidDatabaseFileException(f"SOASP: Not enough arguments.\n\t{line}")
        #
        # # Replace macros for their actual values.
        # for part in line:
        #     if part in self.macros:
        #         part = self.macros[part]
        #
        # if not (re.fullmatch(self.re_domain_dot, line[2]) and line[3].isnumeric()):
        #     raise InvalidDatabaseFileException(f"SOASP: Invalid domain name or TTL value.\n\t{line}")
        #
        # return line[0], line[2], line[3]

    def _parse_soaadmin(self, line: list[str]):
        print("SOADMIN")

    def _parse_soa_srl_rfr_rtr_exp(self, line: list[str]):
        print("SRL,RFR,RTR,EXP")

    def _parse_ns(self, line: list[str]):
        print("NS")

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
        macros_values = {}

        line: list[str]
        for line in content_lines:
            if line[1]:
                operation = self.operations.get(line[1], lambda: "Not Implemented")
                # noinspection PyArgumentList
                operation(line)

            # try:
            #
            #     if line[1] == 'DEFAULT':
            #         if line[0] == '@' and :
            #
            #
            #
            # except Exception as err:
            #     print(err)
