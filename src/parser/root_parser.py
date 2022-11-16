from exceptions.exceptions import InvalidRootListEntry

from parser.abstract_parser import FileParser
from parser.abstract_parser import Mode
from parser.regex_compiles import RE_IVP4


class RootListParser(FileParser):

    def __init__(self, file_path_str: str, mode: Mode):
        super(RootListParser, self).__init__(file_path_str, mode)

    def parse(self) -> list[str]:

        content_lines = self.clean_up(self.path)

        result: list = []
        for line in content_lines:
            if not RE_IVP4.fullmatch(line[0]):
                raise InvalidRootListEntry(f"Value must be an Ipv4[:Port] address: {line[0]}")

            result.append(line[0])

        return result
