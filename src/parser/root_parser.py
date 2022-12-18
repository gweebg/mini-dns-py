from exceptions.exceptions import InvalidRootListEntry

from parser.abstract_parser import FileParser
from parser.regex_compiles import RE_IVP4
from parser.abstract_parser import Mode


class RootListParser(FileParser):
    """
    This is the root file parser, given the file path to the root list file, it
    stores in a list each address of the possible root servers.
    """

    def __init__(self, file_path_str: str, mode: Mode):
        """
        Constructor for RootListParser.

        :param file_path_str: The file to be parsed.
        :param mode: Mode in which to parse the file, has to always be Mode.RT.
        """

        super(RootListParser, self).__init__(file_path_str, mode)

    def parse(self) -> list[str]:
        """
        Since there's an address per line, we can simply store each line in a string, but,
        always checking if the line is an actual address.

        :return: The list with the addresses of the root servers.
        """

        content_lines = self.clean_up(self.path)

        # Not used because of the exception.
        # return [line[0] for line in content_lines if RE_IVP4.fullmatch(line[0])]

        result: list = []

        for line in content_lines:

            if not RE_IVP4.fullmatch(line[0]):
                raise InvalidRootListEntry(f"Value must be an Ipv4[:Port] address: {line[0]}")

            result.append(line[0])

        return result

