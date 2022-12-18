from abc import ABC, abstractmethod

from enum import Enum


class Mode(Enum):
    """
    Enum for the modes that we can parse a file.
    """

    CONFIG = 1  # Leads to ConfigFileParser()
    DB = 2  # Leads to DatabaseFileParser()
    RT = 3  # Leads to RootFileParser().


class FileParser(ABC):
    """
    Abstract class for a file parser that specifies that a FileParser
    inheritant must have defined the FileParser::parse() method.
    """

    def __init__(self, file_path_str: str, mode: Mode):
        """
        Constructor for FileParser.

        :param file_path_str: Path of the file to be parsed.
        :param mode: Mode in which to parse the file.
        """

        self.path: str = file_path_str
        self.mode: Mode = mode

    @staticmethod
    def clean_up(path: str) -> list[list[str]]:
        """
        Helper method that cleans the file.
        Removes empty lines, comments and in-line comments.
        In the end returns a list of the lines parsed on its elements, thus the second list[str].

        Example:

            "10.0.2.10 PTR example.com. TTL", would return ["10.0.2.12", "PTR", "example.com.", "TTL"]

        :param path: Path of the file to clean up.
        :return: Returns a list with the parsed lines.
        """

        with open(path, "r") as file:
            # Extract content lines, excluding all comments (including in-line) and blank lines.
            content_lines = [row.partition("#")[0].rstrip() for row in file]
            content_lines = [row for row in content_lines if row]
            content_lines = [row.split(" ") for row in content_lines]

        return content_lines

    @abstractmethod
    def parse(self):
        """ Abstract method that will do the parsing of the file and the creation of an equivalent object."""
