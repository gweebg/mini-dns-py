from abc import ABC, abstractmethod
from enum import Enum


class Mode(Enum):
    CONFIG = 1
    DB = 2


class FileParser(ABC):

    def __init__(self, file_path_str: str, mode: Mode):
        self.path: str = file_path_str
        self.mode: Mode = mode

    @staticmethod
    def clean_up(path: str) -> list[list[str]]:

        with open(path, "r") as file:
            # Extract content lines, excluding all comments (including in-line) and blank lines.
            content_lines = [row.partition("#")[0].rstrip() for row in file]
            content_lines = [row for row in content_lines if row]
            content_lines = [row.split(" ") for row in content_lines]

        return content_lines

    @abstractmethod
    def parse(self):
        """ Abstract method that will do the parsing of the file and the creation of an equivalent object."""
