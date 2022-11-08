from parser.config_parser import ConfigFileParser
from parser.database_parser import DatabaseFileParser
from parser.abstract_parser import FileParser
from models.mode import Mode

from abc import abstractmethod
import errno
import os


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
        return self.call.get(self.mode)(self.path, self.mode)


