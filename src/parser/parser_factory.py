from parser.database_parser import DatabaseFileParser
from parser.abstract_parser import FileParser, Mode
from parser.config_parser import ConfigFileParser
from parser.root_parser import RootListParser

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
            Mode.DB: DatabaseFileParser,
            Mode.RT: RootListParser
        }

    @abstractmethod
    def get_parser(self) -> FileParser:
        """
        Provides the correct parser for the given operation mode (mode.Mode).
        :return: Correct parser object.
        """
        return self.call.get(self.mode)(self.path, self.mode)


# def main():
#     # file_parser = FileParserFactory("../tests/config.conf", Mode.CONFIG)
#     # config = file_parser.get_parser().parse()
#
#     database_parser = FileParserFactory("/core/database-lili-lycoris.db", Mode.DB)
#     database = database_parser.get_parser().parse()
#
#     db = Database(database=database)
#     for entry in db.database.values():
#         print(entry)
#
#     # print(FileParserFactory("../tests/root.data", Mode.RT).get_parser().parse())
#
#
# if __name__ == "__main__":
#     SystemExit(main())
