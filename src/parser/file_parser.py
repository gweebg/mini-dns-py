from parser.mode import Mode

import os
import errno


class FileParser:
    def __init__(self, file_path_str: str, mode: Mode):
        if not os.path.isfile(file_path_str):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file_path_str)

        self.path: str = file_path_str
        self.mode: Mode = mode
        self.call: dict = {
            Mode.CONFIG: self.parse_config,
            Mode.DB: self.parse_database
        }

    @classmethod
    def parse_config(cls, path):
        print("Parse Config!" + path)

    @classmethod
    def parse_database(cls, path):
        print("Parse Database!" + path)

    def parse(self):
        parse_function = self.call[self.mode]
        parse_function(self.path)
