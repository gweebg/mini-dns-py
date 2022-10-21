from parser.file_parser import FileParser
from parser.mode import Mode

import sys


def main():
    parser_conf: FileParser = FileParser("../test/config.conf", Mode.CONFIG)
    parser_db: FileParser = FileParser("../test/db.conf", Mode.DB)

    try:
        error_parser: FileParser = FileParser("../test/not_a_file.txt", Mode.DB)
    except FileNotFoundError as err:
        print(err)

    parser_conf.parse()
    parser_db.parse()


if __name__ == "__main__":
    sys.exit(main())
