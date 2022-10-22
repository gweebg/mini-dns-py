from parser.parser_factory import FileParserFactory
from parser.mode import Mode


def main():
    file_parser = FileParserFactory("../test/config.conf", Mode.CONFIG)
    config = file_parser.get_parser().parse()
    print(config)

    # parser_conf: FileParser2 = FileParser2("../test/config.conf", Mode.CONFIG)
    # parser_db: FileParser = FileParser("../test/db.conf", Mode.DB)

    # try:
    #     error_parser: FileParser = FileParser("../test/not_a_file.txt", Mode.DB)
    # except FileNotFoundError as err:
    #     print(err)

    # parser_conf.parse()
    # parser_db.parse()


if __name__ == "__main__":
    SystemExit(main())
