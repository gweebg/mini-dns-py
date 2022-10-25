from parser.parser_factory import FileParserFactory
from models.mode import Mode


def main():
    # file_parser = FileParserFactory("../tests/config.conf", Mode.CONFIG)
    # config = file_parser.get_parser().parse()
    # print(config)

    database_parser = FileParserFactory("../tests/db.conf", Mode.DB)
    database = database_parser.get_parser().parse()


if __name__ == "__main__":
    SystemExit(main())
