from parser.parser_factory import FileParserFactory
from models.mode import Mode


def main():
    # file_parser = FileParserFactory("../tests/config.conf", Mode.CONFIG)
    # config = file_parser.get_parser().parse()

    database_parser = FileParserFactory("../tests/database.conf", Mode.DB)
    database = database_parser.get_parser().parse()


if __name__ == "__main__":
    SystemExit(main())
