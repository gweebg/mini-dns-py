from dns.dns_database import Database
from parser.parser_factory import FileParserFactory
from parser.abstract_parser import Mode


def main():
    # file_parser = FileParserFactory("../tests/config.conf", Mode.CONFIG)
    # config = file_parser.get_parser().parse()

    database_parser = FileParserFactory("/core/database-lili-lycoris.db", Mode.DB)
    database = database_parser.get_parser().parse()

    db = Database(database=database)
    for entry in db.database.values():
        print(entry)

    # print(FileParserFactory("../tests/root.data", Mode.RT).get_parser().parse())


if __name__ == "__main__":
    SystemExit(main())
