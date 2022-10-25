from src.parser.parser_factory import FileParserFactory
from src.models.mode import Mode
from pytest import fixture

@fixture
def file_parser():
    parser = FileParserFactory('./re_domain_tests.txt')

def test_domain_names():
    parser = FileParserFactory('./re_domain_tests.txt', Mode.CONFIG).get_parser()
    with open('./re_domain_tests.txt', 'r') as test_file:
        pass
