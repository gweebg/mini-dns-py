import os
from argparse import ArgumentTypeError

from parser.regex_compiles import RE_IVP4


def __ipv4_type_validator__(arg_value, pat=RE_IVP4):

    if not pat.match(arg_value):
        raise ArgumentTypeError("Expected value type of IPv4 Address.")

    return arg_value


def __load_latest_id__() -> int:

    if not os.path.exists("../msgid.dat"):

        with open("../msgid.dat", "w") as file:
            file.write('1')

        return 0

    with open("../msgid.dat", "r") as file:
        current_message_id: int = int(file.read())

    with open("../msgid.dat", "w") as file:
        incremented_id = current_message_id + 1

        if current_message_id == 65335:
            incremented_id = 0

        file.write(str(incremented_id))

    return current_message_id
