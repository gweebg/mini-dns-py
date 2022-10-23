from enum import Enum


class ValueType(Enum):
    SS = 1
    SP = 2
    DD = 3
    ST = 4
    LG = 5
    DB = 6


class Mode(Enum):
    CONFIG = 1  # SP, SR, SS
    DB = 2
