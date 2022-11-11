from enum import Enum


class ConfigEntryType(Enum):
    SS = 1
    SP = 2
    DD = 3
    ST = 4
    LG = 5
    DB = 6


class ConfigEntry:

    def __init__(self, line: list[str]):

        self.parameter = line[0]
        self.type = ConfigEntryType[line[1]]
        self.value = line[2]

    def as_log_string(self) -> str:
        ...

    def __repr__(self):
        return f"[{self.type}] : {self.parameter}, {self.value}"

    def __str__(self):
        return f"[{self.type}] : {self.parameter}, {self.value}"
