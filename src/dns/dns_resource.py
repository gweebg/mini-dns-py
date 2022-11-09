from enum import Enum


class DNSValueType(Enum):

    SOASP = 1
    SOAADMIN = 2
    SOASERIAL = 3
    SOAREFRESH = 4
    SOARETRY = 5
    SOAEXPIRE = 8
    NS = 9
    A = 10
    CNAME = 11
    MX = 12
    PTR = 13


class DNSResource:

    def __init__(self, line: list[str], has_priority: bool = False):
        # {parâmetro} {tipo do valor} {valor} {tempo de validade} {prioridade} #

        self.parameter = line[0]
        self.type = DNSValueType[line[1]]
        self.value = line[2]
        self.ttl = line[3]
        self.priority = line[4] if has_priority else None

    def as_log_string(self) -> str:
        ...

    @classmethod
    def __get_validators__(cls):
        yield cls.validate



    def __repr__(self):
        return f"[{self.type}] : {self.parameter}, {self.value}, {self.ttl}, {self.priority}"

    def __str__(self):
        return f"[{self.type}] : {self.parameter}, {self.value}, {self.ttl}, {self.priority}"
