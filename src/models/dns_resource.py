from enum import Enum


class DNSValueType(Enum):
    """
    Enum containing every possible entry type for the DNS resource lines
    in the database.
    """

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
    """
    This class represents a DNS resource, a resource is an entry in the DNS database.
    Every resource has a parameter, value type, value, time-to-live, and optionally a priority value.

    In a structured manner:
        {parameter} {value type (DNSValueType)} {value} {time-to-live (integer)} {priority (integer)}
                                                                                     ^- Optional
    """

    def __init__(self, line: list[str], has_priority: bool = False):
        """
        Constructor for DNSResource.

        :param line: Line to be parsed into a DNSResource.
        :param has_priority: Boolean flag that indicates whether the line has priority.
        """

        self.parameter = line[0]
        self.type = DNSValueType[line[1]]
        self.value = line[2]
        self.ttl = line[3]
        self.priority = line[4] if has_priority else None

    def as_log_string(self) -> str:
        """
        :return: Returns a formatted string to be used on the logs.
        """

        result: str = f"{self.parameter} {self.type.name} {self.value} {self.ttl} "

        if self.priority is not None:
            result = result + str(self.priority)

        return result

    @classmethod
    def from_string(cls, resouce_string: str) -> 'DNSResource':
        """
        Creates a DNSResource from a string.

        :param resouce_string: String to be parsed into a DNSResource.
        :return: DNSResource created.
        """

        values: list[str] = resouce_string.split(' ')
        has_priority: bool = len(values) == 5

        return cls(values, has_priority)

    def __str__(self):
        """
        :return: String representation of a DNSResource.
        """
        return f"<{self.type}> : {self.parameter}, {self.value}, {self.ttl}, {self.priority}"

    def __repr__(self):
        """
        :return: String representation of a DNSResource.
        """
        return f"<{self.type}> : {self.parameter}, {self.value}, {self.ttl}, {self.priority}"
