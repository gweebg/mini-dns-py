from enum import Enum


class ConfigEntryType(Enum):
    """
    Enum with the entry value types for a DNS configuration file.
    """

    SS = 1  # Indicates the address of its secondary server.
    SP = 2  # Indicates the address of the servers primary server.
    DD = 3  # Indicates the allowed domains to answer (if it's a primary/secondary server) or the addresses of a domain
    # (in case it's a resolution server).
    ST = 4  # Indicate the file where the root addresses are located.
    LG = 5  # Indicate where the log files should be stored.
    DB = 6  # Indicate where the database file is stored.


class ConfigEntry:
    """
    Class that represents an entry of a DNS configuration file.
    A config entry will always have three elements, the parameter, the entry type and the value.

    In a more structured manner:
        {parameter} {entry type (ConfigEntryType)} {value}

    Example:

        example.com. SS 10.0.12.12

    """

    def __init__(self, line: list[str]):
        """
        Constructor for DNSEntry.
        :param line: Parsed line to be parsed.
        """

        self.parameter = line[0]
        self.type = ConfigEntryType[line[1]]
        self.value = line[2]

    def __repr__(self):
        """
        :return: String representation of a DNSEntry.
        """
        return f"[{self.type}] : {self.parameter}, {self.value}"

    def __str__(self):
        """
        :return: String representation of a DNSEntry.
        """
        return f"[{self.type}] : {self.parameter}, {self.value}"
