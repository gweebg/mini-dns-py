from dns.models.dns_packet import DNSPacket
from dns.models.config_entry import ConfigEntry

from typing import Optional
from pydantic import BaseModel


class ServerConfiguration(BaseModel):
    """
    Model class that represents a server configuration.

    :param root_servers_path: Path of the file containing every existing root server.
    :param database_path: Path to the database file for the server.
    :param logs_path: List of entries of type LG that contain every log file that should be created.
    :param allowed_domains: List of every domain whitelisted for the server to respond.
    :param primary_server: ConfigEntry object that contains the servers primary server.
    :param secondary_servers: List of ConfigEntry objects that contain the servers secondary servers.
    """

    root_servers_path: Optional[str]
    database_path: Optional[str]
    logs_path: list[ConfigEntry] = []

    allowed_domains: list[ConfigEntry] = []

    primary_server: Optional[ConfigEntry]
    secondary_servers: list[ConfigEntry] = []

    def get_secondary_servers_domains(self) -> list[str]:
        return [entry.parameter for entry in self.secondary_servers]

    def match_dd(self, data: DNSPacket) -> Optional[ConfigEntry]:

        """
        Given a DNSPacket object, this method checks if there is an existing DD entry that
        partially matches the NAME in the query info section.

        :param data: Provided DNSPacket object.
        :return: The IP address specified on the DD entry if there was a match, None otherwise.
        """

        result: Optional[ConfigEntry] = None
        smallest_index: int = -1

        # Iterating over the DD configuration entries.
        for entry in self.allowed_domains:

            # Matching the longest suffix.
            if entry.parameter in data.query_info.name:

                substring_index: int = data.query_info.name.index(entry.parameter)

                # The smaller the index the closer we are to the domain.
                if substring_index > smallest_index:
                    result = entry
                    smallest_index = substring_index

        return result

    def __str__(self):
        """
        String representation of a ServerConfiguration object.
        :return: Result string.
        """
        return f"{self.primary_server}\n{self.database_path}\n{self.root_servers_path}\n{self.logs_path}" \
               f"\n{self.secondary_servers}\n{self.allowed_domains}\n"

    class Config:
        """
        Pydantic way of saying that we don't need validators for custom types.
        """
        arbitrary_types_allowed = True
