from models.config_entry import ConfigEntry

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

    allowed_domains: list[str] = []

    primary_server: Optional[ConfigEntry]
    secondary_servers: list[ConfigEntry] = []

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
