from models.config_entry import ConfigEntry

from typing import Optional
from pydantic import BaseModel


class ServerConfiguration(BaseModel):

    root_servers_path: Optional[str]
    database_path: Optional[str]
    logs_path: list[ConfigEntry] = []

    allowed_domains: list[str] = []

    primary_server: Optional[ConfigEntry]
    secondary_servers: list[ConfigEntry] = []

    def __str__(self):
        return f"{self.primary_server}\n{self.database_path}\n{self.root_servers_path}\n{self.logs_path}" \
               f"\n{self.secondary_servers}\n{self.allowed_domains}\n"

    class Config:
        arbitrary_types_allowed = True
