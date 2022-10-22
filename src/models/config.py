from ipaddress import IPv4Address
from pydantic import BaseModel
from pathlib import Path

from parser.mode import ValueType


class ConfigElement(BaseModel):
    mode: ValueType
    value: str  # IPv4Address | Path


class Config(BaseModel):
    """
    {
        'example.com' : [("SS", IPv4Address('193.123.5.189')),
                         ("SP", IPv4Address('193.123.5.189:8888')],
        'all' : [...],
        'root' : [...]
    }
    """

    config: dict[str, list[ConfigElement]] = {}
