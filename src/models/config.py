from pydantic import BaseModel
from enum import Enum


class ConfigValueType(Enum):
    DB = 1
    SP = 2
    SS = 3
    DD = 4
    ST = 5
    LG = 6


class Config(BaseModel):
    parameter: str
    value_type: str
    value: str
