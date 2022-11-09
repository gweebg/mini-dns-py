from pydantic import BaseModel, Field, ValidationError, conlist
from enum import Enum

from exceptions.exceptions import InvalidDNSHeaderFormat


class DNSPacketHeaderFlag(Enum):
    Q = 1
    R = 2
    A = 3


class DNSPacketHeader(BaseModel):

    """
    3874,Q+R,0,0,0,0
    """

    message_id: int = Field(gt=0, lt=65536)
    flags: conlist(DNSPacketHeaderFlag, min_items=1, max_items=3)
    response_code: int = Field(ge=0, le=3)
    number_values: int = Field(ge=0, le=255)
    number_authorities: int = Field(ge=0, le=255)
    number_extra: int = Field(ge=0, le=255)

    def as_binary(self):
        ...

    @staticmethod
    def __unpack_flags__(flag_string: str) -> [DNSPacketHeaderFlag]:
        return [DNSPacketHeaderFlag[flag] for flag in flag_string.split('+')]

    @classmethod
    def from_string(cls, header_string: str) -> 'DNSPacketHeader':

        separated_values = header_string.split(',')

        if len(separated_values) == 6:

            message_id = int(separated_values[0])
            flags = cls.__unpack_flags__(separated_values[1])
            response_code = int(separated_values[2])
            number_values = int(separated_values[3])
            number_authorities = int(separated_values[4])
            number_extra = int(separated_values[5])

            return cls(message_id=message_id,
                       flags=flags,
                       response_code=response_code,
                       number_values=number_values,
                       number_authorities=number_authorities,
                       number_extra=number_extra)

        else:
            raise InvalidDNSHeaderFormat(f"The number of header parameters must be equal to 6, but received {len(separated_values)}")

    def __str__(self) -> str:

        formatted_flags = ""
        for flag in self.flags:
            formatted_flags = formatted_flags + '+' + flag.name

        return f"{self.message_id}, {formatted_flags[1:]}, {self.response_code}, {self.number_values}, " \
               f"{self.number_authorities}, {self.number_extra}"


class DNSPacket(BaseModel):

    header: DNSPacketHeader
    query_info: ...
    query_data: ...

    def set_data(self) -> 'DNSPacket':
        ...

    @classmethod
    def from_string(cls, query_string: str) -> 'DNSPacket':
        ...


