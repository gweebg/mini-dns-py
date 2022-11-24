from pydantic import BaseModel, constr, Field
from typing import Optional
from enum import Enum

from exceptions.exceptions import InvalidZoneTransferPacket
from models.dns_resource import DNSResource


class ZoneTransferMode(Enum):
    """
    Enum representing a zone transfer packet mode.

    DOM (Domain): Indicates the domain of the database.
    ENT (Entries): Indicates the number of entries on the database.
    ACK (Acknowledge): Acknowledges the number of entries.
    LIN (Line): Indicates a line of the database is being sent.
    """

    DOM = 1
    ENT = 2
    ACK = 3
    LIN = 4


class ZoneTransferPacket(BaseModel):
    """
    Class that represents a zone transfer packet.
    This kind of packet is divided into a header section and a values section.
    The header section has the 'mode' field, which indicates what the packet is supposed to do, and a 'domain' field
    that indicates which domain's database we want a replica.
    As for the values section, it has a 'num_values' field, which represents the number of entries that we are going to
    send, and an optional 'value' field (only used when 'mode' is 'LIN') that carries the database entry in a string
    format.
    """

    # Header Section
    mode: ZoneTransferMode
    domain: constr(regex="^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}")

    # Values Section
    num_value: int = Field(ge=0)
    value: Optional[DNSResource | int]

    @classmethod
    def from_string(cls, packet_string: str) -> 'ZoneTransferPacket':
        """
        Given a string, this function tries to parse it into a ZoneTransferPacket raising InvalidZoneTransferPacket
        if the passed string is invalid or bad formatted.

        :param packet_string: Inputted string to be parsed.
        :return: ZoneTransferPacket object originated from the string.
        """

        values: list[str] = packet_string.split(';')
        if len(values) < 3:
            raise InvalidZoneTransferPacket(
                f"Invalid zone transfer packet, was expecting 3 or 4 values but got {len(values)}. ")

        packet_mode = ZoneTransferMode[values[0]]
        domain: str = values[1]
        num_values = values[2]

        if packet_mode.name in ['DOM', 'ACK']:
            return cls(mode=packet_mode, domain=domain, num_value=num_values)

        if packet_mode == ZoneTransferMode.LIN and len(values) == 4:
            return cls(mode=packet_mode, domain=domain, num_value=num_values, value=DNSResource.from_string(values[3]))

        if packet_mode == ZoneTransferMode.ENT and len(values) == 4:
            return cls(mode=packet_mode, domain=domain, num_value=num_values, value=int(values[3]))

        raise InvalidZoneTransferPacket(f"Invalid zone transfer packet: {packet_string}")

    def as_byte_string(self) -> bytes:
        return str(self).encode("ascii")

    def __str__(self):
        """
        Returns the string representation for a TransferZonePacket object.
        :return: Result string.
        """

        base_string: str = f"{self.mode.name};{self.domain};{self.num_value}"

        if self.value is not None:

            if self.mode == ZoneTransferMode.ENT:
                base_string = base_string + f";{self.value}"

            if self.mode == ZoneTransferMode.LIN:
                base_string = base_string + f";{self.value.as_log_string()}"

        return base_string

    class Config:
        """
        Pydantic way of saying that we don't need validators for custom types.
        """
        arbitrary_types_allowed = True