from pydantic import BaseModel, Field, conlist
from enum import Enum

from dns.dns_resource import DNSValueType
from exceptions.exceptions import InvalidDNSPacket


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

        raise InvalidDNSPacket(
            f"The number of header parameters must be equal to 6, but received {len(separated_values)}")

    def __str__(self) -> str:

        formatted_flags = ""
        for flag in self.flags:
            formatted_flags = formatted_flags + '+' + flag.name

        return f"{self.message_id}, {formatted_flags[1:]}, {self.response_code}, {self.number_values}, " \
               f"{self.number_authorities}, {self.number_extra};"


class DNSPacketQueryInfo(BaseModel):
    """
    example.com.,MX
    """

    name: str
    type_of_value: DNSValueType

    def as_binary(self):
        ...

    @classmethod
    def from_string(cls, query_info_string: str) -> 'DNSPacketQueryInfo':
        separated_values = query_info_string.split(',')

        if len(separated_values) == 2:
            return cls(name=separated_values[0], type_of_value=DNSValueType[separated_values[1]])

        raise InvalidDNSPacket(
            f"The number of query info values must be equal to 2, but received {len(separated_values)}.")

    def __str__(self) -> str:
        return f"{self.name},{self.type_of_value.name};"


class DNSPacketQueryData(BaseModel):
    """
    example.com. MX mx1.example.com 86400 10,
    example.com. MX mx2.example.com 86400 20;
    example.com. NS ns1.example.com. 86400,
    example.com. NS ns2.example.com. 86400,
    example.com. NS ns3.example.com. 86400;
    """

    response_values: list[str]
    authorities_values: list[str]
    extra_values: list[str]

    def as_binary(self):
        ...

    def get_values_as_dns_resources(self):
        ...

    @classmethod
    def from_string(cls, query_values_string: str, header: DNSPacketHeader) -> 'DNSPacketQueryData':

        # TODO: Needs more validation.

        response_values = []
        authorities_values = []
        extra_values = []

        values = query_values_string.split(";")
        values = values[:-1]

        if len(values) not in range(1, 4):
            raise InvalidDNSPacket(
                f"Expected a maximum of 4 value groups but got {len(values)}.")

        if header.number_values > 0 and len(values):
            response_values = [value for value in values[0].split(",")]

        if header.number_authorities > 0:
            authorities_values = [value for value in values[1].split(",")]

        if header.number_extra > 0:
            extra_values = [value for value in values[2].split(",")]

        return cls(response_values=response_values, authorities_values=authorities_values, extra_values=extra_values)

    def __str__(self) -> str:
        formatted_string = ''
        for value in self.response_values:
            formatted_string = formatted_string + value + ","

        formatted_string = formatted_string[:-1] + ";"

        for value in self.authorities_values:
            formatted_string = formatted_string + value + ","

        formatted_string = formatted_string[:-1] + ";"

        for value in self.extra_values:
            formatted_string = formatted_string + value + ","

        return formatted_string[:-1]


class DNSPacket(BaseModel):

    header: DNSPacketHeader
    query_info: DNSPacketQueryInfo
    query_data: DNSPacketQueryData

    @classmethod
    def from_string(cls, query_string: str) -> 'DNSPacket':

        sections = query_string.replace('\n', '').split(";", 2)

        if len(sections) != 3:
            raise InvalidDNSPacket(f"DNS Packet must have three sections but received {len(sections)}.")

        query_header = DNSPacketHeader.from_string(sections[0])
        query_info = DNSPacketQueryInfo.from_string(sections[1])
        query_data = DNSPacketQueryData.from_string(sections[2], query_header)

        return cls(header=query_header, query_info=query_info, query_data=query_data)


# q_data = \
#     "example.com. MX mx1.example.com 86400 10;example.com. MX mx1.example.com 86400 10,example.com. MX mx1.example.com 86400 10;example.com. MX mx1.example.com 86400 10,example.com. MX mx1.example.com 86400 10;"
#
# header = DNSPacketHeader.from_string("3874,Q+R,0,1,2,2")
# info = DNSPacketQueryInfo.from_string("example.com.,MX")
# data = DNSPacketQueryData.from_string(q_data, header)
#
# query = """3874,R+A,0,2,3,5;example.com.,MX;
# example.com. MX mx1.example.com 86400 10,
# example.com. MX mx2.example.com 86400 20;
# example.com. NS ns1.example.com. 86400,
# example.com. NS ns2.example.com. 86400,
# example.com. NS ns3.example.com. 86400;
# mx1.example.com. A 193.136.130.200 86400,
# mx2.example.com. A 193.136.130.201 86400,
# ns1.example.com. A 193.136.130.250 86400,
# ns2.example.com. A 193.137.100.250 86400,
# ns3.example.com. A 193.136.130.251 86400;"""
#
# packet = DNSPacket.from_string(query)
# print(packet.query_data.authorities_values)

