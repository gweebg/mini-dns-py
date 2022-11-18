from pydantic import BaseModel, Field, conlist
from enum import Enum

from models.dns_resource import DNSValueType
from exceptions.exceptions import InvalidDNSPacket
from dns.utils import __get_latest_id__

"""
This module is responsible for the DNS Packet Data Unit implementation.
This includes packet decoding and packet encoding.
"""


class DNSPacketHeaderFlag(Enum):
    """
    Enumeration that represents a DNS Packet Header Flag.
    Q: Query
    R: Response
    A: Response is authoritative
    """

    Q = 1
    R = 2
    A = 3


class DNSPacketHeader(BaseModel):
    """
    BaseModel derived class that represents a DNS Packet Header.

    message_id: DNS Message identification used to link responses to the original query.
    flags: Query flags.
    response_code: Shows the error code in a query response.
        0: Success
        1,2,3: Error
    number_values: Number of actual query values.
    number_authorities: Number of entries values within the AUTHORITY VALUES data field.
    number_extra: Number of extra values on the response.

    Example:
        DNSPacketHeader.from_string("3874,Q+R,0,0,0,0")
        DNSPacketHeader(...)
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
        """
        Given a string with flags formatted like 'f+f+f', where is a flag string, convert the string into a list
        of DNSPacketHeaderFlag.

        :param flag_string: String to be parsed.
        :return: [DNSPacketHeaderFlag] - List containing query flags.
        """
        return [DNSPacketHeaderFlag[flag] for flag in flag_string.split('+')]

    @classmethod
    def from_string(cls, header_string: str) -> 'DNSPacketHeader':
        """
        Convert a string into a DNSPacketHeader object.

        String must be formatted like: "message_id,flags,response_code,number_values,number_authorities,number_values".

        :param header_string: String to be converted.
        :return: DNSPacketHeader - Result header object.
        """

        separated_values = header_string.split(',')

        if len(separated_values) == 6:

            # Unpacking the split up string.
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

    def flags_as_string(self) -> str:

        formatted_flags = ""
        for flag in self.flags:
            formatted_flags = formatted_flags + '+' + flag.name

        return formatted_flags[1:]

    def prettify(self) -> str:

        formatted_flags = self.flags_as_string()

        result: str = f"# Header\nMESSAGE-ID = {self.message_id}, FLAGS = {formatted_flags}, RESPONSE-CODE = {self.response_code},\n" \
                      f"N-VALUES = {self.number_values}, N-AUTHORITIES = {self.number_authorities}, N-EXTRA-VALUES = {self.number_extra}"

        return result

    def __str__(self) -> str:
        """
        String representation of a DNS Header.
        :return: Result string.
        """

        formatted_flags = self.flags_as_string()

        return f"{self.message_id},{formatted_flags},{self.response_code},{self.number_values}," \
               f"{self.number_authorities},{self.number_extra};"


class DNSPacketQueryInfo(BaseModel):
    """
        BaseModel derived class that represents a DNS Packet Query Info section.

        name: Domain name.
        type_of_value: Query type of value, it is a DNSValueType.

        Example:
            DNSPacketQueryInfo.from_string("example.com.,MX")
            DNSPacketQueryInfo(name=..., type_of_value=...)
    """

    name: str
    type_of_value: DNSValueType

    def as_binary(self):
        ...

    @classmethod
    def from_string(cls, query_info_string: str) -> 'DNSPacketQueryInfo':
        """
        Convert a string into a DNSPacketQueryInfo object.

        String must be formatted like: "name,type_of_value".

        :param query_info_string: String to be parsed.
        :return: DNSPacketQueryInfo - Result query info object.
        """

        separated_values = query_info_string.split(',')

        if len(separated_values) == 2:
            return cls(name=separated_values[0], type_of_value=DNSValueType[separated_values[1]])

        raise InvalidDNSPacket(
            f"The number of query info values must be equal to 2, but received {len(separated_values)}.")

    def prettify(self) -> str:

        result: str = f"# Data : Query Info\nQUERY-INFO.NAME = {self.name}, QUERY-INFO.TYPE = {self.type_of_value.name}"
        return result

    def __str__(self) -> str:
        """
        String representation of a DNS Query Info section.
        :return: Result string.
        """

        return f"{self.name},{self.type_of_value.name};"


class DNSPacketQueryData(BaseModel):

    """
    Class that represents a DNS Packet Query Data field.

    response_values: List of values returned on a query response.
    authorities_values: List of authorities values returned on a query response.
    extra_values: List of extra values returned on a query response.

    Values must be formatted like a DNS database record string.

    Example:
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

        """
        Convert a string into a DNSPacketQueryData object.

        String must be formatted like: "list_of_values;list_of_values;list_of_values".

        :param query_values_string: Input string to be parsed.
        :param header: DNSPacketHeader object used to confirm that the number of values match with the
                       actual number of values provided.
        :return: DNSPacketQueryData - Generated result object.

        TODO: Needs more validation.
        """

        response_values = []
        authorities_values = []
        extra_values = []

        values = query_values_string.split(";")
        values = values[:-1]

        if len(values) not in range(0, 4):
            raise InvalidDNSPacket(
                f"Expected a maximum of 4 value groups but got {len(values)}.")

        if header.number_values > 0 and len(values):
            response_values = [value for value in values[0].split(",")]

        if header.number_authorities > 0:
            authorities_values = [value for value in values[1].split(",")]

        if header.number_extra > 0:
            extra_values = [value for value in values[2].split(",")]

        return cls(response_values=response_values, authorities_values=authorities_values, extra_values=extra_values)

    @classmethod
    def empty(cls) -> 'DNSPacketQueryData':
        return cls(response_values=[], authorities_values=[], extra_values=[])

    def prettify(self) -> str:

        result = "# Data: List of Response, Authorities and Extra Values\n"
        values_loc = ['response_values', 'authorities_values', 'extra_values']

        for values in values_loc:

            list_of_values = getattr(self, values)

            if len(list_of_values) > 0:
                for value in list_of_values:
                    result = result + f"{values.replace('_', '-').upper()} = {value},\n"

                result = result[:-2] + ";\n"

        return result

    def __str__(self) -> str:
        """
        String representation of a DNS Query Data field.
        :return: Result string.
        """

        formatted_string = ''
        values_loc = ['response_values', 'authorities_values', 'extra_values']

        for values in values_loc:

            list_of_values = getattr(self, values)

            if len(list_of_values) > 0:
                for value in list_of_values:
                    formatted_string = formatted_string + value + ",\n"

                formatted_string = formatted_string[:-2] + ";\n"

        return formatted_string


class DNSPacket(BaseModel):

    """
    Class that represents a DNS Packet.
    As for now this class only allows the user to send queries based on strings. In the future it will be able to
    convert a query into binary.

    header: DNS Packet Header of type DNSPacketHeader.
    query_info: DNS Packet query information of type DNSPacketQueryInfo.
    query_data: DNS Packet query data of type DNSPacketQueryData.

    Example:
        3874,R+A,0,2,3,5;example.com.,MX;
        example.com. MX mx1.example.com 86400 10,
        example.com. MX mx2.example.com 86400 20;
        example.com. NS ns1.example.com. 86400,
        example.com. NS ns2.example.com. 86400,
        example.com. NS ns3.example.com. 86400;
        mx1.example.com. A 193.136.130.200 86400,
        mx2.example.com. A 193.136.130.201 86400,
        ns1.example.com. A 193.136.130.250 86400,
        ns2.example.com. A 193.137.100.250 86400,
        ns3.example.com. A 193.136.130.251 86400;
    """

    header: DNSPacketHeader
    query_info: DNSPacketQueryInfo
    query_data: DNSPacketQueryData

    def as_byte_string(self) -> bytes:
        return str(self).encode("utf-8")

    @classmethod
    def from_string(cls, query_string: str) -> 'DNSPacket':
        """
        Convert a string into a DNSPacket object.

        String must be formatted like: "header;query_info;query_data".

        :param query_string: Inputted string to be parsed.
        :return: Result DNSPacket object.
        """

        sections = query_string.replace('\n', '').split(";", 2)

        query_header = DNSPacketHeader.from_string(sections[0])
        query_info = DNSPacketQueryInfo.from_string(sections[1])
        query_data = DNSPacketQueryData.empty()

        if len(sections) == 3 and "Q" not in sections[0]:
            query_data = DNSPacketQueryData.from_string(sections[2], query_header)

        return cls(header=query_header, query_info=query_info, query_data=query_data)

    @classmethod
    def generate_bad_format_response(cls) -> 'DNSPacket':

        current_message_id: str = __get_latest_id__()

        query_header = DNSPacketHeader(
            message_id=current_message_id,
            flags=[DNSPacketHeaderFlag.A],
            response_code=3,
            number_values=0,
            number_authorities=0,
            number_extra=0
        )

        query_info = DNSPacketQueryInfo(
            name='bad_format',
            type_of_value=DNSValueType.NS
        )

        query_data = DNSPacketQueryData(
            response_values=[],
            authorities_values=[],
            extra_values=[]
        )

        return cls(header=query_header, query_info=query_info, query_data=query_data)

    def prettify(self) -> str:
        return f"{self.header.prettify()}\n{self.query_info.prettify()}\n{self.query_data.prettify()}"

    def __str__(self):
        """
        String representation of the DNSPacket class.
        :return: Result string.
        """
        return f"{self.header}{self.query_info}\n{self.query_data}"


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
# #
# packet = DNSPacket.from_string(query)
# #
# # error = DNSPacket.generate_bad_format_response()
# #
# # xd = DNSPacket.from_string("80,A,3,0,0,0;bad_format,NS;")
# # print(xd.prettify())
#
# a = DNSPacketQueryData(response_values=[], authorities_values=[], extra_values=[])
#
# not_found = DNSPacket(
#     header=packet.header,
#     query_info=packet.query_info,
#     query_data=DNSPacketQueryData.empty()
# )




