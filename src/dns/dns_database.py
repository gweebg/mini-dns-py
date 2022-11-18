from pydantic import BaseModel

from dns.dns_packet import DNSPacket
from models.dns_resource import DNSValueType, DNSResource


class Database(BaseModel):

    database: dict[DNSValueType, list[DNSResource]]

    def response_values(self, domain_name: str, type_of_value: DNSValueType) -> [DNSResource]:

        response_values = []
        same_type_values: list[DNSResource] = self.database.get(type_of_value)

        for entry in same_type_values:
            if entry.type == type_of_value and entry.parameter == domain_name:
                response_values.append(entry)

        return response_values

    def authorities_values(self, domain_name: str, look_for_super=False):

        authorities_values = []

        if look_for_super:
            domain_name = domain_name.split(".", 1)[1]
            if domain_name == '':
                return authorities_values

        nameservers = self.database.get(DNSValueType["NS"])

        for entry in nameservers:
            if entry.parameter == domain_name:
                authorities_values.append(entry)

        return authorities_values

    def extra_values(self, previous_values: [DNSResource]):

        extra_values = []
        addresses = self.database.get(DNSValueType.A)

        for value in previous_values:
            for address in addresses:

                updated_value = value.value
                if not value.value.endswith("."):
                    updated_value = value.value + "."

                if updated_value == address.parameter:
                    extra_values.append(address)

        return extra_values

    def __str__(self) -> str:
        ...

    @staticmethod
    def values_as_string(values: [DNSResource]) -> [str]:
        return list(map(lambda resource: resource.as_log_string(), values))

    class Config:
        arbitrary_types_allowed = True

