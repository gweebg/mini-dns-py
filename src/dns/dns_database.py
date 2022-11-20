from pydantic import BaseModel

from dns.dns_packet import DNSPacket
from models.dns_resource import DNSValueType, DNSResource


class Database(BaseModel):
    """
    Model class that represents a server database.
    Consists of a dictionary with keys of type DNSValueType and values of type list[DNSResource].
    """

    database: dict[DNSValueType, list[DNSResource]]

    def response_values(self, domain_name: str, type_of_value: DNSValueType) -> [DNSResource]:
        """
        Given domain_name and type_of_value, this function searches the database for full matches of the parameters.

        :param domain_name: Domain name we are looking for.
        :param type_of_value: Type of value we are looking for.
        :return: List with every full match entry.
        """

        response_values = []
        same_type_values: list[DNSResource] = self.database.get(type_of_value)

        for entry in same_type_values:
            if entry.type == type_of_value and entry.parameter == domain_name:
                response_values.append(entry)

        return response_values

    def authorities_values(self, domain_name: str, look_for_super=False):
        """
        Given a domain_name, this function searches the database for matches with the given domain name and type of NS.
        If there was no result found on Database::response_values(), it looks for matches on its super-domain if it exists.

        :param domain_name: Domain name we are looking for.
        :param look_for_super: Flag that indicates wether we are looking for super-domain.
        :return: List with every NS match entry.
        """

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
        """
        Given the concatenated results of the Database::response_values() and Database::authorities_values(), this method
        looks in the database for entries of type A with the name of the values on the previous results.

        :param previous_values: List containing the result values of Database::response_values() and Database::authorities_values().
        :return: List of entries of type A and match on 'previous_values'.
        """

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
        """
        String representation of a Database object.
        :return: String result
        """
        ...

    @staticmethod
    def values_as_string(values: list[DNSResource]) -> [str]:
        """
        This method converts a list of DNSResource into a list of strings (DNSResource string representation).
        :param values: Given values of type list[DNSResource].
        :return: New list of strings.
        """
        return list(map(lambda resource: resource.as_log_string(), values))

    class Config:
        """
        Pydantic way of saying that we don't need validators for custom types.
        """
        arbitrary_types_allowed = True

