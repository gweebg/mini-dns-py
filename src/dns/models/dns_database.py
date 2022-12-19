from pydantic import BaseModel

from dns.models.dns_resource import DNSValueType, DNSResource


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

    def authorities_values(self, domain_name: str, type_of_value: DNSValueType, prev_values: list[DNSResource]):
        """
        Given a domain_name, this function searches the database for matches with the given domain name and type of NS.
        If there was no result found on Database::response_values(), it looks for matches on its super-domain if it exists.

        :param prev_values: Previous values list used to not repeat values!
        :param domain_name: Domain name we are looking for.
        :return: List with every NS match entry.
        """

        authorities_values = []
        look_for_super = len(prev_values) <= 0

        nameservers = self.database.get(DNSValueType.NS)

        # entry.parameter : example.com
        # domain_name: Smaller.example.com.
        for entry in nameservers:
            if entry not in prev_values and entry not in authorities_values:

                if type_of_value in [DNSValueType.A, DNSValueType.CNAME]:
                    if entry.parameter in domain_name:
                        authorities_values.append(entry)

                if domain_name in entry.parameter:
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

        # ss1 CNAME ns2 TTL
        for value in self.database.get(DNSValueType.CNAME):
            for prev in previous_values:

                compare_with = prev.value

                if prev.type == DNSValueType.MX:
                    compare_with = compare_with + '.'

                if value.value == compare_with and value not in previous_values and value not in extra_values:
                    extra_values.append(value)

        return extra_values

    def get_total_entries(self):
        """
        Method that return the total number of entries in the database.
        :return: Number of entries in the database.
        """
        counter = 0
        for key in self.database:
            counter += len(self.database[key])

        return counter

    def entry_string_generator(self) -> list[DNSResource]:

        values = self.database.values()
        flat_map = []

        for value_list in values:
            for value in value_list:
                flat_map.append(value)

        return flat_map

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
