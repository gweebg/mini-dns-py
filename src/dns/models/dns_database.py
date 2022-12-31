from typing import Optional

from pydantic import BaseModel

from dns.models.dns_resource import DNSValueType, DNSResource


class Database(BaseModel):
    """
    Model class that represents a server database.
    Consists of a dictionary with keys of type DNSValueType and values of type list[DNSResource].
    """

    database: dict[DNSValueType, list[DNSResource]]

    @staticmethod
    def get_address_from_ptr(domain_name: str) -> str:
        """
        Method that retrieves the correct address from a query name of type PTR.

        Example:

            > get_address_from_ptr("3.2.0.10-inaddr.reverse.")
            > 10.0.2.3

            > get_address_from_ptr("20023:1.0.0.127-inaddr.reverse.")
            > 127.0.0.1:20023

        :param domain_name: Domain name to parse.
        :return: The address obtained.
        """

        # The address port.
        port = None

        # Transform the p:x.y.z.w-inaddr.reverse. into p:x.y.z.w.
        address_part = domain_name.split("-")[0]

        if ":" in address_part:

            # This should transform an address of type x.y.z.w:p on a [[p], [w, z, y, x]] object.
            divided_address = [part.split(".") for part in [p for p in address_part.split(":")]]
            port = divided_address[0][0]  # Get the port of the address.

        else:

            # This should transform an address of type x.y.z.w on a [[], [w, z, y, x]] object.
            divided_address = [part.split(".") for part in [p for p in address_part.split(":")]]
            divided_address = [[], divided_address[0]]  # We format like this to re-use our code, bellow.

        divided_address[1].reverse()  # Reverse the list to get the correct address.

        # Reconstructing the address as a string, [w, z, y, x] to x.y.z.w.
        reconstructed_address = "".join(f"{part}." for part in divided_address[1]).strip()
        reconstructed_address = reconstructed_address[:-1]

        return f"{reconstructed_address}:{port}" if port else reconstructed_address

    def response_values(self, domain_name: str, type_of_value: DNSValueType) -> [Optional[DNSResource]]:
        """
        Given domain_name and type_of_value, this function searches the database for full matches of the parameters.

        :param domain_name: Domain name we are looking for.
        :param type_of_value: Type of value we are looking for.
        :return: List with every full match entry.
        """

        # The queries of type PTR is a little different. Instead of providing a domain name, we provide
        # the *-inaddr name, for example, if we want to know what is the domain of 10.0.3.1 the query
        # would look like '1.3.0.10-inaddr.reverse.', this happens so that we can get to the in-addr domain
        # via recursive or iterative resolution. It will match on the '0.10-...'.
        if type_of_value is DNSValueType.PTR:

            domain_name = self.get_address_from_ptr(domain_name)

        response_values = []
        same_type_values: list[DNSResource] = self.database.get(type_of_value)

        if same_type_values:
            for entry in same_type_values:
                if entry.type == type_of_value and entry.parameter == domain_name:
                    response_values.append(entry)

        return response_values

    def authorities_values(self, domain_name: str, type_of_value: DNSValueType, prev_values: list[DNSResource]):
        """
        Given a domain_name, this function searches the database for matches with the given domain name and type of NS.
        If there was no result found on Database::response_values(), it looks for matches on its super-domain if it exists.

        :param type_of_value: Type of value we are looking for.
        :param prev_values: Previous values list used to not repeat values!
        :param domain_name: Domain name we are looking for.
        :return: List with every NS match entry.
        """

        authorities_values = []
        nameservers = self.database.get(DNSValueType.NS)

        if nameservers:

            for entry in nameservers:

                if entry not in prev_values and entry not in authorities_values:

                    if entry.parameter in domain_name or domain_name in entry.parameter:

                        authorities_values.append(entry)

        return authorities_values

    def extra_values(self, previous_values: list[DNSResource]):
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
        return list(map(lambda resource: resource.as_log_string(), filter(lambda r: r, values)))

    class Config:
        """
        Pydantic way of saying that we don't need validators for custom types.
        """
        arbitrary_types_allowed = True


# if __name__ == '__main__':
#
#     names = ["1.0.0.127-inaddr.reverse.maki.", "20023:1.0.0.127-inaddr.reverse.maki."]
#
#     for name in names:
#         print("Start: ", name)
#         print("End: ", Database.get_address_from_ptr(name))

