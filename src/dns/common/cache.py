import time

from enum import Enum
from typing import Optional
from threading import Lock, RLock
from itertools import filterfalse

from dns.models.dns_database import Database
from dns.models.dns_packet import DNSPacketQueryData, DNSPacketQueryInfo
from dns.models.dns_resource import DNSResource, DNSValueType


class EntryOrigin(Enum):
    """
    Enumeration that represents the origin of data in a cache entry.
    """

    FILE = 1  # If the cache entry data came from a file.
    PS = 2  # If the cache entry data came for a primary server.
    OTHER = 3  # If the cache entry has another different origin.


class CacheEntry:
    """
    This class represents an entry on a TTL positive cache for resource records.
    """

    def __init__(self, resource_record: DNSResource, origin: EntryOrigin, overwrite_ttl: Optional[int] = None) -> None:

        self.data = resource_record  # The entry data will be the resource record from database/server.
        self.timestamp = None  # When adding this to a cache we will be using CacheEntry::stamp() to mark the time.
        self.origin = origin

        self.ttl = float(self.data.ttl)

        if overwrite_ttl:
            self.ttl = overwrite_ttl  # We can forcefully add a different TTL value to any entry.

        if self.origin.name == "FILE":
            self.ttl = None  # If the TTL value is set to none, then we shall never take it out of cache.

        self.expire_time = None  # Value used to determine if the TTL value has passed.

    def stamp(self) -> None:
        """
        When this entry is added to a cache we stamp the entry to give us the time it was added.
        Besides that we also calculate at what time it should no longer be valid.
        :return: None
        """
        self.timestamp = time.time()

        if self.ttl:
            self.expire_time = self.timestamp + self.ttl

    def is_valid(self) -> bool:
        """
        This method returns whether an entry is valid on not based on it's time to live.
        :return: True if valid, false otherwise.
        """
        if self.ttl is None:  # If the TTL value is None, then the entry stays forever.
            return True

        return time.time() <= self.expire_time

    def __eq__(self, other: 'CacheEntry') -> bool:

        if self.ttl == other.ttl and \
                self.data == other.data and \
                self.origin == other.origin and \
                self.timestamp == other.timestamp:
            return True

        return False


class Cache:
    """
    Class that represents a cache for a DNS server.
    """

    def __init__(self) -> None:

        self.entries: dict[DNSValueType, list[CacheEntry]] = {}
        self.__init_cache()

        self.lock = RLock()

    def __init_cache(self):

        for data_value in DNSValueType:
            self.entries[data_value] = []

    def add_entry(self, entry: CacheEntry) -> None:

        with self.lock:
            entry.stamp()
            self.entries.get(entry.data.type).append(entry)

    def add_from_query_data(self, response: DNSPacketQueryData) -> None:

        with self.lock:
            every_response: list = response.response_values + response.authorities_values + response.extra_values

            for response in every_response:
                entry = CacheEntry(DNSResource.from_string(response), EntryOrigin.OTHER)
                entry.stamp()
                self.entries.get(entry.data.type).append(entry)

    def __match_response(self, query_info: DNSPacketQueryInfo) -> Optional[list[CacheEntry]]:

        with self.lock:

            response_values = []

            # Iterating over every entry, looking for the ones we want.
            entry: CacheEntry
            for entry in self.entries.get(query_info.type_of_value):

                # If the entry is valid (within its TTL), we look up for answers.
                if entry.is_valid():

                    if entry.data.type == query_info.type_of_value and entry.data.parameter == query_info.name:
                        response_values.append(entry)

                else:

                    # If the entry is no longer valid, we remove it.
                    self.entries.get(query_info.type_of_value)[:] = filterfalse(
                        lambda x: x == entry,
                        self.entries.get(query_info.type_of_value)
                    )

                # return list(map(lambda r: r.data.as_log_string(), response_values))
            return response_values if response_values else None

    def __match_authorities(self, response_values: list[CacheEntry], query_info: DNSPacketQueryInfo) -> list[CacheEntry]:

        with self.lock:

            authorities_values: list[CacheEntry] = []

            entry: CacheEntry
            for entry in self.entries.get(DNSValueType.NS):  # Iterating over authorities.

                # If entry is valid and not duplicated.
                if entry.is_valid():

                    if entry not in response_values and \
                            entry not in authorities_values and \
                            entry.data.parameter in query_info.name:

                        authorities_values.append(entry)

                else:

                    # If the entry is no longer valid, we remove it.
                    self.entries.get(DNSValueType.NS)[:] = filterfalse(
                        lambda x: x == entry,
                        self.entries.get(DNSValueType.NS)
                    )

            # return list(map(lambda a: a.data.as_log_string(), authorities_values))
            return authorities_values

    def __match_addresses(self, response_values: list[CacheEntry], authorities_values: list[CacheEntry]) -> list[CacheEntry]:

        with self.lock:

            extra_values: list[CacheEntry] = []

            # Let's get the addresses of the collected values.

            value: CacheEntry
            for value in response_values + authorities_values:

                address: CacheEntry
                for address in self.entries.get(DNSValueType.A):

                    if address.is_valid():

                        updated_value = value.data.value
                        if not value.data.value.endswith("."):
                            updated_value = value.data.value + "."

                        if updated_value == address.data.parameter:
                            extra_values.append(address)

                    else:

                        # If the entry is no longer valid, we remove it.
                        self.entries.get(DNSValueType.A)[:] = filterfalse(
                            lambda x: x == address,
                            self.entries.get(DNSValueType.A)
                        )

            # return list(map(lambda e: e.data.as_log_string(), extra_values))
            return extra_values

    def cache_match(self, query_info: DNSPacketQueryInfo) -> Optional[DNSPacketQueryData]:

        with self.lock:
            response_values = self.__match_response(query_info)

            if response_values:
                authorities_values = self.__match_authorities(response_values, query_info)
                extra_values = self.__match_addresses(response_values, authorities_values)

                return DNSPacketQueryData(
                    response_values=self.map_to_str(response_values),
                    authorities_values=self.map_to_str(authorities_values),
                    extra_values=self.map_to_str(extra_values)
                )

            return None

    def cache_from_database(self, database: Database) -> None:

        with self.lock:

            flattened_database = [x for v in database.database.values() for x in v]

            entry: DNSResource
            for entry in flattened_database:

                cache_entry = CacheEntry(entry, EntryOrigin.FILE)
                self.add_entry(cache_entry)

    @staticmethod
    def map_to_str(data: list[CacheEntry]) -> list[str]:
        return list(map(lambda a: a.data.as_log_string(), data))


"""

# Since, it is a recursive query, we shall check the cache first!
                cached_data = self.cache_match(packet.query_info)
                if cached_data:

                    # Building the response from the obtained data.
                    response = DNSPacket.build_packet(packet, cached_data, True)

                    self.udp_socket.sendto(response.as_byte_string(), address)  # Sending to client.

                    self.log('all', f'EV | localhost | Found a response in cache for:\n{str(packet)}', 'info')
                    self.log('all', f'RP | {address} | Sent the final query response to the client.', 'info')

                    return response.header.response_code

                else:  # Nothing was found on cache, so we forward the query.

"""