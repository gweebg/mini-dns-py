import time

from enum import Enum
from typing import Optional
from threading import Lock, RLock
from itertools import filterfalse

from dns.models.dns_database import Database
from dns.models.dns_packet import DNSPacketQueryData, DNSPacketQueryInfo
from dns.models.dns_resource import DNSResource, DNSValueType


# TODO implement __equals__ to cache entry and others.

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

    def __match_response(self, query_info: DNSPacketQueryInfo) -> Optional[list[DNSResource]]:

        try:
            self.lock.acquire()

            response_values = []

            # Iterating over every entry, looking for the ones we want.
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

            if len(response_values) > 0:
                return list(map(lambda r: r.data, response_values))

            return None

        finally:
            self.lock.release()

    def __match_authorities(self, response_values: list[DNSResource], query_info: DNSPacketQueryInfo) -> list[
        DNSResource]:

        with self.lock:

            authorities_values = []

            for entry in self.entries.get(DNSValueType.NS):  # Iterating over authorities.

                # If entry is valid and not duplicated.
                if entry.is_valid() and entry.data not in response_values and entry not in authorities_values:

                    if entry.data.parameter in query_info.name:
                        authorities_values.append(entry)

                else:

                    # If the entry is no longer valid, we remove it.
                    self.entries.get(DNSValueType.NS)[:] = filterfalse(
                        lambda x: x == entry,
                        self.entries.get(DNSValueType.NS)
                    )

            return list(map(lambda a: a.data, authorities_values))

    def __match_addresses(self, response_values: list[DNSResource], authorities_values: list[DNSResource]) -> list[
        DNSResource]:

        with self.lock:

            extra_values = []

            # Let's get the addresses of the collected values.
            for value in response_values + authorities_values:

                for address in self.entries.get(DNSValueType.A):

                    if address.is_valid():

                        updated_value = value.value
                        if not value.value.endswith("."):
                            updated_value = value.value + "."

                        if updated_value == address.data.parameter:
                            extra_values.append(address)

                    else:

                        # If the entry is no longer valid, we remove it.
                        self.entries.get(DNSValueType.A)[:] = filterfalse(
                            lambda x: x == address,
                            self.entries.get(DNSValueType.A)
                        )

        return list(map(lambda e: e.data, extra_values))

    def cache_match(self, query_info: DNSPacketQueryInfo) -> Optional[DNSPacketQueryData]:

        with self.lock:
            response_values = self.__match_response(query_info)

            if response_values:
                authorities_values = self.__match_authorities(response_values, query_info)
                extra_values = self.__match_addresses(response_values, authorities_values)

                return DNSPacketQueryData(
                    response_values=response_values,  # TODO, tem de ser strings.
                    authorities_values=authorities_values,
                    extra_values=extra_values
                )

            return None

    def cache_from_database(self, database: Database) -> None:
        ...
