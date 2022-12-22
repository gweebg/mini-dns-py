import time

from enum import Enum
from typing import Optional
from threading import Lock

from dns.common.logger import Logger
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
    This class represents an entry on a TTL cache for resource records.
    """

    def __init__(self, resource_record: DNSResource, origin: EntryOrigin, overwrite_ttl: Optional[int] = None) -> None:

        self.data = resource_record  # The entry data will be the resource record from database/server.
        self.timestamp = None  # When adding this to a cache we will be using CacheEntry::stamp() to mark the time.
        self.origin = origin

        self.ttl = self.data.ttl

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

        self.entries: list[CacheEntry] = []
        self.lock = Lock()

    def add_entry(self, entry: CacheEntry) -> None:

        with self.lock:
            entry.stamp()
            self.entries.append(entry)

    def add_from_query_data(self, response: DNSPacketQueryData) -> None:

        every_response: list = response.response_values + response.authorities_values + response.extra_values

        with self.lock:
            for response in every_response:

                entry = CacheEntry(DNSResource.from_string(response), EntryOrigin.OTHER)
                entry.stamp()
                self.entries.append(entry)

    def match(self, query_info: DNSPacketQueryInfo) -> None:
        ...

    def from_database(self, database: Database) -> None:
        ...
