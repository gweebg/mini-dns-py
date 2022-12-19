import time

from collections.abc import MutableSequence
from typing import Optional
from abc import ABC

from dns.models.dns_resource import DNSResource, DNSValueType


class CacheEntry:

    def __init__(self, resource_record: DNSResource, overwrite_ttl: Optional[int] = None):
        self.resource_record = resource_record
        self.time_to_live = overwrite_ttl if overwrite_ttl else self.resource_record.ttl
        self.timestamp = None

    def stamp(self):
        self.timestamp = time.time()


class Cache(MutableSequence, ABC):

    def __init__(self, maxsize: int = 128):

        super(Cache, self).__init__()

        self.type = CacheEntry
        self.maxsize = maxsize

        self.list = list()

    def check(self, value):

        if not isinstance(value, self.type):
            raise TypeError(value)

    def __iter__(self):

        entry: CacheEntry
        for entry in self.list.copy():

            expiry_stamp = entry.timestamp + entry.resource_record.ttl

            if time.time() >= expiry_stamp:
                self.list.remove(entry)
                continue

            yield entry

    def __delitem__(self, key):
        ...

    def __getitem__(self, item):
        ...

    def __len__(self):

        counter = 0
        for _ in self.__iter__():
            counter += 1

        return counter

    def __setitem__(self, key, value):
        ...

    def insert(self, index, value) -> None:
        ...

    def add_entry(self, entry: CacheEntry):

        if len(self.list) < self.maxsize:
            self.check(entry)
            entry.stamp()
            self.insert(len(self.list), entry)

    def lookup(self, name: str, type_of_value: DNSValueType):

        entry: CacheEntry
        for entry in self.__iter__():
            if (entry.resource_record.parameter == name) and (entry.resource_record.type == type_of_value):
                return entry


rr1 = DNSResource.from_string('lili.lycoris. NS ns1.lili.lycoris. 200')
rr2 = DNSResource.from_string('lili.lycoris. NS ns2.lili.lycoris. 300')

ce1 = CacheEntry(rr1)
ce2 = CacheEntry(rr2)

c = Cache(maxsize=3)

c.add_entry(ce1)
c.add_entry(ce2)

for e in c:
    print(e)

# class Cache(dict):
#
#     def __init__(self, maxsize: int = 100):
#         super().__init__()
#         self.__table = {}
#         self.maxsize = maxsize
#
#     def add(self, key, value, timeout=1):
#         if self.__len__() + 1 < self.maxsize:
#             self.__table[key] = time.time() + timeout
#             dict.update(self, {key: value})
#
#     def __contains__(self, item):
#         return time.time() < self.__table.get(item)
#
#     def __iter__(self):
#         for item in dict.__iter__(self):
#             if time.time() < self.__table.get(item):
#                 yield item
#
#     def __len__(self):
#         counter = 0
#         for item in dict.__iter__(self):
#             if time.time() < self.__table.get(item):
#                 counter += 1
#
#         return counter
