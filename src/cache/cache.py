import time


class Cache(dict):

    def __init__(self, maxsize: int = 100):
        super().__init__()
        self.__table = {}
        self.maxsize = maxsize

    def add(self, key, value, timeout=1):
        self.__table[key] = time.time() + timeout
        dict.update(self, {key: value})

    def __contains__(self, item):
        return time.time() < self.__table.get(item)

    def __iter__(self):
        for item in dict.__iter__(self):
            if time.time() < self.__table.get(item):
                yield item

    def __len__(self):
        counter = 0
        for item in dict.__iter__(self):
            if time.time() < self.__table.get(item):
                counter += 1

        return counter





