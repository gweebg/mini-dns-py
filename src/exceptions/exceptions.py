class InvalidConfigFileException(Exception):
    """
    Custom exception for invalid configuration file.
    """

    def __init__(self, message='Bad configuration file.'):
        super(InvalidConfigFileException, self).__init__(message)


class InvalidDatabaseFileException(Exception):
    """
    Custom exception for invalid database file.
    """

    def __init__(self, message='Bad database file.'):
        super(InvalidDatabaseFileException, self).__init__(message)


class InvalidDNSPacket(Exception):
    """
    Custom exception for invalid dns packet.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidDNSPacket, self).__init__(message)


class InvalidQueryValue(Exception):
    """
    Custom exception for invalid query value.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidQueryValue, self).__init__(message)


class InvalidRootListEntry(Exception):
    """
    Custom exception for invalid root list entry.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidRootListEntry, self).__init__(message)


class InvalidZoneTransferPacket(Exception):
    """
    Custom exception for invalid zone transfer packet.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidZoneTransferPacket, self).__init__(message)


class InvalidCacheEntryException(Exception):
    """
    Custom exception for invalid cache entry.
    """

    def __init__(self, message='Invalid cache entry!'):
        super(InvalidCacheEntryException, self).__init__(message)
