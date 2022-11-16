class InvalidConfigFileException(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad configuration file.'):
        super(InvalidConfigFileException, self).__init__(message)


class InvalidDatabaseFileException(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad database file.'):
        super(InvalidDatabaseFileException, self).__init__(message)


class InvalidDNSPacket(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidDNSPacket, self).__init__(message)


class InvalidQueryValue(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidQueryValue, self).__init__(message)


class InvalidRootListEntry(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidRootListEntry, self).__init__(message)
