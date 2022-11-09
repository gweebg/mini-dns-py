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


class InvalidDNSHeaderFormat(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad dns header.'):
        super(InvalidDNSHeaderFormat, self).__init__(message)
