class InvalidConfigFileException(Exception):
    """
    Custom exception for invalid parameters.
    """

    def __init__(self, message='Bad configuration file.'):
        super(InvalidConfigFileException, self).__init__(message)
