import logging

from dns.models.config_entry import ConfigEntry


class Logger:

    """
    Classes that inherit from Logger will be able to log to any file specified on a list of
    ConfigEntry.
    """

    def __init__(self, logger_list: list[ConfigEntry], debug_flag: bool) -> None:
        """
        Constructor of Logger.

        :param logger_list: List containing the information to create de loggers.
        :param debug_flag: If this is active we add a console handler.
        """

        self.loggers = self.create_loggers(logger_list, debug_flag)

    @staticmethod
    def create_loggers(logger_list: list[ConfigEntry], debug_flag: bool) -> dict[str, logging.Logger]:

        loggers: dict[str, logging.Logger] = {}

        # Iterating through the 'LG' entries to create the respective loggers.
        for log_entry in logger_list:

            logger_name = log_entry.parameter  # Logger name.
            logger_path = log_entry.value  # Logger path.

            # Creating the Logger object itself with the correct name.
            logger = logging.getLogger(logger_name)

            logger.handlers.clear()  # Clearing its handlers, just in case.
            logger.setLevel(logging.INFO)  # We will be logging in 'INFO' mode.

            # Configure the logger handler and formatter.
            logger_handler = logging.FileHandler(logger_path, mode='a')  # We are going to append to the file if exists.

            # Example: [logger.py - ERROR] [2022-12-18 21:10:40,520] [EZ | 127.0.0.1 | Some error message goes here.]
            logger_formatter = logging.Formatter("[%(filename)s - %(levelname)s] [%(asctime)s] [%(message)s]")

            # Adding the formatter and setting the formatter to the logger handler.
            logger_handler.setFormatter(logger_formatter)
            logger.addHandler(logger_handler)

            # If the debug flag is active, we enable console logging to the 'all' logger that's obligatory.
            if debug_flag and logger_name == 'all':

                logger_console_handler = logging.StreamHandler()  # Console handler to print in terminal.

                logger_console_handler.setLevel(logging.INFO)  # Same logging level as the file logger.
                logger_console_handler.setFormatter(logger_formatter)  # Using the same format for the file handler.

                logger.addHandler(logger_console_handler)  # Adding the new console handler.

            loggers[logger_name] = logger  # Adding the new logger to the dictionary.

        return loggers

    def log(self, logger_name: str, content: str, mode: str):
        """
        We use this function to log 'content' to 'logger_name' in mode 'mode'.
        If a 'all' logger exists, then it will always log to 'all' independently of the provided 'logger_name'.

        :param logger_name: Which logger to use.
        :param content: What content to write to the log file.
        :param mode: In which mode we want to log (info, debug, warning, error, etc.)
        :return: None
        """

        if logger_name in self.loggers:

            # To log something using the logging module we usually do 'logging.getLogger(..).mode()'.
            # Since the mode is a method and not a parameter we need to obtain the function using
            # the 'getattr' function.
            log_method = getattr(self.loggers.get(logger_name), mode)
            log_method(content)  # Running the logging function.

        # If the logger 'all' is set, then we also log into it.
        if 'all' in self.loggers and logger_name != 'all':

            # Same logic from above aplies here.
            log_method = getattr(self.loggers.get('all'), mode)
            log_method(content)




