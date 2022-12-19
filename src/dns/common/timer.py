from threading import Timer


class RepeatedTimer:
    """
    Class that executes a given function every amount of seconds.
    """

    def __init__(self, interval, function, *args, **kwargs):
        """
        Constructor for the RepeatedTimer class.

        :param interval: Amount of time between repetitions.
        :param function: Function to execute.
        :param args: Arguments to the function.
        :param kwargs: Named arguments to the function.
        """

        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        """
        Method that actually runs the function.
        :return: None
        """

        self.is_running = False
        self.start()

        if not self.args and not self.kwargs:
            self.function()

        else:
            self.function(*self.args, **self.kwargs)

    def start(self):
        """
        Method that starts the timer for the execution, using the Timer class from threading.
        :return: None
        """

        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.daemon = True
            self._timer.start()
            self.is_running = True

    def stop(self):
        """
        Method that stops the timer and the schedule of the function.
        :return: None
        """

        self._timer.cancel()
        self.is_running = False