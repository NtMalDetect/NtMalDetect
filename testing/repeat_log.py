import threading

class Program_Repeater(threading.Thread):

    """Thread that executes a task every N seconds"""
    def __init__(self, interval):
        threading.Thread.__init__(self)
        self._interval = interval
        self._finished = threading.Event()

    def set_interval(self, interval):
        """ set the interval in which this program will repeat """
        self._interval = interval

    def shutdown(self):
        """ shut down this thread """
        self._finished.set()

    def run(self):
        while 1:
            if self._finished.isSet(): return
            self.task()

            # sleep for interval or until shutdown
            self._finished.wait(self._interval)

    def task(self):

