from final_classifier import classify
import sys
import os
import threading


def run():
    input = ""  # the long string of system calls


    """ determine preferences """

    run_program_str = sys.argv[1]  # -r or -p?

    """
    
        -r 
            This will specify that the program we are working with is not currently being run
            but that we are running it with this program to trace its system calls.
            
            For this option, the parameter that follows will specify the path to the file we are analyzing.
            
        -p 
            This will specify that we are logging a currently running process. 
    
            For this option, the parameter will specify that PID of the process.
        
        -h (optional)
        
            If this is specified, both classifiers will need to agree that a given program is malicious
            for this program to determine that it is malicious. The default is that it is not specified
            and it is set so that if any one of the classifiers agree that it is malicious, it is determined
            to be malicious.
         
    """
    if run_program_str == "-r":
        path_to_file = sys.argv[2]
        file_name = path_to_file.split("/")[-1]
        path_to_log_file = "./TEMP/"+file_name+"_log.txt"
        os.system("./NtTrace/NtTrace " + path_to_file + " > " + path_to_log_file)

        # update input variable with the new system calls
        periodic_logger = Log_System_Calls(10, path_to_log_file)
        periodic_logger.run()

        classify(input, False)

    elif run_program_str == "-p":
        PID = sys.argv[2]


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
        """ To be overriden by the subclass """
        pass


class Log_System_Calls(Program_Repeater):
    def __init__(self, interval, path_to_log_file):
        Program_Repeater.__init__(self, interval)
        self._path_to_log_file = path_to_log_file

    def task(self):
        global input
        input = read_from_file_clean_to_only_sys_call(self._path_to_log_file)

def read_from_file_clean_to_only_sys_call(filepath):
    """
    Receives path to txt file as parameter, outputs long string of
    system calls separated by new lines
    """
    returning_string = ""
    f = open(filepath, 'r')
    for line in f:
        if line[:2] == 'Nt':
            newL = line.split('(')[0]
            returning_string += newL+"\n"
    return returning_string
