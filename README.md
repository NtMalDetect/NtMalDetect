# NtMalDetect

This is an open-source program aiming to detect malicious programs using traces of system calls. The system calls are traced using <a href="https://github.com/rogerorr/NtTrace">NtTrace</a> and machine learning algorithms classify the system call trace to either be benign or malicious.
(This is an unfinished project still under development)

This project uses machine learning algorithms on a TFIDF model comprised of ten-grams of system call traces to determine if a given program is a malware. 

## Usage (as of now)

Run NtMalDetect.py with the following arguments (mandatory and optional):
```
-r This will specify that the program we are working with is not currently being run but that we are running it with this program to trace its system calls.
   For this option, the parameter that follows will specify the path to the file we are analyzing.
   
-p This will specify that we will attach and log a currently running process. 
   For this option, the parameter will specify that PID of the process.
-h (optional) If this argument is specified, both classifiers will need to agree that a given program is malicious for this program to determine that it is malicious. The default is that it is not specified and it is set so that if any one of the classifiers agree that it is malicious, it is determined to be malicious.
  
```
Example run:
```
Python3 NtMalDetect.py -r "./suspicious.exe"
Python3 NtMalDetect.py -p 1234
Python3 NtMalDetect.py -p 1234 -h
```

## Contents

  - NtTrace/ - <a href="https://github.com/rogerorr/NtTrace">NtTrace</a>
  - finding_models/ - tries various classifiers and tests their efficiency/accuracy
  - pickles/ - pickle dumps of two of the best classifiers and the vectorizer
  - sysBEN/ - Logs of system call traces of benign programs
  - sysMAL/ - Logs of system call traces of malicious programs
  - testing/ - Various scripts to test certain aspects
  - NtMalDetect.py - The main program that outputs prediction results
  - final_classifier.py - The script that determines if the program is a malware
  - pkl_build.py - Produces the pickle dumps
  
## Upcoming Changes 
- [ ] Finish writing basic working python script.
- [ ] Move all to src/ and make it an executable file.
- [ ] Set up a remote server, export system call traces to a PostgreSQL database.
- [ ] Write an API on that server so that people can submit new traces and new programs to contribute to the database.
- [ ] Write a script that executes itself periodically to re-assess the classifiers and parameters based on the new inputs.



