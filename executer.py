##########################################################################
#Executer.py                                                             #
#A resource to execute the scraper once every ten minutes, for some user #
#defined quantity of iterations.                                         #
#                                                     Author: gormankier #
##########################################################################
import datetime
import time
import subprocess
import getpass
import whos_online
from sys import argv 

if len(argv) > 1:
    script, iterations = argv
else:
    print "No iteration count defined, falling back to default of 1"
    iterations = 1

uname = raw_input("Username: ")
passwd = getpass.getpass()

def runOnce():
    # We will record the timing of the run so we can space out calls
    # every ten minutes
    start = datetime.datetime.now()
    whos_online.scrape(uname, passwd)
    finish = datetime.datetime.now()
    diff = finish - start
    
    # If the cookie is ever 'failed' it means the user credentials 
    # are, or have become, invalid, so we must exit
    with open("cookie.txt") as status: 
        if status.read() == "Failed":
            raise Exception("Login failed")

    print diff
    return diff

# We run the scraper once every ten minutes
for i in xrange(int(iterations)):
    print "Running at %s \n" % datetime.datetime.now().isoformat()
    diff = runOnce().seconds    
    if(int(iterations) > 1):
        time.sleep(600-diff) #10 minutes less run time
