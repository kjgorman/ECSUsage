from sys import argv
import re

script, log_path = argv

header = re.compile("Users")
#
# Remove log entries with no user associated, and print to standard output.
# Basically useful for inspecting users manually from command line, e.g., 
# $> python filter_unused log | grep 2012-06-29 
# For all users online during collection on the 29th June 2012
#
with open(log_path) as log:
    for line in log.readlines():
        if re.match(header, line): 
            continue
        tkns = line.split(",")
        if tkns[4] != " \'\'":
            print line
