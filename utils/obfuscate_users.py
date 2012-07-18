from sys import argv

script, fname = argv

#
# A simple script thaat will remove usernames from a log file
# and output the obfuscated log entries into a file 'obfs-%INPUTFILENAME%'
#

in_handle = open(fname)
out_handle = open("obfs-"+fname, "w+")
for line in in_handle.readlines():
    tkns = line.split(",")
    if len(tkns) == 1:
        continue
    new_line = tkns[0]+","+tkns[1]+","+tkns[2]+","+tkns[3]+",' ', ' ']"
    out_handle.write(new_line+"\n")
in_handle.close()
out_handle.close()
