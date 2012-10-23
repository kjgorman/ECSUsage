##########################################################################################
#whos_online.py                                                                          #
#As the name suggests this code will tell you who is online in the Cotton building 2nd   #
#floor *NIX labs. Originally written as part of my project to heat map computer usage,   #
#it makes use of the 'whos-online' tool available from the ECS cgi-bin to authenticated  #
#users.                                                              author: gormankier  #
##########################################################################################
from sys import argv
import sys
import urllib2
import re
import datetime
import subprocess
import login
import threading

lines = {}
filtered = {}
output = {}

def scrape(uname, passwd):
    dom = "https://ecs.victoria.ac.nz"
    bin = "/cgi-bin/whos-in?location="
    
    # First we log in with the desired username and password combination
    
    login.login(uname, passwd)
    

    # Thereafter we check to ensure we have successfully authenticated, a cookie.txt
    # file of "Failed", has obviously failed. In this case we throw an authentication 
    # exception before doing anything else
    
    try:
        cookie_file = open("cookie.txt", "r")
        authCookie = cookie_file.read()
        if authCookie == "Failed":
            raise Exception("Authentication required")
    finally:
        cookie_file.close()
    
    # Once we have logged in, we will have an authenticated kerberos ticket, which we 
    # need to append to all our subsequent transactions to get pass the auth-wall
    
    opener =  urllib2.build_opener()
    opener.addheaders = [('Cookie', 'FOSWIKIPREF=%7CTwistyPlugin_topicattachmentslist1%3D1; __utma=189107500.660830071.1342665800.1349567813.1349578543.19; __utmz=189107500.1349578543.19.6.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=vuw.ac.mnz; FOSWIKISID=150e66e0f304b29d29cc186cd28b607d; ECS130.195.6.218=1349843408%3A1349843408%3Agormankier%3AECS.VUW.AC.NZ%3Agormankier%3A0%3AGzXhhDqp9ZZK58AFm8I1t1CpNxw%3D; mcs_last_principal=gormankier; mcs_last_realm=ECS.VUW.AC.NZ; kerberos=;'+authCookie)]

    opener.addheaders.append(("User-Agent","Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168 Safari/535.19"))
    opener.addheaders.append(("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
    opener.addheaders.append(("Host", "ecs.victoria.ac.nz"))
    opener.addheaders.append(("Referer", "http://ecs.victoria.ac.nz/cgi-bin/whos-in?location=CO236"))
    opener.addheaders.append(("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.3"))
    opener.addheaders.append(("Accept-Encoding", "gzip,deflate,sdch"))
    opener.addheaders.append(("Accept-Language", "en-US,en;q=0.8"))
    opener.addheaders.append(("Connection", "keep-alive"))
    print opener.addheaders
    # Next we will want to take a look at the command line arguments for debugging
    # and restricting (or expanding) the room inspection list.
    # Arguments will follow the pattern of:
    #   [DEBUG][ROOM]*
    # If no rooms are specified we default to all *NIX labs on the second floor
    
    rooms = ["CO235", "CO232", "CO236", "CO238", "CO246", "CO243", "CO239", "CO237", "CO242"]
    debug = False
    to_file = True
    if len(argv) > 1:
        if argv[1] == 'DEBUG':
            debug = True
            if len(argv) > 2:
                rooms = argv[2:]
                to_file = False
        elif len(argv) > 2:
            rooms = argv[1:]
            to_file = False

    
    # We also define a simple logging function for the sake of brevity in our debugging
    # code later on
    
    def log(output):
        if debug:
            print output

    
    # Now we get into the meat of the program, by starting up a thread to perform a URL
    # request and parse on each of the rooms in the input (or default) room listing.
    

    for room in rooms:
        r = RoomRequest(room, debug, opener, dom, bin)
        r.start()

    
    # We then block this main thread until all of our requests have finished processing,
    # this is to avoid progressing to the log write before a dictionary key is finished 
    # adding. It would of course be possible for each thread to manage its own write to
    # file, but as the speed gain here is minimal by comparison with the parallel URL
    # requests, we won't bother doing anything else.
    
    while threading.active_count() > 1:
        continue
    
    # So now we know that we have <= 1 thread running (i.e. this main thread), we can 
    # safely examine our output dictionary and write it to a file. This also ensures
    # that we don't have any weird concurrent file modification exceptions/deadlocks
    
    try:
        log_file = open("log", "a")
        for room in rooms:
            log("Users in %s" % room)
            if to_file:
                log_file.write("Users in % s\n" % room)
            for tpl in output[room]:
                if to_file:
                    log_file.write("%s\n" % tpl)
                log(tpl)
    finally:
        log_file.close()



# A room request thread is a single request to a room, whose name (e.g. "CO236") is
# given as a constructor argument. It then queries the input url with the authenticated
# opener provided to it, and parses the response into the list of tuples of users.


class RoomRequest(threading.Thread):
    
    def __init__ (self, room, debug, opener, domain, cgibin):
        self.room = room      # Each of these variables
        self.debug = debug     # correspond directly
        self.opener = opener   # with their definitions
        self.dom = domain       # in the scrape function
        self.bin = cgibin       # should be obvious
        threading.Thread.__init__(self)
    
    # Currently unused debugging method similar to the global def.
    
    def log(self, s):
        if self.debug:
            print s 


    # Here's the function that actually performs the heavy lifting
    
    def run(self):
        start = datetime.datetime.now()
        print "Started thread %s\n" % self.room
        #log("Fetching %s" % self.room)
        print "Fetching %s\n" % self.room

        
        # Firstly we attempt to use our authenticated opener to fetch the
        # rooms pure html. A failure here causes everything to break...
        # 
        try:
            html = self.opener.open(self.dom+self.bin+self.room)
            lines[self.room] = html.readlines()
        except IOError, e:
            self.log("Failed to establish connection. Kerberos ticket likely expired")
            self.log(e)
            self.log(e.headers)
            raise Exception("Failed to open", self.room)

        
        # Next we iterate through the lines of HTML until we find the 
        # table element that contains the users  that are online. We
        # then filter only the lines of HTML that are within this table
        # and place it into the 'filtered' dictionary

        found_table = False
        table = ""
        print "Finished fetching"
        for line in lines[self.room]:	
            if re.match("<tr><TD><B>Position</B>", line) != None:
                found_table = True
            if found_table:                        
                if re.search("</table>", line) != None:
                    break
                table += line     
        filtered[self.room] = table


        #self.log("Finished_Fetching")
        #self.log("Filtering_XHTML")
        
        # Now that we have our table of computers and users, we can
        # look through each of these rows and split them out into a
        # row tuple of information: date/time, computer id no.
        # computer name, room, username, real name
        
        headers = True
        output[self.room] = []
        for line in filtered[self.room].split("</tr>"):
            elems = []
            rowdata = [] #First we split the line on the separator elements
            for tkn in line.split("</B>"):
                elems.append(tkn.split("<B>"))
            if headers:
                #We ignore the first loop through, as it's just the headers
                headers = False
            elif len(elems) > 1:
                #self.log("\tInspecting %s" % elems[1][-1:][0])
                #Next we want to get the names from the username/real name section of
                #the table. We do this by matching the close angle bracket followed by
                #a word, then some quantity of whitespace and words (this will match 
                #one to many names, e.g. Kieran or Kieran Gorman). The regex must match
                #the anglular closing tag as well, this ensures our match is maximal
                names = re.finditer("(?<=>)\w+(\s+\w+)*(?=</TD>)", str(elems[2][-1:][0]))
                #Now we append the first four elements to our tuple
                rowdata.append(datetime.datetime.now().isoformat())
                rowdata.append(elems[0][-1:][0])
                rowdata.append(elems[1][-1:][0])
                rowdata.append(self.room)
                #Before adding username and real name (if applicable)
                cntr = 0
                if names != None:
                    for m in names:
                        cntr = cntr+1
                        rowdata.append(m.group())
                        #if the counter has incremented, that means we are
                        #dealing with the 'real name' element of the tuple,
                        #as the default web page data is very feeble, we'll
                        #manually match the username to a real name in our 
                        #users file
                        #Hmmm... probably not so good to include a list of
                        #ECS users in the public domain
                        if cntr == 1:
                            usr = re.compile(rowdata[4])
                            #with open("users.txt") as usrs:
                                #essentially we look for the line that matches
                                #our username, and we fetch out the next two elements
                                # which are almost always first name second names.
                                # As each line is in the format:
                                # USERNAME FIRST NAME [SUBSEQUENT NAMES]*
                                #for line in usrs:
                                #    if re.match(usr, line): 
                                #        delim = re.compile("[\s+,]")
                                #        tkns = filter(None, delim.split(line))
                                #        if len(tkns) >= 3:
                                #            rowdata.append(tkns[1]+" "+tkns[2])
                                #        break   
                    if cntr == 0:
                        #If we have no username, then we want to ensure the tuple
                        #is of the correct arity so we don't need to encode corner
                        #cases for later parsing of the log  file, so we append two
                        #empty strings
                        rowdata.append("")
                        rowdata.append("") 
                output[self.room].append(rowdata)
            #self.log("Finished filtering" )
        print "Finished thread %s\n" % self.room
        print "Executed in", (datetime.datetime.now()-start)
        #Now the thread can print out it's execution time, and die a graceful death
        #knowing it's done its job
    
        

# If you don't want to run from the executer file (maybe running just once)
# you can run directly from here.
   
if __name__ == "__main__":
    import getpass
    username = raw_input("Username: ")
    passwd = getpass.getpass()
    scrape(username, passwd)
