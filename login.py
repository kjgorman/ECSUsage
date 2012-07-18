###########################################################################################
#Login.py                                                                                 #
#                                                                                         #
#A simple utility that will, given a username and password, attempt to log into the VUW   #
#ECS network and save the kerberos authentication ticket required thereafter in the cookie#
#data for requests to protected material                              author: gormankier  #
###########################################################################################
from urllib2 import Request, urlopen, HTTPError
import urllib
import urllib2
import cookielib
import getpass
import re

#
# A module that will attempt to log a given username/password combination into the 
# University of Victoria School of Engineering and Computer Science web domain, 
# saving the kerberos authentication ticket received in cookie data so it may be used
# by other requests to access data that lays behind and auth wall or in the /auth/
# directory.
#
def login(uname, passwd):
    print "Logging in as: ", uname
    uri = "https://ecs.victoria.ac.nz"
    path = "/login-ticket"
    # Firstly we consruct our request
    req = Request(uri+path)
    # Some services discriminate connections that aren't from a web browser (Request by default will indicate
    # it's being sent by an automated process). ECS doesn't do that currently, but it can't hurt to include 
    # for the future.
    req.add_header("User-agent","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")
    # We make user of some prior knowledge of the redirection system to ensure the correct referer
    req.add_header("Referer", "ecs.victoria.ac.nz/login-ticket")
    # And we know our host, obviously.
    req.add_header("Host","ecs.victoria.ac.nz")
    # We want this request to accept our format type
    req.add_header("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    # And the meat of the request, the POST data, including the username and password, obviously no return
    # url or server url is necessary as we will ignore everything in the response bar the auth. cookie
    data = {"username":uname,
	        "password":passwd,
	        "realm":"ECS.VUW.AC.NZ",
	        "login":"Log in",
	        "ReturnUrl":"",
	        "ServerUrl":"",
	        ".cgifields":"ssl_only"} 
    # We use urllib to encode this data to the correct url string
    req.add_data(urllib.urlencode(data))
    # And we use cookielib to keep track of cookies in a managed way
    cj = cookielib.LWPCookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)

    try:
        # So now we try and use our opener with the username/password combination
        resp = urlopen(req)
        html = resp.read()
        # If the returned page has the standard fail message we divert control to
        # the catch clause
        if re.search("Incorrect username or password", html) != None:
            print "Failure"
            raise Exception
        # Otherwise, we can inspect our cookie jar for our authentication ticket
        for cookie in cj:
            print "Login successful"
            print "Authorisation ticket: ", str(cookie).split(" ")[1]
            # Which we proceed to write to our local memory
            o = open("cookie.txt", "w")
            o.write(str(cookie).split(" ")[1])
            o.close()   
            break
    except:
        # If we get here the response contained the default error message, which 
        # which means the supplied credentials were incorrect. We'll exit now and
        # overwrite the cookie file so dependent functions will know something
        # strange has happened to their user credentials
        print "Login failed"
        o = open("cookie.txt", "w")
        o.write("Failed")
        o.close()
        raise Exception("Authentication failed")

if __name__ == "__main__":
    uname = raw_input("Username: ")
    passwd = getpass.getpass()
    login(uname, passwd)

