#! /usr/bin/python
#
#
# KYDScript (KYD stands for "Know Your Domains")
#
# Code by CPE / CERT Societe Generale 
# 
# Greetings to GAR for some Python debugging help ;-)
#
# Microsoft Windows compatible version by JPT
#
# v1.2
#
#
# What does it do ?
#
# 1. after usual parameter and file checking, it fetches one domain in the input file
# 2. tries socket.gethostbyname_ex on the domain
# 3.		if exception raised : makes a whois, and looks for the "Registrar" field
#			if none : "domain does not exist". Else : "no web server for domain"
# 4. checks with urlparse.
#		if exception : "no web server" (there could be a "A" record, but no web server)
#		if 301 or 302 : follow and check if timeout
# 5. outputs the results as a CSV file.
#

import socket
import urllib2
import string
import sys
import time
import commands
import re
import subprocess

from httplib import HTTP
from urlparse import urlparse

def checkURL(url,file):
	myhttpurl='http://'+url
	p = urlparse(myhttpurl)
	h = HTTP(p[1])
	h.putrequest('HEAD', p[2])
	h.putheader('Host',url)
	try:
		h.endheaders()
	except socket.error or socket.timeout:
		print >>file,';NO WEB SERVER' # Cas ou on a bien un domaine avec enregistrement A, mais rien derriere (pas de serveur web)
	else:
		try :
			status, errormessage, headers=h.getreply();
			print >>file,status,";",
			if  status==301 or status==302:
				myopener=urllib2.build_opener()
				try:
					f=myopener.open(myhttpurl)
				except urllib2.URLError:
					print  >>file,"REDIRECTION URL TIME OUT" # redirection ok mais domaine final time out
				else:
					finalurl=f.url[7:] # on vire le http:// en prenant la chaine a partir du 7eme char, pas tres class mais bon...
					print >>file,finalurl		
			else:
				print >>file,myhttpurl[7:]+";"
			return status
		except Exception, e:
			print "Exeption " + str(e) + " on " + str(url)
	return 0	


# Credits... :-p
print 'KYDScript (Know Your Domains Script) v1.1 by CPE / CERT Societe Generale'

# Test nombre d'arguments
if len(sys.argv)!=3 :
	print "Usage : ",sys.argv[0],"inputfilename outputfilename"
	sys.exit()

# Ouverture fichier d'input
try:
	myinputfile=open(sys.argv[1], "r")
except IOError:
	print "No such file :",sys.argv[1]
	sys.exit()

# Ouverture fichier d'output
try:
	myoutputfile=open(sys.argv[2],"w")
except IOError:
	print "Cannot write file :",sys.argv[2]
	sys.exit()

socket.setdefaulttimeout(20)
none='None'

for mydomain in myinputfile:
	
	mydomain=mydomain.strip()
	whoisdata=""
	print "Processing "+mydomain
	print >>myoutputfile,mydomain+";",

	try:
		mydata=socket.gethostbyname_ex(mydomain)
	
	except socket.gaierror, err:
		try:
			whoisdata = subprocess.check_output(["c:\SysinternalsSuite\whois", "%s" %mydomain])	
		except subprocess.CalledProcessError as e:
			whoisdata = e.output
		# For *nix: whoisstatus, whoisdata = commands.getstatusoutput("whois %s" %mydomain)
		print whoisdata
		bla=re.search('Registrar:',whoisdata)
		bla=str(bla)
		if bla=="None":
			print >>myoutputfile,'; ;DOMAIN DOES NOT EXIST'
		else:
			print >>myoutputfile,"; ;NO WEB SERVER FOR DOMAIN"
	else:
		ipslist=mydata[2]
		print >>myoutputfile,','.join(ipslist)+";",
		checkURL(mydomain,myoutputfile)
		
	time.sleep(2)
	
	
myinputfile.close()
myoutputfile.close()
