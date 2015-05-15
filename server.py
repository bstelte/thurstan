#!/usr/bin/python           # This is server.py file
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# THURSTAN
# Simple IOC Scanner Server
#
# (c) Björn Stelte 
#
# send messages to central server
# Mar 2015
# v0.1
#
# based on LOKI - IOC Scanner
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import socket               # Import socket module
import time
import yara
import os
import traceback
import pickle
import re
import urllib2
import urllib
import json
import ConfigParser

#api = 'your vt api key here'
#base = 'https://www.virustotal.com/vtapi/v2/'
#virustotal_active = 0

config = ConfigParser.ConfigParser()
config.read("server.ini")

api = config.get("virustotal", "api")
base = config.get("virustotal", "base")
virustotal_active = config.get("virustotal", "virustotal_active")
cymru_active = config.get("cymru", "cymru_active")
logfilename = config.get("logfile", "logfilename")
hashfilename = config.get("logfile", "hashfilename")
vtfilename = config.get("logfile", "vtfilename")

yaraRules = []
yaraRulesText = []

def getHashes(hash_file):

    hashes = {}

    try:
        with open(hash_file, 'r') as file:
            lines = file.readlines()

        for line in lines:
            try:
                if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                    continue
                row = line.split(';')
                hash = row[0]
                comment = row[1].rstrip(" ").rstrip("\n")
                # Empty File Hash
                if hash == "d41d8cd98f00b204e9800998ecf8427e" or \
                   hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709" or \
                   hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                    continue
                # Else - check which type it is
                if len(hash) == 32 or len(hash) == 40 or len(hash) == 64:
                    hashes[hash.lower()] = comment
            except Exception,e:
                log("ERROR", "Cannot read line: %s" % line)

    except Exception, e:
        traceback.print_exc()
        log("ERROR", "Error reading Hash file: %s" % hash_file)

    return hashes


def getFileNameIOCs(ioc_file):

    filenames = {}

    try:
        with open(ioc_file, 'r') as file:
            lines = file.readlines()

        for line in lines:
            try:
                # Comments
                if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                    continue
                # Elements with description
                if ";" in line:
                    row = line.split(';')
                    regex = row[0]
                    desc  = row[1].rstrip(" ").rstrip("\n")
                # Elements without description
                else:
                    regex = line
                filenames[regex] = desc
            except Exception, e:
                print "Error reading line: %s" % line

    except Exception, e:
        traceback.print_exc()
        print "Error reading File IOC file: %s" % ioc_file

    return filenames

def getReportCymru(md5):
   
    try:
	mhr=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	mhr.connect(("hash.cymru.com",43))
	mhr.send(str(md5+"\r\n"))
	response=''
	while True:
		d=mhr.recv(4096)
		response+=d
		if d=='':
			break
	if "NO_DATA" not in response:
		return 1 
	
    except Exception, e:
        pass

    return 0

def getReport(md5):
    jdata = " "
    try:
	param = {'resource':md5,'apikey':api}
	url = base + "file/report"
	data = urllib.urlencode(param)
	result = urllib2.urlopen(url,data)
	jdata = json.loads(result.read())
	
    except Exception, e:
        #traceback.print_exc()
        print "Error VirusTotal API"

    return jdata

def parse(it, md5, vtfilename):
   try:
	if it['response_code'] == 0:
		print md5 + " -- Not Found in VirusTotal Database"
		return 0
	print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n'
	if 'Sophos' in it['scans']:
		print '\tSophos Detection:',it['scans']['Sophos']['result'],'\n'
	if 'Kaspersky' in it['scans']:
		print '\tKaspersky Detection:',it['scans']['Kaspersky']['result'], '\n'
	if 'ESET-NOD32' in it['scans']:
		print '\tESET Detection:',it['scans']['ESET-NOD32']['result'],'\n'
	print '\tScanned on:',it['scan_date']

	with open(vtfilename, "a") as logfile:
    		logfile.write('"%s", "%s", "%s", "%s/%s", "%s", "%s", "%s" \r\n' % (time.ctime(time.time()), md5, it['positives'], it['total'], it['scans']['Sophos']['result'], it['scans']['Kaspersky']['result'], it['scans']['ESET-NOD32']['result']))

   except Exception, e:
        #traceback.print_exc()
        print "Error JSON parser"
   return 1

from itertools import cycle, izip
def str_xor(s1, s2):
 return ''.join(chr(ord(c)^ord(k)) for c,k in izip(s1, cycle(s2)))

print "  Simple IOC Scanner next generation"
print "  "
print "  (c) Björn Stelte"
print "  v0.1"
print "  extented version based on loki IOC scanner:"
print "  "

if (virustotal_active == "1"):
	print "VirusTotal API activated - will search for hash-values in VT database "
if (cymru_active == "1"):
	print "CYMRU API activated - will search for hash-values in Cymru MHR database "

try:
	for file in ( os.listdir("./signatures")  ):
	    try:

		# Skip hidden, backup or system related files
		if file.startswith(".") or file.startswith("~") or file.startswith("_"):
		    continue

		# Extension
		extension = os.path.splitext(file)[1].lower()

		# Full Path
		yaraRuleFile = "./signatures/%s" % file

		# Encrypted
		if extension == ".yar":
		    try:
		        compiledRules = yara.compile(yaraRuleFile)
		        yaraRules.append(compiledRules)
		        print "INFO Initialized Yara rules from %s" % file
			fileobj = open(yaraRuleFile, 'r')
			yaraRulesText.append(fileobj.read())
			fileobj.close()
		    except Exception, e:
		        print "ERROR Error in Yara file: %s" % file
		        traceback.print_exc()

	    except Exception, e:
		print "ERROR Error reading signature file /signatures/%s" % file
		traceback.print_exc()

except Exception, e:
	print "ERROR Error reading signature folder /signatures/"
	#traceback.print_exc()

filenameIOCs = getFileNameIOCs("./signatures/filename-iocs.txt")
filenameSuspiciousIOCs = getFileNameIOCs("./signatures/filename-suspicious.txt")
fileHashes = getHashes("./signatures/hash-iocs.txt")
falseHashes = getHashes("./signatures/falsepositive-hashes.txt")

s = socket.socket()         # Create a socket object
#host = socket.gethostname() # Get local machine name
host = "0.0.0.0"
port = 12345                # Reserve a port for your service.
s.bind((host, port))        # Bind to the port
print "\n THURSTAN Server - v0.1 (c) 2015 Björn Stelte\n"
s.listen(150)                 # Now wait for client connection.
while True:
	try:
		while True:
		   c, addr = s.accept()     # Establish connection with client.
		   currentTime = time.ctime(time.time())
		   data = c.recv(4096)
		   if data: 
			print 'Got connection from %s at %s - Msg %s' % (addr, currentTime, data)
			datastring = data
			if (datastring.startswith('Hash ')):
				md5=datastring.replace('Hash ','')
				with open(hashfilename, "a") as logfilehash:
			    		logfilehash.write('%s\r\n' % (md5))
				if (virustotal_active == "1"):
					if (parse(getReport(md5.upper),md5,vtfilename) == 1):
						with open(logfilename, "a") as logfile:
			    				logfile.write('VirusTotal MD5 Hash %s found\r\n' % (md5))
				if (cymru_active == "1"):
					if (getReportCymru(md5.upper) == 1):
						with open(logfilename, "a") as logfile:
			    				logfile.write('CYMRU MD5 Hash %s found\r\n' % (md5))
			else:
				with open(logfilename, "a") as logfile:
			    		logfile.write('"%s", "%s", "%s"\r\n' % (addr, currentTime, data))
		   if (data == "yara"):
			for i in yaraRulesText[0:]: 
				c.send(str_xor(i, 'YaraRules'))
				rec = c.recv(1024)
			print "%s Yara Rules send" % len(yaraRulesText)
			c.send(str_xor('all', 'YaraRules'))	
		   elif (data == "ioc"): 
			c.send(pickle.dumps(filenameIOCs))
			print "%s IOCs send" % len(filenameIOCs)
			#c.send('all')
		   elif (data == "sioc"): 
			c.send(pickle.dumps(filenameSuspiciousIOCs))
			print "%s SuspiciousIOCs send" % len(filenameSuspiciousIOCs)
			#c.send('all')
		   elif (data == "hash"): 
			c.send(pickle.dumps(fileHashes))
			print "%s hashes send" % len(fileHashes)
			#c.send('all')
		   elif (data == "ehash"): 
			c.send(pickle.dumps(falseHashes))
			print "%s falsehashes send" % len(falseHashes)
			#c.send('all')
		   else:	
		   	c.send('received')
		   c.close()                # Close the connection
	except Exception, e:
		print " Socket Error "
		#traceback.print_exc()
