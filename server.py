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
import socket               # Import socket module
import time
import yara
import os
import traceback
import pickle
import re

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

print "  Simple IOC Scanner next generation"
print "  "
print "  (c) Björn Stelte"
print "  v0.1"
print "  extented version based on loki:"
print "  "

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
	traceback.print_exc()

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
			with open("thurstan_server.log", "a") as logfile:
		    		logfile.write('"%s", "%s", "%s"\r\n' % (addr, currentTime, data))
		   if (data == "yara"):
			for i in yaraRulesText[0:]: 
				c.send(i)
				rec = c.recv(1024)
			print "%s Yara Rules send" % len(yaraRulesText)
			c.send('all')	
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
	
