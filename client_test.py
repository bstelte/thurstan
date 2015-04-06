#!/usr/bin/python           # This is client.py file
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Thurstan
# Simple IOC Scanner Client Test application
#
# Björn Stelte 
# 
# send messages to central server
# Mar 2015
# v0.1
import socket               # Import socket module
import base64

yaraRules = []

s = socket.socket()         # Create a socket object
#host = socket.gethostname() # Get local machine name
host = "127.0.0.1"
port = 12345                # Reserve a port for your service.

s.connect((host, port))
s.send('yara')
while True:
	data = s.recv(4096)
	if (data == "all"): break
	else: 
		yaraRules.append(data)
		s.send("next")	
print "received Yara Rules"
#data = s.recv(4096)
s.close                     # Close the socket when done
