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
