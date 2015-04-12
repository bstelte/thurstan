#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# THURSTAN
# Simple IOC Scanner Application
#
#
# Björn Stelte 
# THURSTAN
# scanner gets rules from and sends messages to central server
# Mar 2015
# v0.1
#
# based on LOKI 
# February 2015
# v0.4.3
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


import sys
import os
import argparse
import scandir
import traceback
import yara
import hashlib
import re
import stat
import datetime
import platform
import psutil
import pickle
import time
import socket               # Import socket module

from sets import Set
from colorama import Fore, Back, Style
from colorama import init

# Win32 Imports
try:
    import wmi
    from win32com.shell import shell
    isLinux = False
except Exception, e:
    print "Linux System - deactivating process memory check ..."
    isLinux= True
#     isLinux= False

# Predefined paths to skip (Linux platform)
LINUX_PATH_SKIPS_START = Set(["/proc", "/dev", "/media", "/sys/kernel/debug", "/sys/kernel/slab", "/sys/devices", "/usr/src/linux" ])
LINUX_PATH_SKIPS_END = Set(["/initctl"])

def recv_timeout(the_socket,timeout=1):
    #make socket non blocking
    the_socket.setblocking(0)
     
    #total data partwise in an array
    total_data=[];
    data='';
    c = 0;
     
    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break
         
        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break
         
	c += 1
	if not args.noindicator:
        	printProgress(c)

        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin=time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
     
    #join all parts to make final string
    return ''.join(total_data)

from itertools import cycle, izip
def str_xor(s1, s2):
 return ''.join(chr(ord(c)^ord(k)) for c,k in izip(s1, cycle(s2)))

def scanPath(path, rule_sets, filename_iocs, filename_suspicious_iocs, hashes, false_hashes):

    # Startup
    log("INFO","Scanning %s ...  " % path)

    # Counter
    c = 0

    # Get application path
    appPath = getApplicationPath()

    # Linux excludes from mtab
    if isLinux:
        allExcludes = LINUX_PATH_SKIPS_START | Set(getExcludedMountpoints())

    for root, directories, files in scandir.walk(path, onerror=walkError, followlinks=False):

            if isLinux:
                # Skip paths that start with ..
                newDirectories = []
                for dir in directories:
                    skipIt = False
                    completePath = os.path.join(root, dir)
                    for skip in allExcludes:
                        if completePath.startswith(skip):
                            log("INFO", "Skipping %s directory" % skip)
                            skipIt = True
                    if not skipIt:
                        newDirectories.append(dir)
                directories[:] = newDirectories

            # Loop through files
            for filename in files:
                try:

                    # Get the file and path
                    filePath = os.path.join(root,filename)

                    # Linux directory skip
                    if isLinux:

                        # Skip paths that end with ..
                        for skip in LINUX_PATH_SKIPS_END:
                            if filePath.endswith(skip):
                                if LINUX_PATH_SKIPS_END[skip] == 0:
                                    log("INFO", "Skipping %s element" % skip)
                                    LINUX_PATH_SKIPS_END[skip] = 1

                        # File mode
                        mode = os.stat(filePath).st_mode
                        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISLNK(mode) or stat.S_ISSOCK(mode):
                            continue

                    # Counter
                    c += 1

                    if not args.noindicator:
                        printProgress(c)

                    # Skip program directory
                    if appPath.lower() in filePath.lower():
                        log("DEBUG", "Skipping file in program directory FILE: %s" % filePath)
                        continue

                    file_size = os.stat(filePath).st_size
                    # print file_size

                    # File Name Checks -------------------------------------------------
                    for regex in filename_iocs.keys():
                        match = re.search(r'%s' % regex, filePath)
                        if match:
                            description = filename_iocs[regex]
                            log("ALERT", "File Name IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath))

                    # File Name Suspicious Checks --------------------------------------
                    for regex in filename_suspicious_iocs.keys():
                        match = re.search(r'%s' % regex, filePath)
                        if match:
                            description = filename_suspicious_iocs[regex]
                            log("WARNING", "File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, filePath))

                    # Hash Check -------------------------------------------------------
                    if file_size > ( args.s * 1024):
                         # Print files
                        if args.printAll:
                            log("INFO", "Checking %s" % filePath)
                        continue
                    else:
                        if args.printAll:
                            log("INFO", "Scanning %s" % filePath)

                    # Read file complete
                    with open(filePath, 'rb') as f:
                        fileData = f.read()

                    md5, sha1, sha256 = generateHashes(fileData)

                    log("DEBUG", "MD5: %s SHA1: %s SHA256: %s FILE: %s" % ( md5, sha1, sha256, filePath ))

                    # False Positive Hash
                    if md5 in false_hashes.keys() or sha1 in false_hashes.keys() or sha256 in false_hashes.keys():
                        continue

                    # Malware Hash
                    matchType = None
                    matchDesc = None
                    matchHash = None
                    if md5 in hashes.keys():
                        matchType = "MD5"
                        matchDesc = hashes[md5]
                        matchHash = md5
                    elif sha1 in hashes.keys():
                        matchType = "SHA1"
                        matchDesc = hashes[sha1]
                        matchHash = sha1
                    elif sha256 in hashes.keys():
                        matchType = "SHA256"
                        matchDesc = hashes[sha256]
                        matchHash = sha256

                    if matchType:
                        log("ALERT", "Malware Hash TYPE: %s HASH: %s FILE: %s DESC: %s" % ( matchType, matchHash, filePath, matchDesc))

                    # Yara Check -------------------------------------------------------
                    try:
                        for rules in rule_sets:
                            matches = rules.match(data=fileData)
                            if matches:
                                for match in matches:
                                    log("ALERT", "Yara Rule MATCH: %s FILE: %s" % ( match.rule, filePath))
                    except Exception, e:
                        if args.debug:
                            traceback.print_exc()

                except Exception, e:
                    if args.debug:
                        traceback.print_exc()


def scanProcesses(rule_sets, filename_iocs, filename_suspicious_iocs):
    # WMI Handler
    c = wmi.WMI()
    processes = c.Win32_Process()
    t_systemroot = os.environ['SYSTEMROOT']

    # WinInit PID
    wininit_pid = 0
    # LSASS Counter
    lsass_count = 0

    for process in processes:

        try:

            # Gather Process Information --------------------------------------
            pid = process.ProcessId
            name = process.Name
            cmd = process.CommandLine
            if not cmd:
                cmd = "N/A"
            if not name:
                name = "N/A"
            path = "none"
            parent_pid = process.ParentProcessId
            priority = process.Priority
            ws_size = process.VirtualSize
            if process.ExecutablePath:
                path = process.ExecutablePath
            # Owner
            try:
                owner_raw = process.GetOwner()
                owner = owner_raw[2]
            except Exception, e:
                owner = "unknown"
            if not owner:
                owner = "unknown"

        except Exception, e:
            log("ALERT", "Error getting all process information. Did you run the scanner 'As Administrator'?")
            continue

        # Is parent to other processes - save PID
        if name == "wininit.exe":
            wininit_pid = pid

        # Skip some PIDs ------------------------------------------------------
        if pid == 0 or pid == 4:
            log("INFO", "Skipping Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))
            continue

        # Skip own process ----------------------------------------------------
        if os.getpid() == pid:
            log("INFO", "Skipping THURSTAN Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))
            continue

        # Print info ----------------------------------------------------------
        log("NOTICE", "Scanning Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ))

        # Special Checks ------------------------------------------------------
        # better executable path
        if not "\\" in cmd and path != "none":
            cmd = path

        # Skeleton Key Malware Process
        if re.search(r'psexec .* [a-fA-F0-9]{32}', cmd, re.IGNORECASE):
            log("WARNING", "Process that looks liks SKELETON KEY psexec execution detected PID: %s NAME: %s CMD: %s" % ( pid, name, cmd))

        # File Name Checks -------------------------------------------------
        for regex in filename_iocs.keys():
            match = re.search(r'%s' % regex, cmd)
            if match:
                description = filename_iocs[regex]
                log("ALERT", "File Name IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, cmd))

        # File Name Suspicious Checks --------------------------------------
        for regex in filename_suspicious_iocs.keys():
            match = re.search(r'%s' % regex, cmd)
            if match:
                description = filename_suspicious_iocs[regex]
                log("WARNING", "File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s" % (regex, description, cmd))

        # Yara rule match
        # only on processes with a small working set size
        if int(ws_size) < ( 100 * 1048576 ): # 100 MB
            try:
                alerts = []
                for rules in rule_sets:
                    matches = rules.match(pid=pid)
                    if matches:
                        for match in matches:
                            # print match.rule
                            alerts.append("Yara Rule MATCH: %s PID: %s NAME: %s CMD: %s" % ( match.rule, pid, name, cmd))
                if len(alerts) > 3:
                    log("INFO", "Too many matches on process memory - most likely a false positive PID: %s NAME: %s CMD: %s" % (pid, name, cmd))
                elif len(alerts) > 0:
                    for alert in alerts:
                        log("ALERT", alert)
            except Exception, e:
                log("ERROR", "Error while process memory Yara check (maybe the process doesn't exist anymore or access denied). PID: %s NAME: %s" % ( pid, name))
        else:
            log("DEBUG", "Skipped Yara memory check due to the process' big working set size (stability issues) PID: %s NAME: %s SIZE: %s" % ( pid, name, ws_size))

        ###############################################################
        # THOR Process Anomaly Checks
        # Source: Sysforensics http://goo.gl/P99QZQ

        # Process: System
        if name == "System" and not pid == 4:
            log("WARNING", "System process without PID=4 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))

        # Process: smss.exe
        if name == "smss.exe" and not parent_pid == 4:
            log("WARNING", "smss.exe parent PID is != 4 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if path != "none":
            if name == "smss.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "smss.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "smss.exe" and priority is not 11:
            log("WARNING", "smss.exe priority is not 11 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))

        # Process: csrss.exe
        if path != "none":
            if name == "csrss.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "csrss.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "csrss.exe" and priority is not 13:
            log("WARNING", "csrss.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))

        # Process: wininit.exe
        if path != "none":
            if name == "wininit.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "wininit.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "wininit.exe" and priority is not 13:
            log("NOTICE", "wininit.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        # Is parent to other processes - save PID
        if name == "wininit.exe":
            wininit_pid = pid

        # Process: services.exe
        if path != "none":
            if name == "services.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "services.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "services.exe" and priority is not 9:
            log("WARNING", "services.exe priority is not 9 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if wininit_pid > 0:
            if name == "services.exe" and not parent_pid == wininit_pid:
                log("WARNING", "services.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))

        # Process: lsass.exe
        if path != "none":
            if name == "lsass.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "lsass.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "lsass.exe" and priority is not 9:
            log("WARNING", "lsass.exe priority is not 9 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if wininit_pid > 0:
            if name == "lsass.exe" and not parent_pid == wininit_pid:
                log("WARNING", "lsass.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        # Only a single lsass process is valid - count occurrences
        if name == "lsass.exe":
            lsass_count += 1
            if lsass_count > 1:
                log("WARNING", "lsass.exe count is higher than 1 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))

        # Process: svchost.exe
        if path is not "none":
            if name == "svchost.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "svchost.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "svchost.exe" and priority is not 8:
            log("NOTICE", "svchost.exe priority is not 8 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if name == "svchost.exe" and not ( owner.upper().startswith("NT ") or owner.upper().startswith("NET") or owner.upper().startswith("LO") or owner.upper().startswith("SYSTEM") ):
            log("WARNING", "svchost.exe process owner is suspicious PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))

        if name == "svchost.exe" and not " -k " in cmd and cmd != "N/A":
            print cmd
            log("WARNING", "svchost.exe process does not contain a -k in its command line PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))

        # Process: lsm.exe
        if path != "none":
            if name == "lsm.exe" and not ( "system32" in path.lower() or "system32" in cmd.lower() ):
                log("WARNING", "lsm.exe path is not System32 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "lsm.exe" and priority is not 8:
            log("NOTICE", "lsm.exe priority is not 8 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if name == "lsm.exe" and not ( owner.startswith("NT ") or owner.startswith("LO") or owner.startswith("SYSTEM") ):
            log("WARNING", "lsm.exe process owner is suspicious PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if wininit_pid > 0:
            if name == "lsm.exe" and not parent_pid == wininit_pid:
                log("WARNING", "lsm.exe parent PID is not the one of wininit.exe PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))

        # Process: winlogon.exe
        if name == "winlogon.exe" and priority is not 13:
            log("WARNING", "winlogon.exe priority is not 13 PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                str(pid), name, owner, cmd, path))
        if re.search("(Windows 7|Windows Vista)", getPlatformFull()):
            if name == "winlogon.exe" and parent_pid > 0:
                for proc in processes:
                    if parent_pid == proc.ProcessId:
                        log("WARNING", "winlogon.exe has a parent ID but should have none PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s PARENTPID: %s" % (
                            str(pid), name, owner, cmd, path, str(parent_pid)))

        # Process: explorer.exe
        if path != "none":
            if name == "explorer.exe" and not t_systemroot.lower() in path.lower():
                log("WARNING", "explorer.exe path is not %%SYSTEMROOT%% PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                    str(pid), name, owner, cmd, path))
        if name == "explorer.exe" and parent_pid > 0:
            for proc in processes:
                if parent_pid == proc.ProcessId:
                    log("NOTICE", "explorer.exe has a parent ID but should have none PID: %s NAME: %s OWNER: %s CMD: %s PATH: %s" % (
                        str(pid), name, owner, cmd, path))


def generateHashes(filedata):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception, e:
        traceback.print_exc()
        return 0, 0, 0


def walkError(err):
    if args.debug:
        traceback.print_exc()


def removeNonAsciiDrop(string):
    nonascii = "error"
    #print "CON: ", string
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception, e:
        traceback.print_exc()
        pass
    #print "NON: ", nonascii
    return nonascii


def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % ( " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception, e:
        type_info = " ".join(platform.win32_ver())
    return type_info


def setNice():
    try:
        pid = os.getpid()
        p = psutil.Process(pid)
        log("INFO", "Setting THURSTAN process with PID: %s to priority IDLE" % pid)
        p.set_nice(psutil.IDLE_PRIORITY_CLASS)
        return 1
    except Exception, e:
        log("ERROR", "Error setting nice value of THOR process")
        return 0


def getExcludedMountpoints():
    excludes = []
    mtab = open("/etc/mtab", "r")
    for mpoint in mtab:
        options = mpoint.split(" ")
        if not options[0].startswith("/dev/"):
            if not options[1] == "/":
                excludes.append(options[1])

    mtab.close()
    return excludes


def getFileNameIOCs_ng(ioc):

    filenames = {}  
    try:
	s = socket.socket()         # Create a socket object
	port = 12345                # Reserve a port for your service.
	s.connect((args.x, port))
	s.send(ioc)
	data = s.recv(10000)
	filenames = pickle.loads(data)		
	log("INFO","received IOCs")
	s.close                       
       
    except Exception, e:
        log("ERROR", "Error reading IOCs")
        if args.debug:
            traceback.print_exc()     
    	

    return filenames

def getHashes_ng(hash_file):
    hashes = {}  
    log("INFO","requesting Hashes - please wait")
    try:
	s = socket.socket()         # Create a socket object
	port = 12345                # Reserve a port for your service.
	s.connect((args.x, port))
	s.send(hash_file)
	#data = s.recv(10000)
	data = recv_timeout(s)
	hashes = pickle.loads(data)		
	log("INFO","received Hashes")
	s.close                       
       
    except Exception, e:
        log("ERROR", "Error reading hashes")    
    	
        if args.debug:
            traceback.print_exc()     
    	

    return hashes


def initializeYaraRules_ng():

    yaraRules = []

    try:
	s = socket.socket()         # Create a socket object
	port = 12345                # Reserve a port for your service.
	s.connect((args.x, port))
	log("INFO","requesting Yara Rules - please wait")
	s.send('yara')
	while True:
		#data = s.recv(10000)
		data = str_xor(recv_timeout(s), 'YaraRules')
		if (data == "all"): break
		else:
			compiledRules = yara.compile(source=data)
                	yaraRules.append(compiledRules)
			s.send("next")
			
	log("INFO","received Yara Rules")
	s.close 
                        
       
    except Exception, e:
        log("ERROR", "Error reading signatures")
	traceback.print_exc()
        if args.debug:
            traceback.print_exc()

    log ("INFO", "%s Yara Rules loaded" % len(yaraRules))
    return yaraRules




def printProgress(i):
    if (i%4) == 0:
        sys.stdout.write('\b/')
    elif (i%4) == 1:
        sys.stdout.write('\b-')
    elif (i%4) == 2:
        sys.stdout.write('\b\\')
    elif (i%4) == 3:
        sys.stdout.write('\b|')
    sys.stdout.flush()


def getApplicationPath():
    try:
        application_path = ""
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        elif __file__:
            application_path = os.path.dirname(__file__)
        if application_path != "":
            # Working directory change skipped due to the function to create TXT, CSV and HTML file on the local file
            # system when thurstan is started from a read only network share
            # os.chdir(application_path)
            pass
        if application_path == "":
            application_path = os.path.dirname(os.path.realpath(__file__))
        return application_path
    except Exception, e:
        log("ERROR","Error while evaluation of application path")


def log(mes_type, message):

    global alerts, warnings

    try:
        # Default
        color = Fore.WHITE
        # Print to console
        if mes_type == "ERROR":
            color = Fore.MAGENTA
        if mes_type == "INFO":
            color = Fore.GREEN + Style.BRIGHT
        if mes_type == "ALERT":
            color = Fore.RED
            alerts += 1
        if mes_type == "DEBUG":
            if not args.debug:
                return
            color = Fore.WHITE
        if mes_type == "WARNING":
            color = Fore.YELLOW
            warnings += 1
        if mes_type == "NOTICE":
            color = Fore.CYAN
        if mes_type == "RESULT":
            if "clean" in message.lower():
                color = Fore.BLACK+Back.GREEN
            elif "suspicious" in message.lower():
                color = Fore.BLACK+Back.YELLOW
            else:
                color = Fore.BLACK+Back.RED

        # Print to console
        if mes_type == "RESULT":
            res_message = "\b\b[%s] %s" % (mes_type, removeNonAsciiDrop(message))
            print color,res_message,Back.BLACK
            print Fore.WHITE,Style.NORMAL
        else:
            print color,"\b\b[%s] %s" % (mes_type, removeNonAsciiDrop(message)),Back.BLACK,Fore.WHITE,Style.NORMAL

        # Write to file
        with open(args.l, "a") as logfile:
            logfile.write("%s %s THURSTAN: %s\n" % (getSyslogTimestamp(), t_hostname, removeNonAsciiDrop(message)))

	# Write to server
        if ((args.x) and ((mes_type == "ALERT") or (mes_type == "WARNING") or (mes_type == "RESULT"))):
            s = socket.socket()         # Create a socket object
	    port = 12345                # Reserve a port for your service.
	    s.connect((args.x, port))
	    #hostmessage = "match"
	    hostmessage = "%s THURSTAN match: %s \n" % (t_hostname, removeNonAsciiDrop(message))
	    s.send(hostmessage)
	    print s.recv(1024)
	    s.close     


    except Exception, e:
        traceback.print_exc()
        print "Cannot print/send log file"


def getSyslogTimestamp():
    date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%b %d %H:%M:%S")
    daymod = re.compile('^([A-Z][a-z][a-z]) 0([0-9])')
    date_str_mod = daymod.sub(r"\1  \2", date_str)
    return date_str_mod


def printWelcome():
    print " THURSTAN "
    print "  "
    print "  IOC Scanner"
    print "  "
    print "  (c) Björn Stelte"
    print "  v0.1"
    print "  "
    print "  DISCLAIMER - USE AT YOUR OWN RISK"
    print "  "
    print Back.GREEN + " ".ljust(79) + Back.BLACK
    print Fore.WHITE+''+Back.BLACK


# MAIN ################################################################
if __name__ == '__main__':

    # Counters --------------------------------------------------------
    warnings = 0
    alerts = 0

    # Parse Arguments
    parser = argparse.ArgumentParser(description='THURSTAN - Simple IOC Scanner - DISCLAIMER - USE AT YOUR OWN RISK.')
    parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
    parser.add_argument('-s', help='Maximum file site to check in KB (default 2000 KB)', metavar='kilobyte', default=2048)
    parser.add_argument('-l', help='Log file', metavar='log-file', default='thurstan_scan.log')
    parser.add_argument('-x', help='Report to Server (host)', metavar='host', default='')
    parser.add_argument('--printAll', action='store_true', help='Print all files that are scanned', default=False)
    parser.add_argument('--noprocscan', action='store_true', help='Skip the process scan', default=False)
    parser.add_argument('--nofilescan', action='store_true', help='Skip the file scan', default=False)
    parser.add_argument('--noindicator', action='store_true', help='Do not show a progress indicator', default=False)
    parser.add_argument('--dontwait', action='store_true', help='Do not wait on exit', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Colorization ----------------------------------------------------
    init()

    # Remove old log file
    if os.path.exists(args.l):
        os.remove(args.l)

    # Print Welcome ---------------------------------------------------
    printWelcome()
    if not isLinux:
        t_hostname = os.environ['COMPUTERNAME']
    else:
        t_hostname = os.uname()[1]
#	t_hostname = platform.node()


    log("INFO", "THURSTAN - Starting Thurstan Scan on %s" % t_hostname)

    # Check if admin
    isAdmin = False
    if not isLinux:
        if shell.IsUserAnAdmin():
            isAdmin = True
            log("INFO", "Current user has admin rights - very good")
        else:
            log("NOTICE", "Program should be run 'as Administrator' to ensure all access rights to process memory and file objects.")
    else:
        if os.geteuid() == 0:
            isAdmin = True
            log("INFO", "Current user is root - very good")
        else:
            log("NOTICE", "Program should be run as 'root' to ensure all access rights to process memory and file objects.")

    # Set process to nice priority ------------------------------------
    if not isLinux:
        setNice()

    # Read IOCs -------------------------------------------------------
    # File Name IOCs
    filenameIOCs = getFileNameIOCs_ng("ioc")
    log("INFO","File Name Characteristics initialized with %s regex patterns" % len(filenameIOCs.keys()))
    # File Name Suspicious IOCs
    filenameSuspiciousIOCs = getFileNameIOCs_ng("sioc")
    log("INFO","File Name Suspicious Characteristics initialized with %s regex patterns" % len(filenameSuspiciousIOCs.keys()))
    # Hash based IOCs
    fileHashes = getHashes_ng("hash")
    log("INFO","Malware Hashes initialized with %s hashes" % len(fileHashes.keys()))
    # Hash based False Positives
    falseHashes = getHashes_ng("ehash")
    log("INFO","False Positive Hashes initialized with %s hashes" % len(falseHashes.keys()))
    # Compile Yara Rules
    yaraRules = initializeYaraRules_ng()

    # Scan Processes --------------------------------------------------
    resultProc = False
    if not args.noprocscan and not isLinux:
        if isAdmin:
            scanProcesses(yaraRules, filenameIOCs, filenameSuspiciousIOCs)
        else:
            log("NOTICE", "Skipping process memory check. User has no admin rights.")

    # Scan Path -------------------------------------------------------
    # Set default
    defaultPath = args.p
    if isLinux and defaultPath == "C:\\":
        defaultPath = "/"

    resultFS = False
    if not args.nofilescan:
        scanPath(defaultPath, yaraRules, filenameIOCs, filenameSuspiciousIOCs, fileHashes, falseHashes)

    # Result ----------------------------------------------------------
    print " "
    if alerts:
        log("RESULT", "INDICATORS DETECTED!")
        log("RESULT", "THURSTAN recommends a forensic analysis and triage with a professional triage tool.")
    elif warnings:
        log("RESULT", "SUSPICIOUS OBJECTS DETECTED!")
        log("RESULT", "THURSTAN recommends a deeper analysis of the suspicious objects.")
    else:
        log("RESULT", "SYSTEM SEEMS TO BE CLEAN.")

    print " "
    if not args.dontwait:
        raw_input("Press Enter to exit ...")
