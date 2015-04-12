# Thurstan - Simple IOC Scanner based on Loki

Scanner for Simple Indicators of Compromise with client/server Architecture

Detection is based on four detection methods:

    1. File Name IOC
       Regex match on full file path/name

    2. Yara Rule Check
       Yara signature match on file data and process memory

    3. Hash check
       Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files

## How-To Run Thurstan and Analyse the Reports

### Run Server

  - Download the program archive via the button "Download ZIP" on the right sidebar
  - Unpack THURSTAN locally
  - open a command line "cmd.exe" and run server.exe from there

### Run Client

  - Download the program archive via the button "Download ZIP" on the right sidebar
  - Unpack THURSTAN locally
  - Provide the folder to a target system that should be scanned: removable media, network share, folder on target system
  - open a command line "cmd.exe" as Administrator and run thurstan.exe from there with parameter "-x Server-IP" (you can also run LOKI without administrative privileges but some checks will be disabled and relevant objects on disk will not be accessible)

## Usage

    usage: thurstan.exe [-h] [-x serverip] [-p path] [-s kilobyte] [--printAll] [--noprocscan]
                    [--nofilescan] [--noindicator] [--debug]

    optional arguments:
      -h, --help     show this help message and exit
      -x serverip    IP-adr of thurstan server
      -p path        Path to scan
      -s kilobyte    Maximum file site to check in KB (default 2000 KB)
      --printAll     Print all files that are scanned
      --noprocscan   Skip the process scan
      --nofilescan   Skip the file scan
      --noindicator  Do not show a progress indicator
      --debug        Debug output

# Antivirus - False Positives

The compiled scanner may be detected by antivirus engines. This is caused by the fact that the scanner is a compiled python script that implement some file system and process scanning features that are also used in compiled malware code.

If you don't trust the compiled executable, please compile it yourself.

# License

Thurstan
Copyright (c) 2015 Björn Stelte

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)

