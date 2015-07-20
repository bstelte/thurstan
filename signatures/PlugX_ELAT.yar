rule PlugX_ELAT
{ 
	meta:
		maltype = "plugX"
		reference = "http://www.fireeye.com/blog/technical/targeted-attack/2014/02/operation-greedywonk-multiple-economic-and-foreign-policy-sites-compromised-serving-up-flash-zero-day-exploit.html"
		description = "Malware creates a randomized directory within the appdata roaming directory and launches the malware. Should see multiple events for create process rundll32.exe and iexplorer.exe as it repeatedly uses iexplorer to launch the rundll32 process."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data=/\\AppData\\Roaming\\[0-9]{9,12}\VMwareCplLauncher\.exe/

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="\\Windows\\System32\\rundll32.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="Program Files\\Internet Explorer\\iexplore.exe"
	condition:
		all of them
}
rule Korplug_ELAT
{ 
	meta:
		maltype = "Korplug Backdoor"
		reference = "http://www.symantec.com/connect/blogs/new-sample-backdoorkorplug-signed-stolen-certificate"
		description = "IOC looks for events associated with the KORPLUG Backdoor linked to the recent operation greedy wonk activity."
		
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\RasTls.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\rundll32.exe"

		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="ProgramData\\RasTls\\svchost.exe"
	condition:
		all of them
}
