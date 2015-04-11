rule folder_dumpfile
{
	meta:
		author="Cedric PERNET"
		date="2013/07"
		comment="a YARA rule to detect dump files created by APT attackers"

	strings:
		$eng1="Volume in drive" wide ascii nocase
		$eng2="Volume serial number" wide ascii nocase
		$eng3="Directory of" wide ascii nocase
		$eng4="<DIR>" wide ascii nocase
		$eng5="File" wide ascii nocase

		$fr1="Le volume dans le lecteur" wide ascii nocase
		$fr2="du volume est" wide ascii nocase
		$fr3="pertoire de" wide ascii nocase
		$fr4="<REP>" wide ascii nocase
		$fr5="fichier" wide ascii nocase

		$de1="Volumeseriennummer" wide ascii nocase
		$de2="<DIR>" wide ascii nocase
		$de3="verzeichnis von" wide ascii nocase
		$de4="Datei" wide ascii nocase

	condition:
		(all of ($eng*)) or (all of ($fr*)) or (all of ($de*))
}
