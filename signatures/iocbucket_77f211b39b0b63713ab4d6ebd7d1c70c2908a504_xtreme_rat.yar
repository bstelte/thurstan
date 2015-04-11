rule Xtreme_RAT_Generic : Trojan TLPGREEN
{
meta:
author="Florian Roth; Jean-Philippe Teissier"
date="18/04/2014"
description="Xtreme RAT - Remote Access Trojan"
strings:
$magic = { 4d 5a }
$s1 = "XTREME" wide fullword
$s2 = "XTREMEBINDER" wide
$s4 = "SOFTWARE\\XtremeRAT" wide
$s5 = "XTREMEUPDATE" wide
$s6 = "XtremeKeylogger" wide
$s7 = /myversion\|[0-9]\.[0-9]/ wide
$s8 = "xtreme rat" wide nocase	
condition:
$magic at 0 and 1 of ($s*)
}