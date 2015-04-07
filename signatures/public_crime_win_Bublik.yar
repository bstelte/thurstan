rule Bublik : Downloader
{
	meta:
		author="Kevin Falcoz"
		date="29/09/2013"
		description="Bublik Trojan Downloader"
		
	strings:
		$signature1={63 6F 6E 73 6F 6C 61 73}
		$signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}
		
	condition:
		$signature1 and $signature2
}