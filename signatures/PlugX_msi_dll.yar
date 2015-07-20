rule PlugX_msi_dll : plugx_msi_dll
{
meta:
	author = "Anonymous"
	date = "2015-07-20"
	description = "APT PlugX msi.dll"
	hash0 = "a18b748564f67ead58ece5b679b8a8f6"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "setup.msi" wide
	$string1 = "z\\MnHNM\\TmXT\\"
	$string2 = ".reloc"
	$string3 = "Ba>;BP"
	$string4 = "[byfZbp"
	$string5 = "bSzXcR[b"
condition:
	5 of them
}
