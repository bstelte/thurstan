rule mumblehard_packer
{
	meta:
		description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
		author = "Marc-Etienne M.Léveillé"
		date = "2015-04-07"
		reference = "http://www.welivesecurity.com"
		version = "1"
	strings:
		$decrypt = { 31 db [1-10] ba ?? 00 00 00 [0-6] (56 5f | 89 F7) 39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 }
	condition:
		$decrypt
}
