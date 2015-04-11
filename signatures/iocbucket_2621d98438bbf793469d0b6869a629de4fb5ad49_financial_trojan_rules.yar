rule xmlc : banker
{
	meta:
		author = "@iocbucket"
    strings: 
        $a = "/c del" fullword
        $b = "PostDel" fullword
        $c = ">> NUL" fullword
        $d = "LOADXML"
        $e = "lm.dat"
        $f = "---------------%s----------------"
        $g = /(\x00|\x20)([a-z0-9]{5,8}\.dll)\x00{1,8}\\\2/

    condition:
        filesize < 150KB and (3 of ($a,$b,$c,$d,$e,$f) or #g >= 2)      
}

rule silent_banker : banker
{
    strings: 
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}  
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}

rule zbot : banker
{
     strings: 
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule banbra : banker
{
    strings: 
        $a = "senha" fullword nocase
        $b = "cartao" fullword nocase
        $c = "caixa" 
        $d = "login" fullword nocase
        $e = ".com.br"

     condition:
        #a > 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3              
}

rule spyeye
{
meta:
description = "Indicates that the SpyEye Trojan is installed"

strings:
$a = "SPYNET"
$b = "SpyEye"

condition:
($a nd $b)
}

rule tdl3
{
meta:
null_string = 1

strings:
$ = "\\\\?\\globalroot\\"
$ = ".ini" 

condition:
all of them 
}