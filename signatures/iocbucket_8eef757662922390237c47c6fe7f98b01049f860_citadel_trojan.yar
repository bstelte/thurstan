rule Citadel
{
strings:
$a = {8B C7 EB F5 55 8B EC}
    $b = {55 8B EC 83 EC 0C 8A 82 00 01 00 00}
        $c = {83 F9 66 74 ?? 83 F9 6E 74 ?? 83 F9 76 74 ?? 83 F9 7A}
        $d = "Coded by BRIAN KREBS for personal use only. I love my job & wife"
        $e = {3D D0 FF 1F 03 77 ?? 83 7D}
  condition:
($a and $b) or $c or $d or $e
}