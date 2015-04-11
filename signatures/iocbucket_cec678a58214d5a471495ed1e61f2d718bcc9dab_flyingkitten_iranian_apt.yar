rule CrowdStrike_FlyingKitten : rat 
{ 
      meta: 
            copyright = "CrowdStrike, Inc" 
	     author = "Crowdstrike"
             description = "Flying Kitten RAT" 
             version = "1.0" 
             actor = "FLYING KITTEN" 
             in_the_wild = true 
       strings: 
             $classpath = "Stealer.Properties.Resources.resources" 
             $pdbstr = "\\Stealer\\obj\\x86\\Release\\Stealer.pdb" 
       condition: 
             all of them and 
             uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and 
             uint16(uint32(0x3C) + 0x16) & 0x2000 == 0 and 
             ((uint16(uint32(0x3c)+24) == 0x010b and 
            uint32(uint32(0x3c)+232) > 0) or 
             (uint16(uint32(0x3c)+24) == 0x020b and 
            uint32(uint32(0x3c)+248) > 0)) 
} 
 
rule CrowdStrike_CSIT_14003_03 : installer 
{ 
       meta: 
             copyright = "CrowdStrike, Inc" 
             description = "Flying Kitten Installer" 
             version = "1.0" 
             actor = "FLYING KITTEN" 
             in_the_wild = true 
       strings: 
             $exename = "IntelRapidStart.exe" 
             $confname = "IntelRapidStart.exe.config" 
             $cabhdr = { 4d 53 43 46 00 00 00 00 } 
       condition: 
             all of them 
}