private rule IsPE
{
  condition:
     //MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}


rule HW05_rule{
 meta:
  author = "Naveen Reddy Aleti"
  description = "HW05: Yara Binary Code Analysis"

 strings:
  /* Malicious strings */

  $hex_string1 = {2E 3F 41 56 ( 74 79 70 65 5F 69 6E 66 6F  | 65 78 63 65 70 74 69 6F 6E 40 73 74  64  |   62 61 64 5F 65 78 63 65 70 74 69 6F  6E 40 73 74 64 ) 40 40 00} //Av Bad Exception or AvTypeInf

  $hex_string2 = {48 69 64 65 52 65 67 69  73 74 72 79 43 61 6C 6C 62 61 63 6B 3A 20 43 61 6C 6C 65 72 20 70 72 6F 63 65 73 73 20 70 61 74  68 3A 20 25 77 5A 0A 00 }  //HideRegistryCallback

  $hex_string3 = {  48 69 64 65 47 65 74 52  65 67 4B 65 79 56 61 6C 75 65 3A 20 [20-70] }          //  HideGetRegKeyValue :

  $hex_string4 = { 52 65 61 64 48 69 64 69  6E 67 43 6F ?E 66 6? 67 3? 20 ?? ?? ?? [20-80] }         //   ReadHidingConfig :

  $hex_string4 = { 5C 52 45 47 49 53 54 52 59 5C 4D 41  43 48 49 4E 45 5C 53 59 53 54 45 4D 5C 43 75 72  72 65 6E 74 43 [20-100]}  //\REGISTRY\MACHINE\SYSTEM\ControlSet**\services\FsFlt
 

condition:
  2 of them and IsPE

}
