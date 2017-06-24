private rule IsPE
{
  condition:
     //MZ signature at offset 0 and ...
      uint16(0) == 0x5A4D and
     // ... PE signature at offset stored in MZ header at 0x3C
     uint32(uint32(0x3C)) == 0x00004550
}


rule HW04_rule{
 meta:
  author = "Naveen Reddy Aleti"
  description = "HW04:Yara Static Analysis Using Strings,Observables"

 strings:
  /* Malicious strings */
  $mal_Debug = "IsDebuggerPresent"  nocase
  $mal_memory_leak0 = "An unexpected memory leak has occurred."
  $mal_memory_leak1 = "The sizes of unexpected leaked medium and large blocks are:"
  $mal_memory_leak2 = "The unexpected small block leaks are:"
 
  $mal_Hide_Error0 = "HideGetRegKeyValue: HideGetKeyValuePartialInformation error, status = 0x%8X" 
  $mal_Hide_Error1 = "HideGetRegKeyValue: ExAllocatePoolWithTag error"
  $mal_Hide_Error2 = "HideGetRegKeyValue: HideGetKeyValueBasicInformation error, status = 0x%8X"
  $mal_Hide_Error3 = "HideGetFileNameInformation: FltGetFileNameInformation error, status = 0x%8X"
  $mal_Hide_Error4 = "HideQueryNameString: ObQueryNameString error, status = 0x%8X"
  $mal_Hide_Error5 = "HideMakeFullPath: ExAllocatePoolWithTag error"
  $mal_Hide_Error6 = "HideGetProcessIdByName: HideGetSystemProcessInformation fail"
  $mal_Hide_Error7 = "HideGetProcessIdByName: %ws"
  $mal_Hide_Error8 = "HideGetSystemProcessInformation: ExAllocatePoolWithTag fail"
  $mal_Hide_Error9 = "HideGetSystemProcessInformation: ZwQuerySystemInformation fail, status = %x"
  $mal_Hide_Error10 = "HideAllocVirtualMemory: NtAllocateVirtualMemory error, status = 0x%08X"

  $mal_Hide1= "HideGetRegKeyValue"
  $mal_Hide2= "HideGetFileNameInformation" 
  $mal_Hide3= "HideQueryNameString" 
  $mal_Hide4= "HideMakeFullPath" 
  $mal_Hide5= "HideGetProcessIdByName" 
  $mal_Hide6= "HideGetSystemProcessInformation" 
  $mal_Hide7= "HideAllocVirtualMemory" 


 condition:
  2 of them and IsPE
}
