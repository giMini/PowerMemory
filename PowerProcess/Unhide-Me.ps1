<#

.SYNOPSIS 
PowerProcess utility to unhide a hidden process
 
.DESCRIPTION 
This utility try to unhide a hidden process.
This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Unhide-Me -Process fffffa8012dbd940

Windows 7, 8, 10 supported (64 bits)

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]        
        [string] $ProcessAddress
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

Write-Output "Trying to unhide the process at address: $ProcessAddress..."

$chain = "dt nt!_EPROCESS ImageFileName $ProcessAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                
$fi = [array]::indexof($tabFA,"quit:") - 1
$processName = $tabFA[$fi]
Write-Output "A process has been found ($processName)"

Write-Output "Get a previous process to insert $processName after..."
$chain = "!process 0 0 System"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$referencedProcessAddress = $tabFA[$fi]

$chain = "dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $referencedProcessAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                 
$fi = [array]::indexof($tabFA,"_LIST_ENTRY") + 2
$referencedProcessLinks = $tabFA[$fi]

$chain = "dt nt!_eprocess ActiveProcessLinks. ImageFileName $referencedProcessAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                  
$fi = [array]::indexof($tabFA,"[") + 1
$referencedFLINK = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"]") - 1
$referencedBLINK = $tabFA[$fi]

# Process next to lsass
$chain = "dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $referencedFLINK-$activeProcessLinksOffset)"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                 
$fi = [array]::indexof($tabFA,"_LIST_ENTRY") + 2
$forwardProcessLinks = $tabFA[$fi]

# Process to insert
$chain = "dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $ProcessAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                 
$fi = [array]::indexof($tabFA,"_LIST_ENTRY") + 2
$thisProcessLinks = $tabFA[$fi]

Write-Output "Begin to insert the process $processName"

# update flink of the process to insert to the base links of the process next to lsass
$chain = "f $thisProcessLinks L4 0x$($forwardProcessLinks.Substring(17,2)) 0x$($forwardProcessLinks.Substring(15,2)) 0x$($forwardProcessLinks.Substring(13,2)) 0x$($forwardProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# update blink of the process to insert to the base links of the process of lsass
$chain = "f $thisProcessLinks+0x8 L4 0x$($referencedProcessLinks.Substring(17,2)) 0x$($referencedProcessLinks.Substring(15,2)) 0x$($referencedProcessLinks.Substring(13,2)) 0x$($referencedProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# update flink of referenced process (lsass) to the links process of the process to insert
$chain = "f $referencedProcessLinks L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# update blink of Next process to the links of the process to insert
$chain = "f $forwardProcessLinks+0x8 L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

Write-Output "$processName is inserted and unhidden"