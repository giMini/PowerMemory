<#
.SYNOPSIS 
PowerProcess utility to get the name of a process by providing its address
 
.DESCRIPTION 
This utility try to get the name of a process with the help of its addess 
This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Get-ProcessNameByAddress -Process cmd.exe

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

#-----------------------------------------------------------[Functions]------------------------------------------------------------

. $utilityFunctions

#----------------------------------------------------------[Execution]----------------------------------------------------------

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
    "1014342" {
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
    }
}

Write-Output "Trying to get the process name located at $ProcessAddress"

$chain = "dt nt!_EPROCESS ImageFileName $ProcessAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                
$fi = [array]::indexof($tabFA,"quit:") - 1
$processName = $tabFA[$fi]

Write-Output "The process name is $processName"
