<#
.SYNOPSIS 
    Fun in memory to trick the MineSweeper application
 
.DESCRIPTION 
    Play with the memory of MineSweeper to secure the minefield :-)

.EXAMPLE 
PS > Demine-Field.ps1

.Note
    Work with MineSweeper 5.1.2600.0

#>


[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $Flag,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $Demine,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $Reveal,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $Explose,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $UniversalResponse,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [switch] $Clean
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

#----------------------------------------------------------[Functions]-------------------------------------------------------------

function Get-OperatingSystemMode ($operatingSystem, $osArchitecture) {
    if($operatingSystem -eq "5.1.2600" -or $operatingSystem -eq "5.2.3790"){
        $mode = 3
    }
    else {
        if($operatingSystem -eq "6.1.7601" -or $operatingSystem -eq "6.1.7600"){
            if($osArchitecture -like "64*") {
                $mode = 1
            }
            else {
                $mode = 132
            }
        }
        else {
            if($operatingSystem -eq "6.2.9200"){
                $mode = 2
            }
            else{
                if($operatingSystem -eq "6.3.9600" -or $operatingSystem -eq "10.0.10240"){        
                    if($osArchitecture -like "64*") {  
                        if($operatingSystem -eq "6.3.9600"){
                            $mode = "8.1"       
                        }       
                        else {
                            $mode = "2r2"
                        }
                    }
                    else {
                        $mode = "232"
                    }
                }
                else {
                    if ($operatingSystem -eq "10.0.10514" -or $operatingSystem -eq "10.0.10586" -or $operatingSystem -eq "10.0.11082"){
                         $mode = "2016"
                    }
                    else {
                        if($operatingSystem -eq "10.0.14342") {
                             $mode = "1014342"
                        }
                        else {
                            Write-Output "The operating system could not be determined... terminating..."
                            Stop-Script
                        }
                    }
                }
            }
        }
    }
    return $mode
}

function Write-InFile ($buffer, $chain) {
    [io.file]::WriteAllText($buffer, $chain) | Out-Null
}

function Call-MemoryWalker ($memoryWalker, $file, $fullScriptPath, $symbols) {
    $tab = &$memoryWalker -pn winmine.exe -y $symbols -c "`$`$<$fullScriptPath;qd"     
    return $tab
}

function White-Rabbit {
    Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator "" -ForegroundColor Yellow
}

function Stop-Script () {   
    Begin{
        "Script terminating..." 
        Write-Output "================================================================================================"
    }
    Process{                  
        Exit
    }
}

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
    "1014342" {
            $memoryWalker = "$scriptPath\debugger\x64\cdb.exe"
        }
}

&"$scriptPath\winmine.exe"

Clear-Host
Write-Output "================================================================================================"
White-Rabbit

if($Flag){
    $howToWin = 1
}
else {
    if($Demine){
        $howToWin = 2
    }        
    else {
        if($Reveal){
            $howToWin = 3
        }        
        else {
            if($Explose){
                $howToWin = 4
            }        
            else {
                if($UniversalResponse){
                    $howToWin = 5
                }        
                else {
                    if($Clean){
                        $howToWin = 6
                    }        
                    else {
                        $howToWin = Read-Host 'How do you want to win?
1) Flag the bombs!
2) Demine the bombs!
3) Reveal the bombs!
4) Explose the bombs!
5) 42
6) Clean the board :-)
0) Exit

Enter menu number and press <ENTER>'
                    }
                }
            }
        }
    }
}
switch ($howToWin){
    "1" {$howToWin = '8e'}
    "2" {$howToWin = '0e'}
    "3" {$howToWin = '8a'}
    "4" {$howToWin = 'cc'}
    "5" {$howToWin = '42'}  
    "6" {$howToWin = '40'} 
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Exiting...";Stop-Script}
}


$chain = "db winmine!xBoxMac L1"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"L1") + 3
$gridWidth = [Convert]::ToInt32($tabFA[$fi], 16)

# max size is 30 because stored in memory 32 bytes max (30 + "borders")

$chain = "db winmine!yBoxMac L1"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $memoryWalker $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"L1") + 3
$gridHeight = [Convert]::ToInt32($tabFA[$fi], 16)

Write-Output "Working on the field...($gridWidth x $gridHeight)`n"

$i = 0
$j = ""
while ($i -lt (($gridHeight*2)+3)) {
    if($j -eq 0) {
        $chain = "db winmine!rgBlk"        
    }
    else {
        $chain = "db winmine!rgBlk$j"
    }
        
    Write-InFile $buffer "$chain"
    $tabSystem = Call-MemoryWalker $memoryWalker $file $fullScriptPath $symbols    
    $tabFA = ($tabSystem -split ' ')      
    $fi = [array]::indexof($tabFA,"cdb:") + 8
    $address = $tabFA[$fi]
    $c = 10
    $toFill = ""
    while ($c -lt 26){
        $fi = [array]::indexof($tabFA,"cdb:") + $c
        if($c -eq 17){
            $split = $tabFA[$fi] -split '-'
            $toFill += " $($split[0])"
            $toFill += " $($split[1])"
        }
        else {
            $toFill += " $($tabFA[$fi])" 
        }   
        $c++     
    }                   
    $toFill = $toFill -replace ("8f", $howToWin) # empty !
    $chain = "f $address L10 $toFill"   
    Write-InFile $buffer "$chain"
    $tabSystem = Call-MemoryWalker $memoryWalker $file $fullScriptPath $symbols 
    $i++
    $j += "+10"
}
Write-Output "`nThe field has been secured!"

Stop-Script