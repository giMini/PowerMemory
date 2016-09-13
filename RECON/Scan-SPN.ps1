#requires -version 2
<#
.SYNOPSIS
  Scan services in a windows domain with SPN

.PARAMETER [optional] domain
    The domain to query

.OUTPUTS
  Console outputs

.NOTES
  Version:        0.1
  Author:         Pierre-Alexandre Braeken
  Creation Date:  2015-11-02
  Purpose/Change: Initial script development
  
.EXAMPLE
  .\Scan-SPN.ps1
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param(
    [String]$SPNScript
    )

Set-StrictMode -version 2


$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptParentPath + "\" + $launchDate

$loggingFunctions = "$scriptParentPath\RWMC\logging\Logging.ps1"
$utilsFunctions = "$scriptParentPath\RWMC\utilities\Utils.ps1"
$domainFunctions = "$scriptParentPath\RWMC\utilities\Domain.ps1"
$vipFunctions = "$scriptParentPath\RWMC\utilities\VIP.ps1"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script version will be write in the log file
$scriptName = "Scan-SPN"
$scriptVersion = "0.1"

#Log File Info

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "$scriptName" + "_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

#-----------------------------------------------------------[Functions]------------------------------------------------------------

. $loggingFunctions
. $utilsFunctions
. $domainFunctions
. $vipFunctions


#-----------------------------------------------------------[Execution]------------------------------------------------------------
 
Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter
cls
Write-Output "================================================================================================"
White-Rabbit
Write-Output "================================================================================================"

$type = "LDAP"
$domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname
$domainDistinguishedName = ([ADSI]'').distinguishedName
$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name 
$forestDomain = Get-ForestDomain $currentDomain
$domains = $forestDomain.forest.Domains

$remoteLocalFile = $SPNScript 

$remoteLocalFile = Read-Host 'Which SPN type do you want to locate?
1) CIFS
2) DNS
3) DFSR
4) MSSQL
5) LDAP
6) Microsoft Virtual Console Service
7) MSClusterVirtualServer
8) SAP
9) SIP
10) POP
11) TERMSRV
12) WSMAN
13) tapinego
14) HTTP
15) GC
16) FTP
0) Exit

Enter menu number and press <ENTER>' 

switch ($remoteLocalFile){
    "1" {$type = "CIFS"}
    "2" {$type = "DNS"}
    "3" {$type = "DFSR"}
    "4" {$type = "MSSQL"}
    "5" {$type = "LDAP"}
    "6" {$type = "Microsoft Virtual Console Service"}
    "7" {$type = "MSClusterVirtualServer"}
    "8" {$type = "SAP"}
    "9" {$type = "SIP"}
    "10" {$type = "POP"}
    "11" {$type = "TERMSRV"}
    "12" {$type = "WSMAN"}
    "13" {$type = "tapinego"}
    "14" {$type = "HTTP"}
    "15" {$type = "GC"}
    "16" {$type = "FTP"}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... trying to locate LDAP SPN records"}
}

foreach($domain in $domains) {  
    Scan-ServicePrincipalName -Type $type -Domain $domain
}

Read-Host "Press any key to terminate"