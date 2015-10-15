Set-StrictMode -Version 2.0

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate

$loggingFunctions = "$scriptPath\logging\Logging.ps1"

$scriptName = [System.IO.Path]::GetFileName($scriptFile)
$scriptVersion = "0.2"

if(!(Test-Path $logDirectoryPath)) {
    #New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

#$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

$type = "LDAP"

function Stop-Script () {   
    Begin{
        Write-Output "--- Script terminating ---"
    }
    Process{        
        "Script terminating..." 
        Write-Output "================================================================================================"        
        Exit
    }
}

function Set-LDAPQuery {
<#
.SYNOPSIS
    Set a LDAP query
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None 

.DESCRIPTION
    Set-LDAPQuery allows for the configuration of a LDAP query. The output of this function is an LDAP object. 

.PARAMETER LDAPObject
    DirectorySearcher parameter that let you specify an LDAP object bound on a domain controller and a domain distinguished name.

.PARAMETER filter

.PARAMETER propertiesToLoad

.PARAMETER scope

.PARAMETER pageSize

.EXAMPLE
    C:\PS> Set-LDAPQuery $LDAPObject "(servicePrincipalName=MSSQL*)" "name","distinguishedName,objectCategory,servicePrincipalName" "subtree" "1000"
#>
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        $LDAPObject, 
        $filter, 
        $propertiesToLoad, 
        $scope, 
        $pageSize                
    )    
    $LDAPObject.Filter = $filter
    foreach($property in $propertiesToLoad){
        $LDAPObject.PropertiesToLoad.Add($property) | Out-Null
    }
    $LDAPObject.SearchScope = $scope
    $LDAPObject.PageSize = $pageSize
    return $LDAPObject 
}

function Scan-ServicePrincipalName {
<#
.SYNOPSIS
    LDAP queries to locate service principal name in a domain
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION
    Scan-ServicePrincipalName allows to locate service principal name in a domain. The output of this function is a list of SPNs of the type selected.

.PARAMETER Type
    Int parameter that let you specify the SPN type you want to query in the domain.

.EXAMPLE
    C:\PS> Scan-ServicePrincipalName -Type $type
#>
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Type
    )      
    
    $domainDistinguishedName = ([ADSI]'').distinguishedName    # (Get-ADDomain).DistinguishedName    
    $domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname

    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
    $filter = "(servicePrincipalName=$Type*)" 
    $propertiesToLoad = "name","distinguishedName,objectCategory,servicePrincipalName"
    $scope = "subtree" 
    $pageSize = 1000 
    $LDAPQuery = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
    $results = $LDAPQuery.FindAll() 
    
    "There are " + $results.count + " SPNs"
    
    foreach($result in $results) {
        $userEntry = $result.GetDirectoryEntry()
        Write-Output "Object Name = " $userEntry.name
        Write-Output "DN      =      "  $userEntry.distinguishedName
        Write-Output "Object Cat. = "  $userEntry.objectCategory
        Write-Output "servicePrincipalNames"
        $i=1
        foreach($SPN in $userEntry.servicePrincipalName) {
            Write-Output "SPN($i)=$SPN"
            $i++
        }
        Write-Output ""
    }         
}

cls
Write-Output "================================================================================================"        
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

Scan-ServicePrincipalName -Type $type