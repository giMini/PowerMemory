# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function Name 'Import-Modules' - Import module if not loaded
# ________________________________________________________________________
function Import-Modules {
    Begin{
        Write-Log -streamWriter $global:streamWriter -infoToLog "Active Directory module import"
    }
    Process{
        Try{
            if(!(get-module activedirectory)) {
		        Write-Host "Importing module activedirectory..." -ForegroundColor white -BackgroundColor Blue       
		        Import-Module activedirectory 
	        }  
        }
    
        Catch{
            Write-Error -streamWriter $global:streamWriter -errorCaught $_.Exception -forceExit $True
            Break
        }
    }  
    End{
        If($?){
            Write-Log -streamWriter $global:streamWriter -infoToLog "Completed Successfully."
            Write-Log -streamWriter $global:streamWriter -infoToLog " "
        }
    }         
}
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function Name 'Get-DistinguishedNameFromFQDN' - Convert domain name into distinguished name
# ________________________________________________________________________
function Get-DistinguishedNameFromFQDN {
	param([string]$domainFullQualifiedDomain=(throw "You must specify the domain Full Qualified Name !"))
    Begin{
        Write-Verbose "Get distinguished name from domain name"
    }
    Process{
        Try{
            $distinguishedName = "" 
	        $obj = $domainFullQualifiedDomain.Replace(',','\,').Split('/')
	        $obj[0].split(".") | ForEach-Object { $distinguishedName += ",DC=" + $_}
	        $distinguishedName = $distinguishedName.Substring(1)
            Write-Verbose "Domain name is $domainFullQualifiedDomain, distinguished name is $distinguishedName"
	        return $distinguishedName
        }    
        Catch{
            Write-Error -streamWriter $global:streamWriter -errorCaught $_.Exception -forceExit $True
            Break
        }
    }  
    End{
        If($?){
            Write-Verbose "Completed Successfully."            
        }
    }  	
}

function Get-ForestDomain($currentDomain) {   
    $forest = Get-ADForest -Identity $currentDomain
    $domain = Get-ADDomain -Identity $currentDomain    

    # Retrieve in an object the forest and domain user context
    $forestDomain = New-Object PSObject -Property @{        
		forest = $forest
	    domain = $domain
	}  
	
    return $forestDomain
}

function Get-FSMOPlacement($domainName) {   
    #Import-Modules                         
    
    $forestDomain = Get-ForestDomain $domainName

    $forest = $forestDomain.forest
    $domain = $forestDomain.domain

    #-ForegroundColor white -BackgroundColor Blue   

	$fsmoPlacement = New-Object PSObject -Property @{        
		"SchemaMaster" = $forest.SchemaMaster
		"DomainNamingMaster" = $forest.DomainNamingMaster
		"RIDMaster" = $domain.RIDMaster
		"PDCEmulator" = $domain.PDCEmulator		
		"InfrastructureMaster" = $domain.InfrastructureMaster		
	}    

	return $fsmoPlacement            
 }

function Get-AdInfos($currentDomain) {          
    #Import-Modules     			                    

    $forestDomain = Get-ForestDomain $currentDomain

    $forest = $forestDomain.forest
    $domain = $forestDomain.domain

    Write-Host $forest

    #-ForegroundColor white -BackgroundColor Blue       

	$adInfos = New-Object PSObject -Property @{   
        "ForestName" = $forest.Name     
        "RootDomain" = $forest.RootDomain
		"ForestLevel" = $forest.ForestMode
    	"Domainlevel" = $domain.DomainMode
        "Sites" = $forest.Sites
        "Domains" = $forest.Domains
        "GlobalCatalogs" = $forest.GlobalCatalogs        
        "RODC" = $domain.ReadOnlyReplicaDirectoryServers
        "DC" = $domain.ReplicaDirectoryServers
        "SPNSuffixes" = $domain.SPNSuffixes
        "UPNSuffixes" = $domain.UPNSuffixes
        "ApplicationPartitions" = $domain.ApplicationPartitions
        "PartitionsContainer" = $domain.PartitionsContainer
        "CrossForestReferences" = $domain.CrossForestReferences
	}    

	return $adInfos            
 }
<#
function Get-DistinguishedNameFromFQDN {
	param([string]$domainFullQualifiedDomain=(throw "Vous devez indiquer le Full Qualified Name du Domaine !"))
	$distinguishedName = "" 
	$obj = $domainFullQualifiedDomain.Replace(',','\,').Split('/')
	$obj[0].split(".") | ForEach-Object { $distinguishedName += ",DC=" + $_}
	$distinguishedName = $distinguishedName.Substring(1)
	return $distinguishedName
}#>
function Set-LDAPQuery ($LDAPObject, $filter, $propertiesToLoad, $scope, $pageSize) {
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
    #$LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName))
    $LDAPObject.Filter = $filter
    foreach($property in $propertiesToLoad){
        $LDAPObject.PropertiesToLoad.Add($property) | Out-Null
    }
    $LDAPObject.SearchScope = $scope
    $LDAPObject.PageSize = $pageSize
    return $LDAPObject 
}

function Get-Nesting ($group, $parents) { 
    foreach ($member in $global:groupMembers[$group]) {         
        foreach ($parent in $parents) { 
            if ($member -eq $parent) {                 
                Write-Host "Circular nested group found $parent"
                Write-Log -streamWriter $global:streamWriter -infoToLog "Circular nested group found $parent"
                $global:circularGroupNumber = $global:circularGroupNumber + 1                 
                Return 
            } 
        }                   
        if ($global:groupMembers.ContainsKey($member)) {
            $parrentArrayRecurse = $parents 
            Get-Nesting $member ($parrentArrayRecurse += $member) 
        }
 
    } 
} 

function Get-DomainsColor {
    if($ADForest -ne "") {
        $forest = Get-ADForest -Identity $ADForest
    }
    else {
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name
        $forest = Get-ADForest -Identity $currentDomain
          
    }    	
    return $forest
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
        $Type,
        [String]
        [ValidateNotNullOrEmpty()]
        $Domain
    )      
    
   # $domainDistinguishedName = ([ADSI]'').distinguishedName    # (Get-ADDomain).DistinguishedName    
   # $domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname
    
    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$Domain" ))
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
