<#
.SYNOPSIS
  For all SPN account in the connected forest, create TGS in memory computer

.DESCRIPTION 

.PARAMETER [optional] domain
    GCName the global catalog to query

.OUTPUTS
  Console outputs + log file + visio of the current forest if selected

.NOTES

  
.EXAMPLE
  .\Create-TGSInMemory
#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
  [Parameter(Mandatory=$False)] [string]$Filter
)

Add-Type -AssemblyName System.IdentityModel

$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$GC += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain  
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = "LDAP://" + $GC
$searcher.PageSize = 1000
$searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
$searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
$searcher.SearchScope = "Subtree"

$results = $searcher.FindAll()
        
foreach ($result in $results) {
    foreach ($spn in $result.Properties["serviceprincipalname"]) {
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "$($spn.ToString())"
    }
}