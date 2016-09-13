#requires -version 2
<#
.SYNOPSIS
  Audit a Windows Active Directory domain

.PARAMETER [optional] domain
    The domain to query

.OUTPUTS
  Console outputs + log file + visio of the current forest if selected

.NOTES
  Version:        0.1
  Author:         Pierre-Alexandre Braeken
  Creation Date:  2015-05-11
  Purpose/Change: Initial script development
  Tested with Visio 2007
  
.EXAMPLE
  .\Get-ActiveDirectoryInfo contoso.com
#>

#VisRowIndices Enumeration (Visio) https://msdn.microsoft.com/en-us/library/office/ff765539.aspx
#VisCellIndices Enumeration (Visio) https://msdn.microsoft.com/en-us/library/office/ff767991.aspx
Param(
[parameter(ParameterSetName="ADForest",Mandatory=$False)] 
[string]$ADForest=""
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set-StrictMode -version 2

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

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
$scriptName = "Get-ActiveDirectoryInfo"
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

$adminCountInformation = Read-Host 'Do you want to assess admin accounts and groups?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'

switch ($adminCountInformation){
    "1" {$adminCountInformation = 1}
    "2" {$adminCountInformation = 0}
    "Yes" {$adminCountInformation = 1}
    "No" {$adminCountInformation = 0}
    "Y" {$adminCountInformation = 1}
    "N" {$adminCountInformation = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... admin accounts and groups will not be assessed";$assessGPP = "0"}
}

$assessGPPconnectedForest = Read-Host 'Do you want to assess Goup Policy Preferences in connected forest?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($assessGPPconnectedForest){
    "1" {$assessGPPconnectedForest = 1}
    "2" {$assessGPPconnectedForest = 0}
    "Yes" {$assessGPPconnectedForest = 1}
    "No" {$assessGPPconnectedForest = 0}
    "Y" {$assessGPPconnectedForest = 1}
    "N" {$assessGPPconnectedForest = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Goup Policy Preferences will not be assessed";$assessGPPconnectedForest = "0"}
}

$assessforestShare = Read-Host 'Do you want to assess forests shares?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($assessForestShare){
    "1" {$assessForestShare = 1}
    "2" {$assessForestShare = 0}
    "Yes" {$assessForestShare = 1}
    "No" {$assessForestShare = 0}
    "Y" {$assessForestShare = 1}
    "N" {$assessForestShare = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... forests shares will not be assessed";$assessforestShare = "0"}
}

$assessGroupNesting = Read-Host 'Do you want to assess Group nesting (to found circular nesting)?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($assessGroupNesting){
    "1" {$assessGroupNesting = 1}
    "2" {$assessGroupNesting = 0}
    "Yes" {$assessGroupNesting = 1}
    "No" {$assessGroupNesting = 0}
    "Y" {$assessGroupNesting = 1}
    "N" {$assessGroupNesting = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... group nesting will not be assessed";$assessGroupNesting = "0"}
}

$assessDrawTopology = Read-Host 'Do you want to draw the topology of your forest?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($assessDrawTopology){
    "1" {$assessDrawTopology = 1}
    "2" {$assessDrawTopology = 0}
    "Yes" {$assessDrawTopology = 1}
    "No" {$assessDrawTopology = 0}
    "Y" {$assessDrawTopology = 1}
    "N" {$assessDrawTopology = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... topology will not be drawn";$assessDrawTopology = "0"}
}

Import-Modules

if($ADForest -eq "") {
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name    
    $ADForest = ""
}
else {
    $currentDomain = $ADForest
}

$domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname

# Get some informations about AD
$forestDomain = Get-ForestDomain $currentDomain

$sites = $forestDomain.forest.Sites
$domains = $forestDomain.forest.Domains
$applicationPartitions = $forestDomain.forest.ApplicationPartitions
$applicationPartitions = $forestDomain.forest.PartitionsContainer
$crossForestReferences = $forestDomain.forest.CrossForestReferences
$sPNSuffixes = $forestDomain.forest.SPNSuffixes
$uPNSuffixes = $forestDomain.forest.UPNSuffixes

#$adInfos = Get-AdInfos $currentDomain

Write-Log -streamWriter $global:streamWriter -infoToLog "`nFunctional levels - ad infos"
Write-Log -streamWriter $global:streamWriter -infoToLog "==============================="
Write-Log -streamWriter $global:streamWriter -infoToLog "Forest Name: $($forestDomain.forest.Name) - Root domain: $($forestDomain.forest.RootDomain)"
Write-Log -streamWriter $global:streamWriter -infoToLog "Forest Level: $($forestDomain.forest.ForestMode)"

Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nSites"
Write-Log -streamWriter $global:streamWriter -infoToLog "=========="
foreach($site in $sites) {             
    Write-Log -streamWriter $global:streamWriter -infoToLog "$site"
}
Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nDomains"
Write-Log -streamWriter $global:streamWriter -infoToLog "============"
foreach($domain in $domains) {             
    Write-Log -streamWriter $global:streamWriter -infoToLog "$domain"
}

foreach($domain in $domains) {  
    $groupsFiltered = @()
    $distinguishedName = ""
    $members = @()
    $global:groupMembers = @{}
    $global:circularGroupNumber = 0 
    $domainObject = ""
    $domainObject = Get-ADDomain -Identity $domain             
        
    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nDomain : $domain $($domainObject.NetBIOSName)"

    Write-Log -streamWriter $global:streamWriter -infoToLog "Domain Level: $($domainObject.DomainMode)"

    # Get FSMO Roles placement in AD
    $fsmoPlacement = ""
    $fsmoPlacement = Get-FSMOPlacement $domain
    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nFSMO Roles"
    Write-Log -streamWriter $global:streamWriter -infoToLog "==============="
    Write-Log -streamWriter $global:streamWriter -infoToLog "Schema Master: $($fsmoPlacement.SchemaMaster)"
    Write-Log -streamWriter $global:streamWriter -infoToLog "Domain Naming Master: $($fsmoPlacement.DomainNamingMaster)"
    Write-Log -streamWriter $global:streamWriter -infoToLog "PDC Emulator: $($fsmoPlacement.PDCEmulator)"
    Write-Log -streamWriter $global:streamWriter -infoToLog "RID Master: $($fsmoPlacement.RIDMaster)"
    Write-Log -streamWriter $global:streamWriter -infoToLog "Infrastructure Master: $($fsmoPlacement.InfrastructureMaster)"

    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nReplica Directory Servers"     
    Write-Log -streamWriter $global:streamWriter -infoToLog "=============================="
    $replicaDirectoryServers = $domainObject.ReplicaDirectoryServers
    foreach($replica in $replicaDirectoryServers) {        
        Write-Log -streamWriter $global:streamWriter -infoToLog "$replica"
    }
    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nRead Only Replica Directory Servers"
    Write-Log -streamWriter $global:streamWriter -infoToLog "========================================"
    $readOnlyReplicaDirectoryServers = $domainObject.ReadOnlyReplicaDirectoryServers
    foreach($rodc in $readOnlyReplicaDirectoryServers) {        
        Write-Log -streamWriter $global:streamWriter -infoToLog "$rodc"
    }

    $domainDistinguishedName = Get-DistinguishedNameFromFQDN ($domain) 

    if($adminCountInformation -eq 1) {   

        $search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://"+ $domainDistinguishedName ))
        $search.Filter = "(objectCategory=group)" 
        $search.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $search.SearchScope = "subtree" 
        $search.PageSize = 1000 
        $groupsFiltered = $search.FindAll() 
        $groupCount = $groupsFiltered.Count
        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tGroups count: $groupCount"
        $domainDistinguishedName = Get-DistinguishedNameFromFQDN ($domain) 
        $search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://"+ $domainDistinguishedName ))
        $search.Filter = "(objectCategory=user)" 
        $search.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $search.SearchScope = "subtree" 
        $search.PageSize = 1000 
        $usersFiltered = $search.FindAll() 
        $userCount = $usersFiltered.Count
        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tUsers count: $userCount"    

        $adminCounts = ""        

        #$domainControllerToQuery[0]
        Write-Log -streamWriter $global:streamWriter -infoToLog "`r`n`tListing users with AdminCount = 1"
        Write-Log -streamWriter $global:streamWriter -infoToLog "`t---------------------------------`n"
        #$adminCounts = Get-ADuser -LDAPFilter "(adminCount=1)" -Server $domainControllerToQuery[0] -Properties Name, PasswordLastSet, Enabled, PasswordNeverExpires | Select-Object Name, PasswordLastSet, Enabled, PasswordNeverExpires
        #$adminCounts.Count

        #$domain = "contoso.com"

        $domainDistinguishedName = Get-DistinguishedNameFromFQDN ($domain) 

        Write-Progress -Activity "LDAP (&(objectCategory=user)(admincount=1)) query will be executed on LDAP://$domainControllerToQuery/$domainDistinguishedName" -status "Running..." -id 1  
        $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
        $filter = "(&(objectCategory=user)(admincount=1))" 
        $propertiesToLoad = "distinguishedName","objectsid"
        $scope = "subtree" 
        $pageSize = 1000 
        $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
        $adminCounts = $LDAPQuery.FindAll() 
		
        if($adminCounts)
        {
	        $adminCounts = $adminCounts | Sort Name
	        If($adminCounts -is [array])
	        {
		        [int]$AdminsCount = $adminCounts.Count
	        }
	        Else
	        {
		        [int]$adminsCount = 1
	        }
	        [string]$adminsCountStr = "{0:N0}" -f $AdminsCount
			
	        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tusers with AdminCount=1 ($($AdminsCountStr) members):"	
            $errorColor = 0
	        foreach($admin in $adminCounts) {
                $errorMessage = ""
                $distinguishedName = $admin.Properties.distinguishedname    
                # https://technet.microsoft.com/en-us/library/ee198831.aspx
                # userAccountControl
                # Password Never Expires
                # Integer: ADS_UF_DONT_EXPIRE_PASSWD flag
                # Value: 0x10000
		        # $user = Get-ADuser -Identity "$distinguishedName" -server $domain -Properties Name, PasswordLastSet, Enabled, PasswordNeverExpires | Select-Object Name, PasswordLastSet, Enabled, PasswordNeverExpires        
                $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
                $filter = "(&(distinguishedName=$distinguishedName))" 
                $propertiesToLoad = "Name","pwdLastSet","userAccountControl","objectSid"
                $scope = "subtree" 
                $pageSize = 1000 
                $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
                $user = $LDAPQuery.findOne()
		        $xRow++
				
		        if($user) {
			        $userName =  $user.Properties.name            
			        if($user.Properties.pwdlastset -eq $Null) {
				        $userPwdLastSet = "No Date Set" #-ForegroundColor Red
                        $errorColor = 1
			        }
			        else {
                        $datePwdLastSet = [datetime]::fromfiletime($user.Properties.pwdlastset[0])
				        $userPwdLastSet = $datePwdLastSet #-ForegroundColor Green
			        }
			        If($user.Properties.useraccountcontrol -eq 65536) {
				        $expiration =  "Never expire"
                        $errorColor = 1
			        }
                    else {
			            $expiration =  $user.Properties.useraccountcontrol
                    }

			        if($user.Properties.useraccountcontrol -eq 514) {
				        $userEnable = "Disabled" #-ForegroundColor Red
                        $errorColor = 1
			        }
                    else {
			            $userEnable = "Enabled" #-ForegroundColor Green	            
                    }
		        }
		        else
		        {
                    $byte = $admin.Properties.objectsid    #$user.Properties.objectsid  
                    try {                
                        $stringSID = (New-Object System.Security.Principal.SecurityIdentifier($byte[0],0)).Value
                        $errorColor = 1
                    }
                    catch{               
                        Write-Log -streamWriter $global:streamWriter -infoToLog $_.Exception #-ForegroundColor red
                    }            
                    $userName = $distinguishedName          
                    $userEnable = ""                        
			        $errorMessage =  "! user not get through LDAP Request SID ! is $stringSID"  #-ForegroundColor Red			            
		        }
                if ($errorColor -eq 1 ) {
                    Write-Log -streamWriter $global:streamWriter -infoToLog "$userName $userPwdLastSet $userEnable $expiration $errorMessage" #-ForegroundColor Red
                }
                else {
                    Write-Log -streamWriter $global:streamWriter -infoToLog "$userName $userPwdLastSet $userEnable $expiration $errorMessage"
                }
                $errorColor = 0
	        }	    
        }
        elseif(!$?) {
	        Write-Log -streamWriter $global:streamWriter -infoToLog "Unable to retrieve users with AdminCount=1"
        }
        else {
	        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tusers with AdminCount=1: "
	        Write-Log -streamWriter $global:streamWriter -infoToLog "<None>"
        }

        Write-Log -streamWriter $global:streamWriter -infoToLog "`n`n`tListing groups with AdminCount = 1"
        Write-Log -streamWriter $global:streamWriter -infoToLog "`t---------------------------------`n"

        Write-Progress -Activity "LDAP (&(objectCategory=group)(admincount=1)) query will be executed on LDAP://$domainControllerToQuery/$domainDistinguishedName" -status "Running..." -id 1  
        $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
        $filter = "(&(objectCategory=group)(admincount=1))" 
        $propertiesToLoad = "distinguishedName","objectsid"
        $scope = "subtree" 
        $pageSize = 1000 
        $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
        $adminCounts = $LDAPQuery.FindAll() 

        if($adminCounts) {
	        $adminCounts = $adminCounts | Sort Name
	        if($adminCounts -is [array]) {
		        [int]$AdminsCount = $adminCounts.Count
	        }
	        else {
		        [int]$adminsCount = 1
	        }
	        [string]$adminsCountStr = "{0:N0}" -f $AdminsCount
			
	        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tGroups with AdminCount=1 ($($AdminsCountStr) members):"	
    
            $errorColor = 0
	        foreach($admin in $adminCounts) {
                $distinguishedName = $admin.Properties.distinguishedname
        
		        #$user = Get-ADGroup -Identity "$distinguishedName" -Properties Name, PasswordLastSet, Enabled, PasswordNeverExpires | Select-Object Name, PasswordLastSet, Enabled, PasswordNeverExpires
                $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
                $filter = "(&(distinguishedName=$distinguishedName))" 
                $propertiesToLoad = "Name","userAccountControl","objectSid"
                $scope = "subtree" 
                $pageSize = 1000 
                $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
                $user = $LDAPQuery.findOne()
		        $xRow++
				
		        if($user) {
			        $userName = $user.Properties.name			
			        if($user.Properties.useraccountcontrol -eq 65536) {
				        $expiration =  "Never expire"
                        $errorColor = 1
			        }
                    else {
			             $expiration =  $user.Properties.useraccountcontrol
                    }
			        if($user.Properties.useraccountcontrol -eq 514) {
				        $userEnable = "Disabled"
                        $errorColor = 1
			        }
                    else {
			            $userEnable = "Enabled"
                    }
		        }
		        else {
                    $byte = $admin.Properties.objectSID
                    $stringSID = (New-Object System.Security.Principal.SecurityIdentifier($byte[0],0)).Value
                    $errorMessage =  $stringSID
			        #Write-Output "Unknown:" $admin.Properties.objectSID  -ForegroundColor Red			
		        }
                if ($errorColor -eq 1 ) {
                    Write-Log -streamWriter $global:streamWriter -infoToLog "$userName $userPwdLastSet $userEnable $expiration $errorMessage" #-ForegroundColor Red
                }
                else {
                    Write-Log -streamWriter $global:streamWriter -infoToLog "$userName $userPwdLastSet $userEnable $expiration $errorMessage"
                }
                $errorColor = 0
	        }			
        }
        elseif(!$?) {
	        Write-Log -streamWriter $global:streamWriter -infoToLog "Unable to retrieve users with AdminCount=1"
        }
        else {
	        Write-Log -streamWriter $global:streamWriter -infoToLog "`t`tGroups with AdminCount=1: "
	        Write-Log -streamWriter $global:streamWriter -infoToLog "<None>"
        }
    }


    Write-Log -streamWriter $global:streamWriter -infoToLog "`n`n`t`tListing Stale computers`n"
    Write-Log -streamWriter $global:streamWriter -infoToLog "`t---------------------------------`n"

    Write-Progress -Activity "LDAP (&(objectCategory=computer)(admincount=1)) query will be executed on LDAP://$domainControllerToQuery/$domainDistinguishedName" -status "Running..." -id 1  
    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
    $filter = "(&(objectCategory=computer)(admincount=1))" 
    $propertiesToLoad = "distinguishedName","objectSID"
    $scope = "subtree" 
    $pageSize = 1000 
    $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
    $adminCounts = $LDAPQuery.FindAll() 


    # The Following Machines and t Contacted the Domain in the Past 90 Days [To do]
    $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
    $filter = "(&(objectclass=computer))" 
    $propertiesToLoad = "dNSHostName","pwdLastSet"
    $scope = "subtree" 
    $pageSize = 1000 
    $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize
    $staleComputer = $LDAPQuery.FindAll() 

    foreach ($sc in $staleComputer) {    
        $dnsHostName = $sc.Properties.dnshostname
        $datePwdLastSet = [datetime]::fromfiletime($sc.Properties.pwdlastset[0])
        #Write-Output "$datePwdLastSet"
    }    
    
    $propertiesToLoad=""
    Try{
        $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))    
        $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"         
        $propertiesToLoad = "Name","pwdLastSet","userAccountControl","objectsid"
        $scope = "subtree" 
        $pageSize = 1000 
        $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize    
        $users = $LDAPQuery.FindAll() 
        Write-Log -streamWriter $global:streamWriter -infoToLog "`n`n`t`tListing potential empty accounts password`n"  
        Write-Log -streamWriter $global:streamWriter -infoToLog "`t---------------------------------`n"
        foreach($user in $users) {
            $byte = $user.Properties.objectsid
            $emptyAccount = "$($user.Properties.name) (" + $((New-Object System.Security.Principal.SecurityIdentifier($byte[0],0)).Value) + ")"            
            Write-Log -streamWriter $global:streamWriter -infoToLog "$emptyAccount)"           
        }
        Write-Log -streamWriter $global:streamWriter -infoToLog "----------------------------------------------------------------------------------------------"
    }
    Catch{
        Write-Host $_.Exception
        Break
    }

    # GPP assessment
    if($assessGPP -eq 1) {                
        <#
        $filePath = "\\$domain\SYSVOL\$domain\Policies"    
        $fileName = "groups.xml"
        $nonSecureFilePath = Get-ChildItem -Recurse -Force $filePath -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "*$fileName*") } | Select-Object Name,Directory
        if($nonSecureFilePath -ne $Null) {
            Write-Log -streamWriter $global:streamWriter -infoToLog "`nA groups.xml file was founded !" #-ForegroundColor Red
            $directory = $nonSecureFilePath.Directory
            $nonSecureFileName = $nonSecureFilePath.Name

            $xmlPath = "$directory\$nonSecureFileName"
        
            $nodes = ( Select-Xml -Path $xmlPath -XPath / ).Node
            $nodes | ForEach-Object {
                $userNameGroups = $_.Groups.User.Properties.userName
                $cPassword = $_.Groups.User.Properties.cpassword
            }
            if($cPassword -ne $Null) {
                $decryptedPassword = Get-DecryptMyPassword -cPassword $cPassword
                Write-Log -streamWriter $global:streamWriter -infoToLog "A local password was founded ! $userNameGroups\$decryptedPassword" #-ForegroundColor Red
            }    
        }#>
    }
        
    # Test group nesting
    if($assessGroupNesting -eq 1) {
        Write-Progress -Activity "Group Nesting assessment" -status "Running..." -id 1  
        Write-Progress -Activity "Formating LDAP query for $domain" -status "Running..." -id 1      
        $domainDistinguishedName = Get-DistinguishedNameFromFQDN $domain
        $domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname

        Write-Progress -Activity "LDAP (objectCategory=group) query will be executed on LDAP://$domainControllerToQuery/$domainDistinguishedName" -status "Running..." -id 1  
        $search = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainControllerToQuery/"+ $domainDistinguishedName ))
        $search.Filter = "(objectCategory=group)" 
        $search.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $search.PropertiesToLoad.Add("member") | Out-Null 
        $search.SearchScope = "subtree" 
        $search.PageSize = 1000 
        <#
        $search.PageSize = 200 --> TotalSeconds      : 21,374693
        $search.PageSize = 1000 --> TotalSeconds      : 17,1569108
        #>
        $groupsFiltered = @()
        $distinguishedName = ""
        $members = @()
        $groupsFiltered = $search.FindAll() 
    
        Write-Progress -Activity "LDAP query executed, completing array with values" -status "Running..." -id 1  
        foreach ($group in $groupsFiltered) {             
            $distinguishedName = [string]$group.Properties.distinguishedname
            $members = @($group.properties.Item("member")) 
            $global:groupMembers.Add($distinguishedName, $members) 
        } 
        Write-Progress -Activity "Completed array, beginning test of nested group" -status "Running..." -id 1  
        $groups = $global:groupMembers.Keys 
        Write-Progress -Activity "Testing nested group" -status "Running..." -id 1  
        foreach ($group in $groups) {     
            Get-Nesting $group @($group) 
        } 
 
        Write-Output "Number of circular reference founded : $global:circularGroupNumber"
        Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nNumber of circular reference founded : $global:circularGroupNumber"  
    }  
}
if($assessGPPconnectedForest -eq 1) {   
    Write-Progress -Activity "Group Policy Preferences assessment" -status "Running..." -id 1  
    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nGroup Policy Preferences assessment"
    Write-Log -streamWriter $global:streamWriter -infoToLog "========================================"
    Write-Log -streamWriter $global:streamWriter -infoToLog $forestDomain.forest.Name 
    Write-Log -streamWriter $global:streamWriter -infoToLog "`t---------------------------------`n"   

    $domainNameConnectedForestAndDomains = @()
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name   
    $domainControllerToQuery = ([ADSI]"LDAP://RootDSE").dnshostname
    $currentDomainDistinguishedName = Get-DistinguishedNameFromFQDN $currentDomain     
    $systemContainer = [ADSI]"LDAP://CN=System,$currentDomainDistinguishedName"
    $systemCollection = $systemContainer.psbase.children    
    foreach ($system in $systemCollection){    
        if($system.objectClass -eq "trustedDomain"){                         
            $domainNameConnectedForestAndDomains += $system.cn     
        }
    }
    $forestDomain = Get-ForestDomain $currentDomain
    $forestDistinguishedName = Get-DistinguishedNameFromFQDN $forestDomain.forest.Name       
    $LDAPConnection = New-Object System.DirectoryServices.Protocols.LdapConnection(New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("$($forestDomain.forest.Name)", 389)) 
    $ok = 0
    try {
        $LDAPConnection.Bind()
        $ok = 0
    }
    catch {
        $ok = 1
        $_
    }
    if ($ok -eq 0) {
        $systemContainer = [ADSI]"LDAP://CN=System,$forestDistinguishedName"
        $systemCollection = $systemContainer.psbase.children    
        foreach ($system in $systemCollection){    
            Write-Progress $system
            if($system.objectClass -eq "trustedDomain"){                         
                $domainNameConnectedForestAndDomains += $system.cn      
                $selectedDomainDistinguishedName = Get-DistinguishedNameFromFQDN $system.cn            
                $LDAPConnectionSelectedDomain = New-Object System.DirectoryServices.Protocols.LdapConnection(New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("$($system.cn)", 389)) 
                $okSelectedDomain = 0
                try {
                    Write-Progress "Connection attempt to $($system.cn)"
                    $LDAPConnectionSelectedDomain.Bind()
                    $okSelectedDomain = 0
                }
                catch {
                    $okSelectedDomain = 1
                    $_
                }
                if ($okSelectedDomain -eq 0) {
                    $systemContainerSelectedDomain = [ADSI]"LDAP://CN=System,$selectedDomainDistinguishedName"
                    $systemCollectionSelectedDomain = $systemContainerSelectedDomain.psbase.children    
                    foreach ($systemSelectedDomain in $systemCollectionSelectedDomain){    
                        Write-Progress $systemSelectedDomain
                        if($systemSelectedDomain.objectClass -eq "trustedDomain"){                         
                            $domainNameConnectedForestAndDomains += $systemSelectedDomain.cn                     
                        }
                    }    
                } 
                else {
                    Write-Progress "Unable to LDAP to $($system.cn)"
                }
            }
        }
    }

    $domainNameConnectedForestAndDomains = $domainNameConnectedForestAndDomains | select -uniq

    foreach ($dncfad in $domainNameConnectedForestAndDomains) {
        Write-Log -streamWriter $global:streamWriter -infoToLog "---------------------------------`n"
        Write-Log -streamWriter $global:streamWriter -infoToLog $dncfad   
        Write-Log -streamWriter $global:streamWriter -infoToLog "*********************************"
        Write-Progress "Look domain $dncfad"
        $grouPolicyPreferences = Get-GPPPassword -Domain $dncfad    
    }
}
# Test write rights in all the forests connected
if($assessForestShare -eq 1) { 
    Write-Progress -Activity "Shares assessment" -status "Running..." -id 1  
    Write-Log -streamWriter $global:streamWriter -infoToLog "`r`nShares assessment"
    Write-Log -streamWriter $global:streamWriter -infoToLog "========================================"      
    $forestDistinguishedName = Get-DistinguishedNameFromFQDN $forestDomain.forest.Name    
    $defaultNamingContext = $([ADSI] "LDAP://RootDSE").Get("defaultNamingContext")
    $systemContainer = [ADSI]"LDAP://CN=System,$forestDistinguishedName"
    $systemCollection = $systemContainer.psbase.children

    foreach ($system in $systemCollection){
        if($system.objectClass -eq "trustedDomain"){                         
            $domainDistinguishedName = Get-DistinguishedNameFromFQDN $system.cn   
            Write-Log -streamWriter $global:streamWriter -infoToLog  $domainDistinguishedName             
            $LDAPObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://$domainDistinguishedName"))
            $filter = "(&(objectclass=computer))" 
            $propertiesToLoad = "dNSHostName"
            $scope = "subtree" 
            $pageSize = 1000 
            $LDAPQuery  = Set-LDAPQuery $LDAPObject $filter $propertiesToLoad $scope $pageSize        
            $forestComputers = $LDAPQuery.FindAll() 
            foreach ($forestComputer in $forestComputers) {              
                $dnsHostName = $forestComputer.Properties.dnshostname 
                if(Test-Connection -ComputerName $dnsHostName -Count 3 -Quiet){                
                    Write-Log -streamWriter $global:streamWriter -infoToLog  "$dnsHostName"
                    net view $dnsHostName | % { if($_.IndexOf(' Disk ') -gt 0){ 
                        $copied = ""
                        $share = $_.Split('  ')[0]  
                        if((Test-Path "\\$dnsHostName\$share" -ErrorAction SilentlyContinue)){ 
                            $copied = Copy-Item -Path "$scriptParentPath\RECON\WhiteRabbit.txt" -Destination "\\$dnsHostName\$share\WhiteRabbit.txt" -PassThru -ErrorAction silentlyContinue
                            if ($copied) { 
                                Write-Log -streamWriter $global:streamWriter -infoToLog  "Write access on \\$dnsHostName\$share" 
                                Remove-Item "\\$dnsHostName\$share\WhiteRabbit.txt"
                            }
                            else { Write-Log -streamWriter $global:streamWriter -infoToLog  "Copy failure \\$dnsHostName\$share"}
                        }            
                    } }
                }
            }        
        }
    }
}

# Draw topology of the current forest
if($assessDrawTopology -eq 1) {

    # Forest draw through ADSI queries
    #$axeX = 1.2
    #[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
    Write-Progress -Activity "Initializing Visio" -status "Running..." -id 1 
    $application = New-Object -ComObject Visio.Application
    $application.visible = $true
    $documents = $application.Documents
    $document = $documents.Add("Basic Network Diagram.vst")
    $pages = $application.ActiveDocument.Pages
    $page = $pages.Item(1)
    $page.name = "Topology"

    #load a background page
    $visBuiltInStencilBackgrounds = 0
    $visMSMetric = 1
    $visOpenHidden = 0x40
    #$backgrounds = $application.Documents.OpenEx($application.GetBuiltInStencilFile($visBuiltInStencilBackgrounds, $visMSMetric), $visOpenHidden)
    #$page.Drop($backgrounds.Masters.ItemU("Vertical Gradient"), 0.750656, 0.750656)

    $activeDirectoryStencil = $application.Documents.Add("$scriptParentPath\RWMC\misc\Active Directory.vss")

    $currentThread = [System.Threading.Thread]::CurrentThread
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    $siteBackground = $activeDirectoryStencil.Masters.Item("Site")
    $notGlobalCatalog = $activeDirectoryStencil.Masters.Item("Domain Controller")
    $globalCatalog = $activeDirectoryStencil.Masters.Item("Global Catalog")
    $IntraSiteconnector = $activeDirectoryStencil.Masters.Item("IntraSite DirectoryReplication")
    $InterSiteconnector = $activeDirectoryStencil.Masters.Item("InterSite DirectoryReplication")

    $siteDescription=@{}
    $siteSubnets=@{}
    $siteObjectClass=@{}
    $headArray=@{}
    $childArray=@{}
    $replicationArray=@{}
    $colorDomain=@{}

    $Configuration = $([ADSI] "LDAP://RootDSE").Get("ConfigurationNamingContext")
    $sitesContainer = [ADSI]"LDAP://CN=Sites,$Configuration"
    $sitesCollection = $sitesContainer.psbase.children

    $visSectionObject = 1
    $visRowFill = 3
    $visFillForegnd = 0    

    $forestDomain = Get-DomainsColor $ADForest
    $colorList = LoadColorList    
    $color = 0

    $nbSite = 2 
    
    Write-Progress -Activity "Collecting informations and drawing" -status "Running..." -id 1 

    foreach($domain in $forestDomain.Domains){            
        $colorDomain.$domain += $colorList[$color]
        $color=$color+1
    }        

    # Get the site names
    foreach ($site in $sitesCollection){
        $nbServer = 5
        if($site.objectClass -eq "site"){
            Write-Log -streamWriter $global:streamWriter -infoToLog "`r`n($([string]$site.cn)) ($($site.objectClass))"
            $siteContainer = $site.distinguishedName
            $siteCN = [string]$site.cn

            $nbServersite = $nbServer
            $shapeSite = $page.Drop($siteBackground,$nbSite,$nbServer)
            #$shapeSite.CellsSRC($visSectionObject,$visRowFill, $visFillForegnd).FormulaU="RGB(255,0,0)"
            $shapeSite.Text = $([string]$site.cn)

            $shapeSiteLayer = $page.Layers.Add($siteCN)
        
            $nbServer = $nbServer - 0.5

            $serversContainer = [ADSI]"LDAP://CN=Servers,$siteContainer"
            $serversCollection = $serversContainer.psbase.children
            foreach ($server in $serversCollection){
                $serverContainer = $server.distinguishedName
                $NTDSContainer = [ADSI]"LDAP://CN=NTDS Settings,$serverContainer"
                $headServer = $server.cn
                $headServerText = $server.dNSHostName
                # The following statement uses the SimpleMatch option to direct the -split operator to interpret the dot (.) delimiter literally.             
                $toCompare = $headServerText -split ".",2, "simplematch"
                $dnsDomainOfThisServer = $toCompare[1]
                if($NTDSContainer.options -eq 1) { 
                    Write-Log -streamWriter $global:streamWriter -infoToLog "$headServer is G_C"      
                    $headServerText=$headServerText            
                    $shapeHead = $page.Drop($GlobalCatalog,$nbSite,$nbServer)                                                           
                               
                }
                else {"$($server.cn) is NOT G_C"
                    "$headServer is not G_C"      
                    $headServerText=$headServerText  
                    $shapeHead = $page.Drop($notGlobalCatalog,$nbSite,$nbServer)                    
                }            
                Set-FormulaToShapeAndChildren $shapeHead "FillForegnd" $colorDomain.$dnsDomainOfThisServer            
                $shapeSiteLayer.Add($shapeHead, 1)
                $shpConn = $page.Drop($page.Application.ConnectorToolDataObject, 0, 0) 
                # Connect its Begin to the 'From' shape:
                $connectBegin = $shpConn.CellsU("BeginX").GlueTo($shapeHead.CellsU("PinX"))       
                # Connect its End to the 'To' shape:
                $connectEnd = $shpConn.CellsU("EndX").GlueTo($shapeSite.CellsU("PinX"))
                $headArray.Add("$headServer",$shapeHead) 
                Write-Log -streamWriter $global:streamWriter -infoToLog "From Server: "
                $NTDSCollection = $NTDSContainer.psbase.children             
                #$cellName = $shapeHead.CellsU("Char.Color")
                #$cellName.FormulaForceU = $colorDomain.$dnsDomainOfThisServer
                $shapeHead.Text = $headServerText               

                foreach ($NTDS in $NTDSCollection){                
                    if($ntds.objectClass -eq "nTDSConnection"){                            
                        $interSite = 0           
                        if($ntds.transportType -ne $null) {
                            $interSite = 1
                        }
                        $fromServer = $ntds.fromServer -split ",*..="                    
                        $childServer = $($fromServer[2])                                      
                        if ($childArray.$headServer.count -gt 0) {
                            $childArray.$headServer += ","
                        }
                        $childArray.$headServer += $childServer
                        # Replication link management
                        $keyLink = $headServer.trim() + $childServer.trim()                    
                        if($interSite -eq 1 ) {                        
                            $typeReplication = 1
                            $replicationArray.Add("$keyLink",1)
                            Write-Log -streamWriter $global:streamWriter -infoToLog "InterSite $($fromServer[2]) from site: $($fromServer[4])" #-BackgroundColor Green
                        }
                        else {                        
                            $typeReplication = 0
                            $replicationArray.Add("$keyLink",0) 
                            Write-Log -streamWriter $global:streamWriter -infoToLog "IntraSite $($fromServer[2]) from site: $($fromServer[4])"
                        }                                   
                    }
                }
                $nbServer--
            }
            $nbSite = $nbSite + 2.5
        } 
    }

    foreach($serverHead in $childArray.Keys) {    
        $toExplode = $childArray.item($serverHead)
        $listServerToConnect = $toExplode -split ","
        $serverHead = [string]$serverHead
        foreach($item in $listServerToConnect) {                
            $shapeToConnect = $headArray.item($serverHead)             
            $shapeToBeConnected = $headArray.item($item)
            $keyLinkRetrieve = $serverHead + $item
            $typeLink = $replicationArray.item($keyLinkRetrieve)   
            if($typeLink -eq 0) {
                $serverConnector = $IntraSiteconnector
            }
            else {
                $serverConnector = $InterSiteconnector
            }        
            $shapeToConnect.AutoConnect($shapeToBeConnected, 1, $serverConnector)
        }
    }

    # Group
    <# ne pas décommenter
    $vsoSelection = $page.CreateSelection(0) 
    $vsoSelection.Select($shapeSite, ($global:visDeselectAll + $global:visSelect))                 
    $shapeHead = $page.Drop($globalCatalog,$nbSite,$nbServer)
    $vsoSelection.Select($shapeHead, $global:visSelect) 
    $vsoSelection.Group()   
    #>

    #$visSectionObject = 1
    #$visRowPageLayout = 24
    #$visPLOPlaceStyle = 8



    $page.PageSheet.CellsSRC($visSectionObject, $visRowPageLayout, $visPLOPlaceStyle).FormulaForceU = "7" 
    $page.PageSheet.CellsSRC($visSectionObject, $visRowPageLayout, $visPLORouteStyle).FormulaForceU = "3" 
    $page.Layout() 

    $page.CenterDrawing()
    $page.ResizeToFitContents()
    # save the location of the current script
    #$dir = Split-Path $scriptpath
    $document.SaveAs(($logDirectoryPath + "\Active Directory.vsd"))
    $application.Quit()
}

End-Log -streamWriter $global:streamWriter