# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function Name 'Get-DistinguishedNameFromFQDN' - Convert domain name into distinguished name
# ________________________________________________________________________
function Get-DistinguishedNameFromFQDN {
	param([string]$domainFullQualifiedDomain=(throw "You must specify the domain Full Qualified Name !"))
    Begin{
        Write-Log -streamWriter $global:streamWriter -infoToLog "Get distinguished name from domain name"
    }
    Process{
        Try{
            $distinguishedName = "" 
	        $obj = $domainFullQualifiedDomain.Replace(',','\,').Split('/')
	        $obj[0].split(".") | ForEach-Object { $distinguishedName += ",DC=" + $_}
	        $distinguishedName = $distinguishedName.Substring(1)
            Write-Log -streamWriter $global:streamWriter -infoToLog "Domain name is $domainFullQualifiedDomain, distinguished name is $distinguishedName"
	        return $distinguishedName
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