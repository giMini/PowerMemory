function Get-DecryptTripleDESPassword($password, $key, $initializationVector) {  
    try{
        $arrayPassword = $password -split ', '
        $passwordByte = @()
        foreach($ap in $arrayPassword){
            $passwordByte += [System.Convert]::ToByte($ap,16)     
        }

        $arrayKey = $key -split ', '
        $keyByte = @()
        foreach($ak in $arrayKey){
            $keyByte += [System.Convert]::ToByte($ak,16)        
        }

        $arrayInitializationVector = $initializationVector -split ', '
        $initializationVectorByte = @()
        foreach($aiv in $arrayInitializationVector){
            $initializationVectorByte += [System.Convert]::ToByte($aiv,16)        
        }
 
        $TripleDES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
                
        $TripleDES.IV = $initializationVectorByte
        $TripleDES.Key = $keyByte
        $TripleDES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $TripleDES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $decryptorObject = $TripleDES.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)

        $TripleDES.Clear()

        return [System.Text.UnicodeEncoding]::Unicode.GetString($outBlock)
     }
     catch {
        #Write-Error "$error[0]"
    }
}

function Get-DecryptAESPassword($password, $key, $initializationVector) {
    try{

        $arrayPassword = $password -split ', '
        $passwordByte = @()
        foreach($ap in $arrayPassword){
            $passwordByte += [System.Convert]::ToByte($ap,16)     
        }

        $arrayKey = $key -split ', '
        $keyByte = @()
        foreach($ak in $arrayKey){
            $keyByte += [System.Convert]::ToByte($ak,16)        
        }

        $arrayInitializationVector = $initializationVector -split ', '
        $initializationVectorByte = @()
        foreach($aiv in $arrayInitializationVector){
            $initializationVectorByte += [System.Convert]::ToByte($aiv,16)        
        }
        $AESObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                
        $AESObject.IV = $initializationVectorByte
        $AESObject.Key = $keyByte
        $decryptorObject = $AESObject.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($passwordByte, 0 , $passwordByte.Length)

        $AESObject.Clear()

        return [System.Text.UnicodeEncoding]::Unicode.GetString($outBlock)
    }
    catch {
        Write-Output "$error[0]"
    }
}