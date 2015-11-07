#requires -version 2
<#

.SYNOPSIS         
    PowerMemory launcher

.NOTES
    Version:        1.0
    Author:         Pierre-Alexandre Braeken    

#>
Param
    (
        [Parameter(Position = 0)]        
        [String]
        $relaunched = 0
    )
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Set-StrictMode -version 2

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$vipFunctions = "$scriptPath\RWMC\utilities\VIP.ps1"

#----------------------------------------------------------[Declarations]----------------------------------------------------------


#-----------------------------------------------------------[Functions]------------------------------------------------------------

. $vipFunctions

function Stop-Script () {      
    "Script terminating..." 
    Write-Output "================================================================================================"        
    Exit
    
}

#----------------------------------------------------------[Execution]----------------------------------------------------------

cls
Write-Output "================================================================================================"
White-Rabbit


$assessmentType = Read-Host 'What do you want assess?
1) Reveal memory passwords
2) Active Directory assessment
3) Scan services network
0) Exit

Enter menu number and press <ENTER>'
switch ($assessmentType){
    "1" {$assessmentType = 1}
    "2" {$assessmentType = 2}
    "3" {$assessmentType = 3}    
    "0" {Stop-Script}    
    default {Write-Output "The option could not be determined... Exiting...";Stop-Script}
}

if($assessmentType -eq 1) {
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\RWMC\White-Rabbit.ps1 0"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" ' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;    
}

if($assessmentType -eq 2) {
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\RECON\Get-ActiveDirectoryInfo.ps1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" ' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;    
}

if($assessmentType -eq 3) {
    $scriptPath = Split-Path $MyInvocation.InvocationName   
    $RWMC = $scriptPath + "\RECON\Scan-SPN.ps1"     
    $ArgumentList = 'Start-Process -FilePath powershell.exe -ArgumentList \"-ExecutionPolicy Bypass -File "{0}"\" ' -f $RWMC;
    Start-Process -FilePath powershell.exe -ArgumentList $ArgumentList -Wait -NoNewWindow;    
}