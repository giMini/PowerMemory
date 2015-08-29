Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator ""

$myComputer = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name

$adminFlag = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if($adminFlag -eq $true){
    $adminMessage = "with administrator rights on " 
}
else {
    $adminMessage = "without administrator rights on "
}

Write-Host "The script is launched with user " -nonewline; Write-Host "$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) " -f red -nonewline; Write-Host $adminMessage -nonewline; Write-Host $myComputer -f red

$remoteLocalFile = Read-Host 'enter'