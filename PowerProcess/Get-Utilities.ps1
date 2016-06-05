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
                    if ($operatingSystem -eq "10.0.10514" -or $operatingSystem -eq "10.0.10586" -or $operatingSystem -eq "10.0.11082"){
                         $mode = "2016"
                    }
                    else {
                        if($operatingSystem -eq "10.0.14342") {
                             $mode = "1014342"
                        }
                        else {
                            Write-Output "The operating system could not be determined... terminating..."
                            Stop-Script
                        }
                    }
                }
            }
        }
    }
    return $mode
}

function Write-InFile ($buffer, $chain) {
    [io.file]::WriteAllText($buffer, $chain) | Out-Null
}

function Call-MemoryWalker ($kd, $file, $fullScriptPath, $symbols) {    
    $tab = &$kd -kl -y $symbols -c "`$`$<$fullScriptPath;Q"  
    return $tab
}

function Call-UserLandMemoryWalker ($memoryWalker, $file, $fullScriptPath, $symbols) {
    $tab = &$memoryWalker -pn $ProcessName -y $symbols -c "`$`$<$fullScriptPath;qd"     
    return $tab
}

function Convert-EchoTime {
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [int32] $EchoTime
)
    $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0    
    $fileCreated = $origin.AddSeconds($EchoTime).ToLocalTime()
    $fileCreated
}
function White-Rabbit {
    Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator "" -ForegroundColor Yellow
}

function Stop-Script () {   
    Begin{
        "`nScript terminating..." 
        Write-Output "================================================================================================"
    }
    Process{                  
        Exit
    }
}

function Construc-Structure {
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [int32] $Limit,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    $Array,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [int32] $Index,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [int32] $Step,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)]        
    [string] $Pattern

)
    $structure = ""
    while ($Limit -gt 0) {                     
        $fi = [array]::indexof($Array,$Pattern) + $Index
        $structure += " $($Array[$fi])"
        if(($Step % 16) -eq 0) {
            $Index = $Index+4
            $Step = 1
            $Limit = $Limit - 16
        }
        else {    
            $Index++
            $Step++
        }    
    }
    return $structure
}