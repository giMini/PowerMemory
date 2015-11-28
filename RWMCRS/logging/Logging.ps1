Function Start-Log {    
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][string]$scriptName, [Parameter(Mandatory=$true)][string]$scriptVersion, 
        [Parameter(Mandatory=$true)]$streamWriter)
    Process{       
        $global:streamWriter += "[$ScriptName] version [$ScriptVersion] started at $([DateTime]::Now)"
    }
}
 
Function Write-Log {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)]$streamWriter, [Parameter(Mandatory=$true)][string]$infoToLog)  
    Process{    
        #$global:streamWriter | Add-Member -Type NoteProperty -Name Info -Value "$infoToLog"
         $global:streamWriter += "$infoToLog"
    }
}
 
Function Write-Error {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)]$streamWriter, [Parameter(Mandatory=$true)][string]$errorCaught, [Parameter(Mandatory=$true)][boolean]$forceExit)  
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
    Param ([Parameter(Mandatory=$true)]$streamWriter)  
    Process{    
        $global:streamWriter += "Script ended at $([DateTime]::Now)"
  
        #$global:streamWriter.Close()   
    }
}