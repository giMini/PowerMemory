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
function Get-OldDec ($DESXKeyHex, $g_Feedback, $cipherToDecrypt) {
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
