
function Decode-Base64PasteBin {
    $data = "D:\pasteRetrieved.txt"

    $dataLoaded = (gc $data) -replace '\s', '+' 

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($dataLoaded)) | Out-File d:\test.txt

    $decodedFile = (get-content d:\test.txt)

    $decodedFile = $decodedFile -replace '= ',"`n"
    $decodedFile = $decodedFile -replace ' =',"`n"
    $decodedFile = $decodedFile -replace 'Password : ',"`nPassword : "
    $decodedFile = $decodedFile -replace 'Login',"`nLogin"

    $decodedFile | out-file d:\test.txt -Encoding utf8

}




Decode-Base64PasteBin