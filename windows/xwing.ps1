curl.exe -o 'Windows Server 2022 Security Baseline.zip' 'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip'
Expand-Archive -Path 'Windows Server 2022 Security Baseline.zip' -DestinationPath 'C:\Security Baseline' -force 
curl.exe -o 'Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip' 'https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip' 
Expand-Archive -Path 'Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip' -DestinationPath 'C:\Security Baseline\WinServer2019\' -force
curl.exe -o 'Windows 11 v25H2 Security Baseline.zip' 'https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip'
Expand-Archive -Path 'Windows 11 v25H2 Security Baseline.zip' -DestinationPath 'C:\Security Baseline\Win11\' -force

mkdir 'ToImport'

$sourceFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\WinServer2019\")
$destinationFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\ToImport\")
$destinationFolder.MoveHere($sourceFolder,16)
rm -Path 'C:\Security Baseline\WinServer2019\' -Recurse -Force

$sourceFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\Windows Server-2022-Security-Baseline-FINAL\")
$destinationFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\ToImport\")
$destinationFolder.MoveHere($sourceFolder,16)
rm -Path 'C:\Security Baseline\Windows Server-2022-Security-Baseline-FINAL\' -Recurse -Force

$sourceFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\Win11\Windows 11 v25H2 Security Baseline\")
$destinationFolder = (new-object -com shell.application).NameSpace("C:\Security Baseline\ToImport\")
$destinationFolder.MoveHere($sourceFolder,16)
rm -Path 'C:\Security Baseline\Win11\' -Recurse -Force

try {
    new-adorganizationalunit -name "Win11Workstation"
}
catch {
    Write-Host "OU Win11Workstation already exists, moving on"
}
try {
    new-adorganizationalunit -name "Win22Server"
}
catch {
    Write-Host "OU Win22Server already exists, moving on"
}
try {
    new-adorganizationalunit -name "Win19Server"
}
catch {
    Write-Host "OU Win19Server already exists, moving on"
}
