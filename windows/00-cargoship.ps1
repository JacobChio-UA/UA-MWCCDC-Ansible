Save-Script -name winget-install -path .\ -force
winget-install.ps1
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install curl.curl -e --accept-source-agreements --accept-package-agreements
curl.exe -OL 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
Expand-Archive -Path SysinternalsSuite.zip -DestinationPath C:\SysinternalsSuite\ -Force
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" Microsoft.PowerShell -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install Microsoft.VisualStudioCode -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install Microsoft.WindowsTerminal -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install Microsoft.etl2pcapng -e --accept-source-agreements --accept-package-agreements
& "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe" install Git.Git -e --accept-source-agreements --accept-package-agreements