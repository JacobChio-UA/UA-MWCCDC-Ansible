Install-Script -name winget-install -force
winget-install.ps1
winget install curl.curl -e --accept-source-agreements --accept-package-agreements
curl.exe -OL 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
Expand-Archive -Path SysinternalsSuite.zip -DestinationPath C:\SysinternalsSuite\
new-shortcut -target "C:\SysinternalsSuite\PsExec.exe" -shortcutpath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\PsExec.lnk"
winget install WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
winget install Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
winget install Microsoft.PowerShell -e --accept-source-agreements --accept-package-agreements
winget install Microsoft.VisualStudioCode -e --accept-source-agreements --accept-package-agreements
winget install Microsoft.WindowsTerminal -e --accept-source-agreements --accept-package-agreements
winget install Microsoft.etl2pcapng -e --accept-source-agreements --accept-package-agreements
winget install git.git -e --accept-source-agreements --accept-package-agreements

