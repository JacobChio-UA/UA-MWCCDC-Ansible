Install-Script -name winget-install -force
winget-install.ps1

winget install microsoft.sysinternals.suite -e --accept-source-agreements --accept-package-agreements
winget install wireshark -e --accept-source-agreements --accept-package-agreements
winget install nmap -e --accept-source-agreements --accept-package-agreements
winget install powershell -e --accept-source-agreements --accept-package-agreements
winget install vscode -e --accept-source-agreements --accept-package-agreements
winget install WindowsTerminal -e --accept-source-agreements --accept-package-agreements
