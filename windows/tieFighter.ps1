wget 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.3-windivert-1-64bit.msi' -O 'suricata.msi' -UseBasicParsing
Start-Process msiexec.exe -Wait -ArgumentList '/I suricata.msi /qn'
(Invoke-WebRequest 'https://rules.emergingthreats.net/open/suricata-8.0.3/rules/' -UseBasicParsing).Links | Where-Object -Property href -match '.rules' | ForEach-Object {
    Invoke-WebRequest -UseBasicParsing "https://rules.emergingthreats.net/open/suricata-8.0.3/rules$($_.href.substring(1))" -Verbose -OutFile "C:\Program Files\Suricata\rules\$($_.href.substring(2))"
}
