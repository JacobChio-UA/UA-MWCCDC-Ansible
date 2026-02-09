# "It's a trap!" - Admiral Ackbar
# we will try to rebuild windows defender, who knows maybe it will work, maybe not, but we will try

$defenderServices = Get-Service WinDefend, WdBoot, WdFilter, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc

if($defenderServices.Name -ne @('WinDefend', 'WdBoot', 'WdFilter', 'WdNisSvc', 'WdNisDrv', 'SecurityHealthService', 'wscsvc')) {
    Write-Host "One or more defender services are missing"
    $broken = $true
}
else {
    Write-Host "All defender services are present, checking status and start type"
}
foreach ($service in $defenderServices) {
    switch ($service.Name) {
        'SecurityHealthService' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Manual') {
                Write-Host "SecurityHealthService is not running or not set to manual start"
                $broken = $true
            }
        }
        'WinDefend' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Automatic') {
            Write-Host "WinDefend is not running or not set to automatic start"
            $broken = $true
            } 
        }
        'WdBoot' { 
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Boot') {
            Write-Host "WdBoot is not running or not set to boot start"
            $broken = $true
            }
        }
        'WdFilter' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Boot') {
            Write-Host "WdFilter is not running or not set to system start"
            $broken = $true
            }
        }
        'WdNisDrv' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Manual') {
            Write-Host "WdNisDrv is not running or not set to system start"
            $broken = $true
            }
        }
        'WdNisSvc' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Manual') {
            Write-Host "WdNisSvc is not running or not set to system start"
            $broken = $true
            }
        }
        'wscsvc' {
            if ($service.Status -ne 'Running' -or $service.StartType -ne 'Automatic') {
            Write-Host "wscsvc is not running or not set to system start"
            $broken = $true
            }
        }
    }
}
if ($broken) {
    Write-Host "Defender is broken, trying to fix it"
    Write-Host "running a security scan using the scanner microsoft provides to try to fix it"
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkId=212732" -OutFile "msert.exe"
    Start-Process -FilePath "msert.exe" -ArgumentList "/Q" -Wait
    Start-Process -FilePath "msert.exe" -ArgumentList "/F:Y /Q"
    start-process "cmd /c `"for /f `"delims=`" %d in ('dir `"%ProgramData%\Microsoft\Windows Defender\Platform`" /ad /b /o:-n') do if not defined _done `"%ProgramData%\Microsoft\Windows Defender\Platform\%d\MpCmdRun.exe`" -RemoveDefinitions -All" -Wait
    New-Item -Path "C:\DefenderTemp" -ItemType Directory; Invoke-Command {reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' C:\DefenderTemp\_DefenderAVBackup.reg}
    try{DISM /Online /Cleanup-Image /RestoreHealth}
    catch{sfc /scannow}
    Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force
    start-process "for /f `"delims=`" %d in ('dir `"%ProgramData%\Microsoft\Windows Defender\Platform`" /ad /b /o:-n') do if not defined _done `"%ProgramData%\Microsoft\Windows Defender\Platform\%d\MpCmdRun.exe`" -SignatureUpdate -MMPC"
    write-Host "Defender should be fixed now, if not we can try to just win with the super laser"
}
else {
    Write-Host "Defender is not broken, maybe we can just win"
}