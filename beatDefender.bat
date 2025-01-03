@echo off

REM Check admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo github.com/arshx86
) else (
    echo dosyayi admin calistir. // run as administrator
    pause
    exit
)

REM -- Disable defender services
echo stopping defender services...
sc stop WinDefend
sc config WinDefend start= disabled

REM -- Disable defender scheduled tasks
echo removing scheduled defender tasks...
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable

REM -- Disable defender registry keys
echo disabling defender registry keys...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

REM -- Disable defender group policy
echo removing defender group policy...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

REM -- Final
echo cleaning up defender files...
cd "C:\Program Files"
del /f /s /q "Windows Defender"
rd "Windows Defender" /s /q
del /f /s /q "Windows Security"
rd "Windows Security" /s /q

cd "C:\Program Files (x86)"
del /f /s /q "Windows Defender"
rd "Windows Defender" /s /q

cd "C:\ProgramData"
attrib -h -s "Microsoft"
cd "Microsoft"
del /f /s /q "Windows Defender"
rd "Windows Defender" /s /q
del /f /s /q "Windows Security health"
rd "Windows Security health" /s /q

echo cleaning up defender services...
Del /f /s /q SecurityHealthHost.exe
Del /f /s /q SecurityHealthService.exe
Del /f /s /q SecurityHealthSystray.exe

echo defender is disabled, restart your computer to apply changes.
pause
exit >nul 2>&1
