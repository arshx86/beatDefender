@echo off
chcp 65001 >nul

:: Check if running in Windows PE
echo [INFO] Checking Windows PE environment...
wpeutil /? >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must run in Windows PE environment
    echo Boot from Windows PE and try again
    pause
    exit /b 1
)
echo [OK] Windows PE environment detected


color c
:: Add confirmation prompt
echo.
echo [WARNING] This will COMPLETELY remove Windows Defender from your system.
echo This action is PERMANENT and cannot be undone!
echo.
echo Press ANY KEY to continue, or CTRL+C to abort...
pause >nul
echo.
echo Continuing with removal...
echo.
color b

:: Load registry hives
echo [INFO] Loading registry hives...
reg load HKLM\SYS_TEMP C:\Windows\System32\config\SYSTEM >nul 2>&1
reg load HKLM\SOF_TEMP C:\Windows\System32\config\SOFTWARE >nul 2>&1
reg load HKLM\SEC_TEMP C:\Windows\System32\config\SECURITY >nul 2>&1
reg load HKLM\SAM_TEMP C:\Windows\System32\config\SAM >nul 2>&1

:: Disable Defender services in registry
echo [INFO] Disabling Defender services...
reg add "HKLM\SYS_TEMP\ControlSet001\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\SecurityHealthService" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\Sense" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\WdNisSvc" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\WdNisDrv" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\webthreatdefsvc" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYS_TEMP\ControlSet001\Services\webthreatdefuserservice" /v Start /t REG_DWORD /d 4 /f >nul

:: Disable via Group Policy
echo [INFO] Applying Group Policy restrictions...
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 1 /f >nul

:: Disable Real-time Protection
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f >nul

:: Disable SpyNet
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOF_TEMP\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f >nul

:: Direct Windows Defender settings
reg add "HKLM\SOF_TEMP\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f >nul

:: Tamper Protection
reg add "HKLM\SOF_TEMP\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f >nul

:: Additional Defender registry keys to remove
reg delete "HKLM\SOF_TEMP\Microsoft\Windows Defender\Exclusions" /f >nul 2>&1
reg delete "HKLM\SOF_TEMP\Microsoft\Windows Defender\Health" /f >nul 2>&1
reg delete "HKLM\SOF_TEMP\Microsoft\Windows Defender\Scan" /f >nul 2>&1
reg delete "HKLM\SOF_TEMP\Microsoft\Windows Defender\Threats" /f >nul 2>&1

:: Take ownership of all Defender directories
echo [INFO] Taking ownership of Defender files...
takeown /f "C:\Program Files\Windows Defender" /r /d y >nul
icacls "C:\Program Files\Windows Defender" /grant administrators:F /t /c >nul
takeown /f "C:\Program Files\Windows Defender Advanced Threat Protection" /r /d y >nul
icacls "C:\Program Files\Windows Defender Advanced Threat Protection" /grant administrators:F /t /c >nul
takeown /f "C:\ProgramData\Microsoft\Windows Defender" /r /d y >nul
icacls "C:\ProgramData\Microsoft\Windows Defender" /grant administrators:F /t /c >nul
takeown /f "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection" /r /d y >nul
icacls "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection" /grant administrators:F /t /c >nul
takeown /f "C:\ProgramData\Microsoft\Windows Security Health" /r /d y >nul
icacls "C:\ProgramData\Microsoft\Windows Security Health" /grant administrators:F /t /c >nul

:: Delete main Defender directories
echo [INFO] Deleting Defender directories...
cd /d "C:\Program Files"
rd /s /q "Windows Defender" >nul 2>&1
rd /s /q "Windows Defender Advanced Threat Protection" >nul 2>&1

cd /d "C:\ProgramData\Microsoft"
rd /s /q "Windows Defender" >nul 2>&1
rd /s /q "Windows Defender Advanced Threat Protection" >nul 2>&1
rd /s /q "Windows Security Health" >nul 2>&1
rd /s /q "Windows Defender Platform" >nul 2>&1

:: Delete System32 Defender files
echo [INFO] Deleting System32 Defender files...
cd /d "C:\Windows\System32"
del /f /q msmpeng.exe >nul 2>&1
del /f /q mpcmdrun.exe >nul 2>&1
del /f /q securityhealthservice.exe >nul 2>&1
del /f /q securityhealthsystray.exe >nul 2>&1
del /f /q securityhealthhost.exe >nul 2>&1
del /f /q windowsdefender.exe >nul 2>&1
del /f /q wdboot.sys >nul 2>&1
del /f /q wdfilter.sys >nul 2>&1
del /f /q wdnissvc.sys >nul 2>&1
del /f /q wdnisdrv.sys >nul 2>&1

:: Delete more driver files from drivers directory
cd /d "C:\Windows\System32\drivers"
del /f /q wdboot.sys >nul 2>&1
del /f /q wdfilter.sys >nul 2>&1
del /f /q wdnissvc.sys >nul 2>&1
del /f /q wdnisdrv.sys >nul 2>&1
del /f /q *defender* >nul 2>&1

:: Delete PowerShell modules
cd /d "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
rd /s /q "Defender" >nul 2>&1
rd /s /q "WindowsDefender" >nul 2>&1

:: Delete WinSxS backups more thoroughly
echo [INFO] Cleaning WinSxS component store...
cd /d "C:\Windows\WinSxS"
for /d %%i in (*defender*) do rd /s /q "%%i" >nul 2>&1
for /d %%i in (*windowsdefender*) do rd /s /q "%%i" >nul 2>&1
for /d %%i in (*wd_*) do rd /s /q "%%i" >nul 2>&1
for /d %%i in (*securityhealth*) do rd /s /q "%%i" >nul 2>&1

:: Delete temporary and cache files
cd /d "C:\Windows\Temp"
del /f /q *defender* >nul 2>&1
del /f /q *securityhealth* >nul 2>&1
del /f /q *msmpeng* >nul 2>&1

cd /d "C:\Windows\Logs"
rd /s /q "Windows Defender" >nul 2>&1

:: Remove from startup
echo [INFO] Removing from startup...
reg delete "HKLM\SOF_TEMP\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f >nul 2>&1
reg delete "HKLM\SOF_TEMP\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f >nul 2>&1

:: Remove scheduled tasks by deleting task files
echo [INFO] Removing scheduled tasks...
cd /d "C:\Windows\System32\Tasks"
rd /s /q "Microsoft\Windows\Windows Defender" >nul 2>&1

:: Disable Security Center
reg add "HKLM\SOF_TEMP\Microsoft\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Microsoft\Security Center" /v FirewallDisableNotify /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Microsoft\Security Center" /v UpdatesDisableNotify /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOF_TEMP\Microsoft\Security Center" /v AntiVirusOverride /t REG_DWORD /d 1 /f >nul

:: Remove Windows App packages related to security
echo [INFO] Removing Windows Security apps...
cd /d "C:\Windows\SystemApps"
rd /s /q "Microsoft.Windows.SecHealthUI_*" >nul 2>&1
rd /s /q "WindowsDefender*" >nul 2>&1

:: Clean up event logs
echo [INFO] Cleaning event logs...
cd /d "C:\Windows\System32\winevt\Logs"
del /f /q "Microsoft-Windows-Windows Defender%4Operational.evtx" >nul 2>&1
del /f /q "Microsoft-Windows-Windows Defender%4WHC.evtx" >nul 2>&1

:: Unload registry hives
echo [INFO] Unloading registry hives...
reg unload HKLM\SYS_TEMP >nul 2>&1
reg unload HKLM\SOF_TEMP >nul 2>&1
reg unload HKLM\SEC_TEMP >nul 2>&1
reg unload HKLM\SAM_TEMP >nul 2>&1

color a
echo Done. Press any key to restart.
pause >nul
shutdown /r -t 3
