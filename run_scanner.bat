@echo off
setlocal ENABLEDELAYEDEXPANSION

REM ------------------------------------------------------------------------------
REM Title     : VirusTotal IoC Scanner Runner with Debugger and Safe URL Handling
REM ------------------------------------------------------------------------------

set "SCRIPT=query_virustotal.ps1"
set "PROGRESS_FILE=scan_progress.txt"
set "LOG_FILE=debug_log.txt"
set "TOTAL_IOCS=0"

echo [INFO] Bulk IoC Scanner 


REM Check for PowerShell
where powershell >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] PowerShell is not installed or in PATH.
    pause
    exit /b 1
)

REM Check for PowerShell script
if not exist "%SCRIPT%" (
    echo [ERROR] PowerShell script '%SCRIPT%' not found.
    pause
    exit /b 1
)

REM Check for input file
if not exist "ioc_input.csv" (
    echo [ERROR] Input file 'ioc_input.csv' not found.
    pause
    exit /b 1
)

REM Count valid IoCs
for /f "usebackq skip=1 delims=" %%a in ("ioc_input.csv") do (
    set "line=%%a"
    setlocal enabledelayedexpansion
    set "line=!line:"=!""!
    if not "!line!"=="" (
        echo !line! | findstr /i "http://" >nul
        if errorlevel 1 (
            echo !line! | findstr /i "https://" >nul
            if errorlevel 1 (
                echo !line! | findstr /r "[a-zA-Z0-9\-]\+\.[a-zA-Z][a-zA-Z]" >nul
                if errorlevel 1 (
                    endlocal & set /a TOTAL_IOCS+=1
                ) else (endlocal)
            ) else (endlocal)
        ) else (endlocal)
    ) else (endlocal)
)

if %TOTAL_IOCS%==0 (
    echo [ERROR] No valid IPs found in ioc_input.csv.
    pause
    exit /b 1
)

REM Clean up old logs/progress
if exist "%PROGRESS_FILE%" del /f /q "%PROGRESS_FILE%"
if exist "%LOG_FILE%" del /f /q "%LOG_FILE%"

REM Run PowerShell script and log output (no CMD parser issues)
echo [INFO] Launching PowerShell script with debugging enabled...
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" >> "%LOG_FILE%" 2>&1

REM Wait a moment then close any open Notepad (auto-close debug viewer)
timeout /t 1 >nul
taskkill /f /im notepad.exe >nul 2>&1

REM Display progress bar every 1 second
echo [INFO] Scanning started. Monitoring progress ...
set "prev=0"

:progress_loop
if not exist "%PROGRESS_FILE%" (
    timeout /t 1 >nul
    goto progress_loop
)

set /p count=<"%PROGRESS_FILE%"
if "!count!"=="%TOTAL_IOCS%" goto done

set /a percent=(count*100)/TOTAL_IOCS
set /a barLen=(percent/2)

set "bar="
for /l %%i in (1,1,!barLen!) do set "bar=!bar!#"
for /l %%i in (!barLen!,1,50) do set "bar=!bar!."

cls
echo [INFO] Bulk IoC Scanner 
echo.
echo Scanned: !count! / %TOTAL_IOCS%    Progress: !percent!%%
echo [!bar!]
echo.
timeout /t 1 >nul
goto progress_loop

:done
cls
echo [INFO] Bulk IoC Scanner 
echo.
echo All %TOTAL_IOCS% scans completed.
echo Results:
echo - virustotal_results.json
echo - virustotal_results.csv
echo - abuseipdb_results.csv
echo - merged_results.csv
echo.
echo See log file for any errors:
echo - %LOG_FILE%
echo.
del "%PROGRESS_FILE%" >nul 2>&1
pause
exit /b 0
