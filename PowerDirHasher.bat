@echo off
setlocal enabledelayedexpansion
echo PowerDirHasher Launcher
echo ===================

REM Get the directory where the batch file is located
set "SCRIPT_DIR=%~dp0"

REM Check if a file or directory was dropped onto the batch file
if "%~1"=="" (
    echo No path was dropped. Starting PowerDirHasher normally...
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%PowerDirHasher.ps1"
) else (
    echo Path dropped: %~1
    
    REM Check if it's a directory
    if exist "%~1\" (
        echo Detected as directory
        echo Starting PowerDirHasher with the selected directory...
        powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "& '%SCRIPT_DIR%PowerDirHasher.ps1' -Path '%~1'"
    ) else (
        REM Get file extension
        set "EXT=%~x1"
        echo File extension detected: !EXT!
        
        REM Check if it's a .hashtask file using string comparison
        if /i "!EXT!"==".hashtask" (
            echo Detected as .hashtask file
            echo Starting PowerDirHasher with the selected task file...
            powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "& '%SCRIPT_DIR%PowerDirHasher.ps1' -Path '%~1'"
        ) else (
            echo The dropped file is not a .hashtask file or a directory.
            echo PowerDirHasher accepts only directories or .hashtask files.
            pause
        )
    )
)

exit