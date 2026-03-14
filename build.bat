@echo off
REM Build luducat Bridge plugin for Playnite.
REM
REM Prerequisites:
REM   - .NET SDK (any version supporting net462 target)
REM     https://dotnet.microsoft.com/download
REM
REM Usage:
REM   build.bat              Build Release
REM   build.bat --deploy     Build and copy to Playnite extensions folder
REM   build.bat --clean      Clean before building

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "SRC_DIR=%PROJECT_DIR%src"
set "CONFIG=Release"
set "OUTPUT_DIR=%SRC_DIR%\bin\%CONFIG%\net462"
set "DEPLOY="
set "CLEAN="

for %%A in (%*) do (
    if /i "%%A"=="--deploy" set "DEPLOY=1"
    if /i "%%A"=="--clean" set "CLEAN=1"
)

echo === luducat Bridge Build ===

REM Check dotnet is available
where dotnet >nul 2>&1
if errorlevel 1 (
    echo ERROR: dotnet SDK not found. Install from https://dotnet.microsoft.com/download
    exit /b 1
)

REM Clean if requested
if defined CLEAN (
    echo Cleaning...
    dotnet clean "%SRC_DIR%\LuducatBridge.csproj" -c %CONFIG% >nul 2>&1
)

REM Restore and build
echo Building %CONFIG%...
dotnet build "%SRC_DIR%\LuducatBridge.csproj" -c %CONFIG%
if errorlevel 1 (
    echo ERROR: Build failed.
    exit /b 1
)

echo Build succeeded.
echo Output: %OUTPUT_DIR%

REM Deploy to Playnite extensions directory
if defined DEPLOY (
    call :find_playnite
    if not defined PLAYNITE_EXT (
        echo ERROR: Could not find Playnite installation.
        echo Searched: registry, %%LOCALAPPDATA%%\Playnite, portable
        echo Set PLAYNITE_DIR environment variable to your Playnite folder and retry.
        exit /b 1
    )

    REM Remove old plugin from both possible locations to avoid stale copies
    set "_LOCAL_OLD=%LOCALAPPDATA%\Playnite\Extensions\LuducatBridge"
    set "_ROAMING_OLD=%APPDATA%\Playnite\Extensions\LuducatBridge"
    if exist "!_LOCAL_OLD!" (
        echo Removing old plugin from Local...
        rmdir /S /Q "!_LOCAL_OLD!"
    )
    if exist "!_ROAMING_OLD!" (
        echo Removing old plugin from Roaming...
        rmdir /S /Q "!_ROAMING_OLD!"
    )

    set "EXT_DIR=!PLAYNITE_EXT!\LuducatBridge"
    echo Deploying to !EXT_DIR!...

    if not exist "!EXT_DIR!" mkdir "!EXT_DIR!"

    REM Copy build output
    xcopy /Y /Q "%OUTPUT_DIR%\*" "!EXT_DIR!\" >nul

    REM Copy extension manifest and icon
    if exist "%PROJECT_DIR%extension.yaml" copy /Y "%PROJECT_DIR%extension.yaml" "!EXT_DIR!\" >nul
    if exist "%PROJECT_DIR%icon.png" copy /Y "%PROJECT_DIR%icon.png" "!EXT_DIR!\" >nul

    echo Deployed. Restart Playnite to load the plugin.
)

echo === Done ===
exit /b 0

REM ── Find Playnite extensions directory ──────────────────────────
REM Portable detection: Playnite creates "portable.txt" next to the exe.
REM   Portable:  extensions live next to the executable in Extensions\
REM   Installed: extensions live in %APPDATA%\Playnite\Extensions\
:find_playnite
set "PLAYNITE_EXT="

REM 1. Explicit override via environment variable
if defined PLAYNITE_DIR (
    if exist "%PLAYNITE_DIR%\Playnite.DesktopApp.exe" (
        call :resolve_ext_dir "%PLAYNITE_DIR%"
        goto :eof
    )
)

REM 2. Registry — installed Playnite writes its path here
set "_REG_DIR="
for /f "tokens=2*" %%a in ('reg query "HKCU\Software\Playnite" /v InstallDir 2^>nul') do (
    set "_REG_DIR=%%b"
)
if defined _REG_DIR (
    if exist "!_REG_DIR!\Playnite.DesktopApp.exe" (
        call :resolve_ext_dir "!_REG_DIR!"
        goto :eof
    )
)

REM 3. Default installed location
if exist "%LOCALAPPDATA%\Playnite\Playnite.DesktopApp.exe" (
    call :resolve_ext_dir "%LOCALAPPDATA%\Playnite"
    goto :eof
)

REM 4. Portable — check common portable locations
for %%P in (
    "C:\Playnite"
    "%USERPROFILE%\Playnite"
    "%USERPROFILE%\Desktop\Playnite"
) do (
    if exist "%%~P\Playnite.DesktopApp.exe" (
        call :resolve_ext_dir "%%~P"
        goto :eof
    )
)

goto :eof

REM ── Resolve extensions path based on portable.txt marker ────────
:resolve_ext_dir
set "_PLAY_DIR=%~1"
if exist "%_PLAY_DIR%\portable.txt" (
    set "PLAYNITE_EXT=%_PLAY_DIR%\Extensions"
) else (
    set "PLAYNITE_EXT=%APPDATA%\Playnite\Extensions"
)
goto :eof
