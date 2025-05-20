@echo off
echo Checking for Python...

where python > nul 2>&1
if %errorlevel% equ 0 (
    echo Python is already installed.
    goto install_modules
) else (
    echo Python is not installed. Attempting to install...
    echo Downloading Python installer (this might take a while)...
    bitsadmin /transfer python_download_job /priority normal https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe %TEMP%\python-installer.exe
    if errorlevel 1 (
        echo Error downloading Python installer. Please install Python manually and run this script again.
        pause
        exit /b 1
    )

    echo Running Python installer...
    %TEMP%\python-installer.exe /quiet InstallAllUsers=1 TargetDir="%ProgramFiles%\Python312" AppendPath=1
    if errorlevel 1 (
        echo Python installation failed. Please check the installer logs and try again.
        pause
        exit /b 1
    )
    echo Python installed successfully!
)

:install_modules
echo Installing required Python modules...
REM Ensure pip is up to date
python -m pip install --upgrade pip

REM Install the specified modules
python -m pip install base64 Pillow colorama cryptography pycryptodome cython requests pyserial scapy tkinter browser_cookie3 aiohttp discord selenium

if %errorlevel% equ 0 (
    echo All required Python modules installed successfully!
) else (
    echo Some Python modules failed to install. Please check the error messages.
    pause
    REM Decide if you want to exit here or continue with the GitHub download
    REM For now, it will continue, but failed module installs might affect later Python scripts.
)

:download_github_repo
echo.
echo Checking for Git...
where git > nul 2>&1
if %errorlevel% equ 0 (
    echo Git is already installed.
    goto clone_repo
) else (
    echo Git is not installed. Attempting to install...
    echo Please note: Installing Git via command line is complex without a direct silent installer.
    echo It's recommended to install Git manually from https://git-scm.com/download/win.
    echo This script will attempt to download the installer and guide you.

    echo Downloading Git installer (this might take a while)...
    bitsadmin /transfer git_download_job /priority normal https://github.com/git-for-windows/git/releases/download/v2.45.0.windows.1/Git-2.45.0-64-bit.exe %TEMP%\git-installer.exe
    if errorlevel 1 (
        echo Error downloading Git installer. Please download and install Git manually from https://git-scm.com/download/win and run this script again.
        pause
        exit /b 1
    )

    echo Running Git installer...
    echo IMPORTANT: Follow the on-screen instructions for Git installation.
    echo It is recommended to choose the default options unless you know what you are doing.
    start /wait %TEMP%\git-installer.exe
    if %errorlevel% neq 0 (
        echo Git installation might have failed or was cancelled. Please install Git manually.
        pause
        exit /b 1
    )
    echo Git installed successfully!
    echo Please reopen this script after Git installation to ensure it's in the PATH.
    pause
    exit /b 0
)

:clone_repo
echo.
echo Downloading GitHub repository: https://github.com/Syxfer/TS-Hub

set "DESKTOP_PATH=%USERPROFILE%\Desktop"
set "TARGET_FOLDER=%DESKTOP_PATH%\TS HUB"

REM Check if the target folder exists and remove it to ensure a fresh clone
if exist "%TARGET_FOLDER%" (
    echo Removing existing "TS HUB" folder to ensure a fresh download...
    rmdir /s /q "%TARGET_FOLDER%"
    if %errorlevel% neq 0 (
        echo Error: Could not remove existing "TS HUB" folder. Please delete it manually and try again.
        pause
        exit /b 1
    )
)

echo Creating target folder: "%TARGET_FOLDER%"
mkdir "%TARGET_FOLDER%"
if %errorlevel% neq 0 (
    echo Error: Could not create folder "%TARGET_FOLDER%".
    pause
    exit /b 1
)

echo Cloning repository into "%TARGET_FOLDER%"...
git clone https://github.com/Syxfer/TS-Hub "%TARGET_FOLDER%"
if %errorlevel% equ 0 (
    echo GitHub repository downloaded successfully to "%TARGET_FOLDER%"!
) else (
    echo Error downloading GitHub repository. Please check your internet connection and Git installation.
)

pause
exit /b 0
