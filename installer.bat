@echo off
echo Checking for Python...

where python > nul 2>&1
if %errorlevel% equ 0 (
    echo Python is already installed.
    goto install_modules
) else (
    echo Python is not installed. Attempting to install...
    REM You might need to adjust the Python installer path and arguments
    REM based on your specific needs and the installer you have.
    REM This example assumes you have a Python installer executable (e.g., python-3.x.x.exe)
    REM in the same directory as this batch script, or that it's in your PATH.
    REM You might also need to add arguments like /quiet InstallAllUsers=1 TargetDir="C:\Python3x" AppendPath=1
    REM depending on the installer.

    REM **IMPORTANT:** Downloading and running executables from the internet can be a security risk.
    REM Consider providing a local installer or guiding the user to download it themselves.

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
)

pause
exit /b 0