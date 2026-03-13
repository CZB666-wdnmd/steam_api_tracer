@echo off
echo ============================================
echo  Building Microsoft Detours Library
echo ============================================
echo.

:: Check Detours directory exists
if not exist "Detours\src" (
    echo ERROR: Detours not found!
    echo Please clone: git clone https://github.com/microsoft/Detours
    exit /b 1
)

pushd Detours
nmake
popd

if %ERRORLEVEL% NEQ 0 (
    echo FAILED: Detours build failed
    exit /b 1
)

echo.
echo Detours library built successfully.
echo Output: Detours\lib.X64\detours.lib
echo.