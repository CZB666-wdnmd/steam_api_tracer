@echo off
echo ============================================
echo  Steam API Proxy (Detours) - Full Build
echo ============================================
echo.

set DETOURS_INC=Detours\include
set DETOURS_LIB=Detours\lib.X64

if not exist "%DETOURS_INC%\detours.h" (
    echo ERROR: Detours not found. Run:
    echo   git clone https://github.com/microsoft/Detours
    echo   cd Detours ^&^& nmake ^&^& cd ..
    goto :error
)
if not exist "%DETOURS_LIB%\detours.lib" (
    echo ERROR: detours.lib not found. Run: cd Detours ^&^& nmake
    goto :error
)

:: Step 1: Generate exports
echo [1/5] Generating exports from original DLL...
python generate_exports.py steam_api64_o.dll
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: Could not generate exports
    goto :error
)

:: Step 2: Assemble forwarding thunks
echo [2/5] Assembling forwarding thunks...
ml64 /nologo /c /Fo forwarded_exports.obj forwarded_exports.asm
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: MASM assembly failed
    goto :error
)

:: Step 3: Compile C++ proxy
echo [3/5] Compiling proxy DLL...
cl /nologo /std:c++17 /O2 /EHsc /MD /c /DNDEBUG /utf-8 ^
    /I"%DETOURS_INC%" ^
    steam_api_proxy.cpp /Fo:steam_api_proxy.obj
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: steam_api_proxy.cpp compilation failed
    goto :error
)

:: Step 4: Compile IPC dump module
echo [4/5] Compiling IPC dump module...
cl /nologo /std:c++17 /O2 /EHsc /MD /c /DNDEBUG /utf-8 ^
    /I"%DETOURS_INC%" ^
    ipc_dump.cpp /Fo:ipc_dump.obj
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: ipc_dump.cpp compilation failed
    goto :error
)

:: Step 5: Link
echo [5/5] Linking...
link /nologo /DLL /OUT:steam_api64.dll /DEF:steam_api64.def ^
    steam_api_proxy.obj ipc_dump.obj forwarded_exports.obj ^
    "%DETOURS_LIB%\detours.lib" ^
    kernel32.lib user32.lib advapi32.lib
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: Linking failed
    goto :error
)

echo.
echo ============================================
echo  BUILD SUCCESSFUL!
echo ============================================
echo  Output: steam_api64.dll
echo  IPC logs: ipc_trace.log (text) + ipc_payloads.bin (binary)
echo  Parse:    python parse_ipc_dump.py ipc_payloads.bin
echo.

del /q *.obj *.exp 2>nul
goto :done

:error
echo.
echo BUILD FAILED!
exit /b 1

:done
pause