@echo off
setlocal

echo Building Project Chimera

where nim >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Nim compiler not found. Install Nim 2.x first.
    exit /b 1
)

nim --version
if errorlevel 1 exit /b 1

nim c -d:release --threads:on --opt:speed --out:chimera.exe src\main.nim
if errorlevel 1 (
    echo [ERROR] Compilation failed.
    exit /b 1
)

echo.
echo Build complete: chimera.exe
echo Python is loaded from python_runtime\ when present, otherwise from the system.
echo Keep python_core\ beside the executable. This is a portable directory build,
echo not a single-file bundle.
exit /b 0
