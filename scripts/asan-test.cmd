@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1
ctest --test-dir build/asan --output-on-failure --timeout 60
exit /b %errorlevel%
