@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1
dumpbin /imports build\release\dll-resolution-explainer.exe
exit /b %errorlevel%
