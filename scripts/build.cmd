@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %1
if errorlevel 1 exit /b 1
cmake -S . -B build/%2 -G Ninja -DCMAKE_BUILD_TYPE=%3 %~4 %~5
if errorlevel 1 exit /b 1
cmake --build build/%2
exit /b %errorlevel%
