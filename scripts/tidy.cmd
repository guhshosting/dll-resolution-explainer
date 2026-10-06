@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 exit /b 1
"C:\Program Files\LLVM\bin\clang-tidy.exe" src/pe.cpp src/files.cpp src/main.cpp --checks=-*,clang-analyzer-*,bugprone-*,performance-* --warnings-as-errors=* --extra-arg=-Wno-unknown-warning-option -- -std=c++17 -Isrc -DUNICODE -D_UNICODE -DNOMINMAX -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0A00
exit /b %errorlevel%
