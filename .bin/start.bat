@echo off

set /p VERSION=<../VERSION

for /f "tokens=* delims= " %%a in ("%VERSION%") do set VERSION=%%a

git push -f origin main

git tag v%VERSION%

git push origin v%VERSION%