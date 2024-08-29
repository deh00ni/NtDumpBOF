set PLAT="x64"
set VERSION="WIN64"
cl.exe /D %VERSION% /c /GS- main.c /FoNtDump.%PLAT%.o