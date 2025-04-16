@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ================= clean builder old files ================
rd /S /Q "builder\cs-beacon\Release"
rd /S /Q "builder\cs-beacon\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ==================== generate builder ====================
MSBuild.exe GRT-MXLoader.sln /t:cs-beacon /p:Configuration=Release /p:Platform=x86
MSBuild.exe GRT-MXLoader.sln /t:cs-beacon /p:Configuration=Release /p:Platform=x64

echo ================ extract loader shellcode ================
del /S /Q dist
cd builder\cs-beacon
echo --------extract shellcode for x86--------
"..\..\Release\cs-beacon.exe"
echo --------extract shellcode for x64--------
"..\..\x64\Release\cs-beacon.exe"
cd ..\..

echo ================= clean builder old files ================
rd /S /Q "builder\cs-beacon\Release"
rd /S /Q "builder\cs-beacon\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ===================== test shellcode =====================
call test.bat

echo ==========================================================
echo                  build shellcode finish!
echo ==========================================================
