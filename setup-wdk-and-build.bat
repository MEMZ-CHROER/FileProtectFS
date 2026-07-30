@echo off
chcp 65001 >nul

echo ===================================================
echo  一键安装 WDK + 编译 FileProtectFS 驱动
echo ===================================================
echo.
echo 本脚本将安装 Visual Studio 2022 Build Tools + WDK
echo 然后编译 FileProtectFS.sys
echo.
echo 需要: 约 15 分钟, 6 GB 磁盘空间, 高速网络
echo ===================================================
echo.

where winget >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 找不到 winget。请使用 Windows 10 1809+ 或 Windows 11。
    exit /b 1
)

echo [1/5] 安装 Visual Studio 2022 Build Tools...
winget install Microsoft.VisualStudio.2022.BuildTools --silent --accept-source-agreements 2>nul

echo [2/5] 安装 VS 工作负载 (C++ 桌面开发)...
call "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify ^
    --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" ^
    --add Microsoft.VisualStudio.Workload.VCTools ^
    --quiet

echo [3/5] 安装 WDK...
winget install Microsoft.WindowsWDK.10.0.22621 --silent 2>nul

echo [4/5] 设置环境变量...
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"

echo [5/5] 编译驱动...
cd /d "%~dp0driver"
msbuild fileprotect.vcxproj /p:configuration=Release /p:platform=x86
msbuild fileprotect.vcxproj /p:configuration=Release /p:platform=x64

echo.
echo 输出文件:
echo   driver\*\Release\FileProtectFS.sys
echo.
echo 安装:
echo   FileProtect driver install
echo   FileProtect driver start
echo   FileProtect protect --ring0 C:\target.txt
