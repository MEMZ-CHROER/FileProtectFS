@echo off
chcp 65001 >nul

echo ========================================
echo  FileProtect — 构建脚本
echo ========================================
echo.

where dotnet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 找不到 dotnet SDK。请先安装 .NET 8.0 SDK:
    echo   https://dotnet.microsoft.com/zh-cn/download
    exit /b 1
)

set CONFIG=Release

echo 目标框架: net8.0
echo 配置:     %CONFIG%
echo.
echo 提示: 默认编译为 AnyCPU (可在x86/x64系统运行)
echo 如需强制 x86, 使用: build x86
echo 如需单文件发布, 使用: build-release.bat
echo.

:: 判断平台参数
if /I "%1"=="x86" (
    set PLATFORM=x86
    set RUNTIME=win-x86
) else if /I "%1"=="x64" (
    set PLATFORM=x64
    set RUNTIME=win-x64
) else (
    set PLATFORM=
    set RUNTIME=
)

echo [1/3] 还原依赖...
call dotnet restore
echo.

echo [2/3] 清理...
if defined PLATFORM (
    call dotnet clean -c %CONFIG% -p:PlatformTarget=%PLATFORM% >nul 2>&1
) else (
    call dotnet clean -c %CONFIG% >nul 2>&1
)
echo.

echo [3/3] 构建...
if defined PLATFORM (
    call dotnet build -c %CONFIG% -p:PlatformTarget=%PLATFORM% -r %RUNTIME% --no-restore
) else (
    call dotnet build -c %CONFIG% --no-restore
)
echo.

if %ERRORLEVEL% EQU 0 (
    for /d %%a in (bin\%CONFIG%\*) do (
        for %%b in (%%a\FileProtect.exe) do (
            if exist %%b echo ✔ 构建成功: %%b
        )
    )
) else (
    echo [错误] 构建失败。
    exit /b 1
)
