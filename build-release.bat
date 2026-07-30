@echo off
chcp 65001 >nul

echo ========================================
echo  FileProtect — 单文件发布脚本 (x86)
echo ========================================
echo.

where dotnet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 找不到 dotnet SDK。请先安装 .NET 8.0 SDK。
    exit /b 1
)

set CONFIG=Release
set RID=win-x86

echo 目标框架: net8.0
echo 运行时:   %RID%
echo 配置:     %CONFIG%
echo.

echo [1/3] 还原依赖...
call dotnet restore -p:PlatformTarget=x86
echo.

echo [2/3] 清理旧输出...
call dotnet clean -c %CONFIG% -p:PlatformTarget=x86 >nul
echo.

echo [3/3] 发布单文件...
call dotnet publish -c %CONFIG% -r %RID% ^
    -p:PlatformTarget=x86 ^
    -p:PublishSingleFile=true ^
    -p:SelfContained=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -p:DebugType=embedded ^
    --self-contained true ^
    -o publish\
echo.

if %ERRORLEVEL% EQU 0 (
    echo ✔ 发布成功!
    echo 输出: publish\FileProtect.exe
    echo 大小:
    for %%A in (publish\FileProtect.exe) do echo   %%~zA 字节
) else (
    echo [错误] 发布失败。
    exit /b 1
)
