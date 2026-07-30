@echo off
chcp 65001 >nul

echo ========================================
echo  FileProtectFS — 驱动构建脚本
echo ========================================
echo.
echo 需要安装 WDK (Windows Driver Kit) 10/11
echo   https://learn.microsoft.com/zh-cn/windows-hardware/drivers/download-the-wdk
echo.
echo 支持的平台: x86 / x64 / arm64
echo.

:: 默认参数
set PLATFORM=x86
if not "%1"=="" set PLATFORM=%1

set BUILD_CFG=Release
if not "%2"=="" set BUILD_CFG=%2

:: 尝试定位 WDK
set WDK_DIR=
if exist "C:\Program Files (x86)\Windows Kits\10\build\Build.exe" (
    set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
)
if exist "C:\Program Files\Windows Kits\10\build\Build.exe" (
    set WDK_DIR=C:\Program Files\Windows Kits\10
)

if "%WDK_DIR%"=="" (
    echo [错误] 未找到 WDK。请安装 Windows Driver Kit 10/11。
    echo.
    echo 手动构建步骤:
    echo   1. 打开 "开发人员命令提示符 for VS 2022"
    echo   2. cd driver
    echo   3. msbuild /t:build /p:Configuration=%BUILD_CFG% /p:Platform=%PLATFORM% fileprotect.vcxproj
    echo.
    exit /b 1
)

echo 检测到 WDK: %WDK_DIR%
echo 目标平台: %PLATFORM%
echo 构建配置: %BUILD_CFG%
echo.

:: 设置构建环境
call "%WDK_DIR%\bin\SetEnv.cmd" /%PLATFORM% /%BUILD_CFG% 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 设置 WDK 环境失败，尝试直接使用 build...
)

cd driver
echo.
echo 开始构建 FileProtectFS.sys ...
echo.
build /c /Z
set BUILD_RESULT=%ERRORLEVEL%
cd ..

if %BUILD_RESULT% EQU 0 (
    echo.
    echo ✔ 驱动构建成功!
    for %%a in (driver\obj%BUILD_ALT_DIR%\%PLATFORM%\FileProtectFS.sys) do (
        echo 输出: %%a
        echo 大小: %%~za 字节
    )
) else (
    echo.
    echo [错误] 驱动构建失败，错误码: %BUILD_RESULT%
    echo.
    echo 尝试使用 MSBuild 方式:
    echo   msbuild driver\fileprotect.vcxproj /p:configuration=%BUILD_CFG% /p:platform=%PLATFORM%
)
