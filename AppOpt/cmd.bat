@echo off
chcp 65001 >nul
title 使用 MSYS2 (D盘) 一键编译 AppOpt 并复制产物

cd /d "%~dp0"

echo ========================================
echo  1. 检查 MSYS2 及编译工具链...
echo ========================================

if not exist "D:\msys64" (
    echo [错误] 未找到 D:\msys64，请确认 MSYS2 已安装在该位置。
    pause
    exit /b 1
)

if not exist "D:\msys64\ucrt64\bin\gcc.exe" (
    echo [提示] 未找到 UCRT64 GCC，正在通过静默模式安装（约 500MB）...
    echo 请耐心等待，不要关闭窗口...
    D:\msys64\usr\bin\bash.exe -c "pacman -S --needed mingw-w64-ucrt-x86_64-toolchain --noconfirm"
    if errorlevel 1 (
        echo [错误] 工具链安装失败！请检查网络。
        pause
        exit /b 1
    )
    echo [完成] 工具链安装成功！
) else (
    echo [OK] GCC 工具链已存在。
)

echo.
echo ========================================
echo  2. 设置编译环境（临时生效）...
echo ========================================

set PATH=D:\msys64\ucrt64\bin;%PATH%

gcc --version >nul 2>nul
if errorlevel 1 (
    echo [错误] GCC 不可用，请检查 D:\msys64\ucrt64\bin 目录。
    pause
    exit /b 1
) else (
    echo [OK] GCC 已就绪。
)

echo.
echo ========================================
echo  3. 切换 Rust 为 GNU 工具链...
echo ========================================

rustup default stable-x86_64-pc-windows-gnu
if errorlevel 1 (
    echo [错误] Rust 工具链切换失败，请手动执行。
    pause
    exit /b 1
)

rustup target add aarch64-linux-android >nul 2>nul

echo.
echo ========================================
echo  4. 设置 NDK 链接器...
echo ========================================

set CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=D:/NDK/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android35-clang.cmd

if not exist "%CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER%" (
    echo [警告] 找不到 NDK 链接器文件！请修改脚本中的路径。
    pause
    exit /b 1
) else (
    echo [OK] 链接器已定位。
)

echo.
echo ========================================
echo  5. 开始编译 Release 版本...
echo ========================================

cargo build --release --target aarch64-linux-android

if errorlevel 1 (
    echo.
    echo ========================================
    echo 编译失败，请检查上方报错信息。
    echo ========================================
    pause
    exit /b 1
)

echo.
echo ========================================
echo  6. 复制产物到父目录 apps 根目录...
echo ========================================

:: 定义产物路径
set "SOURCE_FILE=%cd%\target\aarch64-linux-android\release\AppOpt"
set "TARGET_DIR=%cd%"
set "TARGET_FILE=%TARGET_DIR%\AppOpt"

:: 检查源文件是否存在
if not exist "%SOURCE_FILE%" (
    echo [错误] 未找到产物文件，编译可能未成功。
    pause
    exit /b 1
)

:: 复制（覆盖旧文件）
copy /Y "%SOURCE_FILE%" "%TARGET_FILE%"
if errorlevel 1 (
    echo [错误] 复制失败，请检查权限。
    pause
    exit /b 1
) else (
    echo [成功] 已复制产物到：%TARGET_FILE%
)

echo.
echo ========================================
echo 全部完成！
echo 产物位置：
echo   1. 原始位置：%SOURCE_FILE%
echo   2. 复制位置：%TARGET_FILE%
echo ========================================
pause