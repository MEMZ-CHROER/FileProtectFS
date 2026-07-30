# FileProtect — Windows 文件权限锁定工具

> 防止指定文件的权限（ACL）被篡改，支持 **用户态 ACL 保护** + **Ring0 驱动级保护**
> 适用于 Windows 10/11 x86/x64

---

## 两种保护模式

| 功能 | 用户态模式 | Ring0 模式 |
|------|:--------:|:---------:|
| 修改文件 ACL 来拒绝 WRITE_DAC | ✅ | ❌（不改ACL） |
| 拦截 `IRP_MJ_SET_SECURITY` | ❌ | ✅ |
| 阻止 `takeown /f` + `icacls /clear` | ❌ 可绕过 | ✅ 彻底拦截 |
| 需要驱动编译 | ❌ | ✅ WDK |
| 需要加载驱动 | ❌ | ✅ |
| 文件原始 ACL 保持不变 | ❌ | ✅ |

---

## Ring0 原理

```c
// 在 Minifilter 驱动中注册 PreSetSecurity 回调
// 当检测到受保护文件 → 直接返回 STATUS_ACCESS_DENIED
// IRP 在完成前就被拒绝，不交给文件系统处理

FLT_PREOP_CALLBACK_STATUS FileProtectPreSetSecurity(...)
{
    if (IsFilePathProtected(filePath)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;  // ← 内核层直接完成IRP，拒绝权限修改
    }
    return FLT_PREOP_SUCCESS;
}
```

**此时：**
- `takeown /f` → 发 `SET_SECURITY` IRP → 被驱动拦截 → `拒绝访问`
- `icacls /grant` → 同上 → 被拦截
- 文件属性面板 → 安全 → 修改权限 → 被拦截
- **`SeTakeOwnershipPrivilege` 在内核层不生效**，因为驱动不检查用户态特权令牌

---

## 编译

### 用户态程序 (.NET 8.0)

```bat
dotnet build -c Release                                    # AnyCPU
dotnet build -c Release -p:PlatformTarget=x86 -r win-x86   # x86
build-release.bat                                           # 单文件发布
```

### Ring0 驱动 (需要 WDK)

**前置要求:** [Windows Driver Kit (WDK) 10/11](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/download-the-wdk)

```bat
# 方法1: WDK 构建 (需设置好 WDK 环境)
build-driver.bat x86

# 方法2: MSBuild (需打开 VS 开发者命令提示符)
msbuild driver\fileprotect.vcxproj /p:configuration=Release /p:platform=x86

# 方法3: 在 Visual Studio 中打开 driver\fileprotect.vcxproj 构建
```

输出: `driver\FileProtectFS.sys`

> **64 位系统需要驱动签名:** 测试环境可启用测试签名模式:
> ```bat
> bcdedit /set testsigning on
> 重启
> ```

---

## 用法

> ⚠ **所有命令均需要管理员权限**

### 用户态保护

```bat
FileProtect protect C:\config.ini         保护文件（修改ACL）
FileProtect unprotect C:\config.ini       解除保护（恢复ACL）
```

### Ring0 内核级保护

```bat
:: 第1步: 安装并启动驱动（只需做一次）
FileProtect driver install
FileProtect driver start

:: 第2步: 使用 --ring0 保护文件
FileProtect protect --ring0 C:\secret.key

:: 解除 Ring0 保护
FileProtect unprotect --ring0 C:\secret.key

:: 查看驱动状态
FileProtect driver status

:: 停止/卸载驱动
FileProtect driver stop
FileProtect driver uninstall
```

### 其他命令

```bat
FileProtect list                           列出所有受保护文件
FileProtect check C:\target.txt           检查文件保护状态
```

---

## 项目结构

```
根目录
├── FileProtect.csproj         — C# 项目文件 (.NET 8.0)
├── app.manifest               — 管理员权限请求
├── Program.cs                 — 命令行入口 + CLI
├── AclProtector.cs            — 用户态 ACL 操作 (P/Invoke)
├── ProtectionStore.cs         — 注册表备份存储
├── Ring0Protector.cs          — Ring0 驱动通信层 (IOCTL)
├── build.bat                  — C# 构建脚本
├── build-release.bat          — 单文件发布脚本
├── build-driver.bat           — 驱动构建脚本
├── README.md
│
└── driver/
    ├── fileprotect.c          — Ring0 Minifilter 驱动 (拦截 SET_SECURITY)
    ├── fileprotect.h          — IOCTL 定义 (C/C# 共享)
    ├── fileprotectfs.inf      — 驱动安装信息
    ├── fileprotect.vcxproj    — VS 项目文件 (WDK)
    ├── sources                — WDK 构建文件
    └── makefile               — WDK makefile
```

## 限制

| 限制 | 说明 |
|------|------|
| 管理员权限 | 所有操作均需管理员权限 |
| 文件系统 | 用户态仅 NTFS；Ring0 支持 NTFS/ReFS |
| Ring0 驱动签名 | 64 位系统需要签名或开启 testsigning |
| 目录保护 | 当前仅支持单个文件 |
| 编译环境 | 驱动需要额外安装 WDK 10/11 |
