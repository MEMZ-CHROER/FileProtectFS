using System.Diagnostics;
using System.Security.Principal;

namespace FileProtect;

/// <summary>
/// FileProtect — Windows 文件权限锁定工具
/// 支持用户态 ACL 保护和 Ring0 驱动级保护
/// </summary>
class Program
{
    private const int ExitSuccess = 0;
    private const int ExitError = 1;

    static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (!IsAdministrator())
        {
            Console.Error.WriteLine("错误: 需要管理员权限才能运行此工具。");
            Console.Error.WriteLine("请以管理员身份重新运行 (右键 -> 以管理员身份运行)。");
            return ExitError;
        }

        if (args.Length == 0 || args[0] is "/?" or "-?" or "--help" or "-h" or "help")
        {
            PrintHelp();
            return ExitSuccess;
        }

        string command = args[0].ToLowerInvariant();

        try
        {
            return command switch
            {
                "protect" or "p" => HandleProtect(args),
                "unprotect" or "u" or "restore" => HandleUnprotect(args),
                "list" or "l" => HandleList(),
                "check" or "c" or "status" => HandleCheck(args),
                "driver" or "drv" => HandleDriver(args),
                _ => HandleUnknownCommand(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"未预期的错误: {ex.Message}");
            return ExitError;
        }
    }

    // ======================================================================
    // 命令: protect
    // ======================================================================

    static int HandleProtect(string[] args)
    {
        bool useRing0 = args.Skip(1).Any(a => a.Equals("--ring0", StringComparison.OrdinalIgnoreCase));
        string? filePath = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--"));

        if (filePath == null)
        {
            Console.Error.WriteLine("用法: FileProtect protect [--ring0] <文件路径>");
            return ExitError;
        }

        string fullPath = Path.GetFullPath(filePath);
        string normalized = AclProtector.NormalizePath(fullPath);

        if (!File.Exists(fullPath))
        {
            Console.Error.WriteLine($"错误: 文件不存在 — {fullPath}");
            return ExitError;
        }

        using var store = new ProtectionStore();

        // 检查是否已在保护列表中
        bool alreadyProtected = store.IsProtected(normalized);
        if (alreadyProtected)
        {
            Console.WriteLine("⚠  该文件已在保护列表中。如需重新保护，请先解除保护。");
            return ExitSuccess;
        }

        if (useRing0)
        {
            return HandleProtectRing0(fullPath, normalized, store);
        }
        else
        {
            return HandleProtectUserMode(fullPath, normalized, store);
        }
    }

    static int HandleProtectRing0(string path, string normalized, ProtectionStore store)
    {
        Console.WriteLine($"正在保护 (Ring0): {path}");

        using var ring0 = new Ring0Protector();

        // 1. 确保驱动就绪
        Console.Write("正在检查 Ring0 驱动... ");
        var readyResult = ring0.EnsureDriverReady();
        if (!readyResult.Success)
        {
            Console.Error.WriteLine($"失败: {readyResult.ErrorMessage}");
            Console.Error.WriteLine("提示: Ring0 保护需要 FileProtectFS.sys 驱动。");
            Console.Error.WriteLine("  请先编译驱动或使用用户态保护 (不带 --ring0 参数)。");
            return ExitError;
        }
        Console.WriteLine("✓");

        // 2. 备份原始安全描述符（仅用于记录，Ring0 不修改 ACL）
        Console.Write("正在记录文件信息... ");
        var backup = AclProtector.BackupSecurity(path);
        if (backup?.Success == true)
        {
            store.SaveBackup(normalized, backup.Sddl!, backup.OwnerSid);
            Console.WriteLine("✓");
        }
        else
        {
            // Ring0 不需要备份也能工作，只是做个记录
            store.SaveBackup(normalized, "(ring0)", null);
            Console.WriteLine("⚠ (无法获取ACL备份，仅记录路径)");
        }

        // 3. 通知驱动添加保护
        Console.Write("正在向驱动注册受保护文件... ");
        var addResult = ring0.AddProtectedFile(path);
        if (!addResult.Success)
        {
            Console.Error.WriteLine($"失败: {addResult.ErrorMessage}");
            store.DeleteBackup(normalized);
            return ExitError;
        }
        Console.WriteLine("✓");

        Console.WriteLine("\n✔  文件已通过 Ring0 驱动保护！");
        Console.WriteLine("  - 内核层拦截 SET_SECURITY IRP");
        Console.WriteLine("  - 任何用户态进程（包括 takeown+icacls）均无法修改权限");
        Console.WriteLine("  - 文件原始 ACL 和所有者保持不变");
        Console.WriteLine("  - 使用 'unprotect --ring0' 命令可解除保护");

        return ExitSuccess;
    }

    static int HandleProtectUserMode(string path, string normalized, ProtectionStore store)
    {
        Console.WriteLine($"正在保护: {path}");

        // 1. 备份原始安全描述符
        Console.Write("正在备份原始安全描述符... ");
        var backupResult = AclProtector.BackupSecurity(path);
        if (backupResult == null || !backupResult.Success)
        {
            Console.Error.WriteLine($"失败: {backupResult?.ErrorMessage ?? "未知错误"}");
            return ExitError;
        }
        Console.WriteLine("✓");

        // 2. 存储备份
        store.SaveBackup(normalized, backupResult.Sddl!, backupResult.OwnerSid);

        // 3. 应用保护
        Console.Write("正在应用权限锁定... ");
        var protectResult = AclProtector.Protect(path);
        if (!protectResult.Success)
        {
            Console.Error.WriteLine($"失败: {protectResult.ErrorMessage}");
            store.DeleteBackup(normalized);
            return ExitError;
        }
        Console.WriteLine("✓");

        Console.WriteLine("\n✔  文件已成功保护！");
        Console.WriteLine("  - 所有用户 (包括管理员) 无法修改文件权限");
        Console.WriteLine("  - 所有用户 (包括管理员) 无法删除文件");
        Console.WriteLine("  - 所有者和组已设置为 SYSTEM");
        Console.WriteLine("  - 所有用户保留读取和执行权限");
        Console.WriteLine("  - 使用 'unprotect' 命令可恢复原始权限");
        Console.WriteLine("  - 提示: 使用 --ring0 参数可启用内核级更强制保护");

        return ExitSuccess;
    }

    // ======================================================================
    // 命令: unprotect
    // ======================================================================

    static int HandleUnprotect(string[] args)
    {
        bool useRing0 = args.Skip(1).Any(a => a.Equals("--ring0", StringComparison.OrdinalIgnoreCase));
        string? filePath = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--"));

        if (filePath == null)
        {
            Console.Error.WriteLine("用法: FileProtect unprotect [--ring0] <文件路径>");
            return ExitError;
        }

        string fullPath = Path.GetFullPath(filePath);
        string normalized = AclProtector.NormalizePath(fullPath);

        if (useRing0)
        {
            return HandleUnprotectRing0(fullPath, normalized);
        }
        else
        {
            return HandleUnprotectUserMode(fullPath, normalized);
        }
    }

    static int HandleUnprotectRing0(string path, string normalized)
    {
        Console.WriteLine($"正在解除 Ring0 保护: {path}");

        using var ring0 = new Ring0Protector();

        // 1. 通知驱动移除保护
        Console.Write("正在通知驱动移除保护... ");
        var removeResult = ring0.RemoveProtectedFile(path);
        if (!removeResult.Success)
        {
            Console.Error.WriteLine($"失败: {removeResult.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");

        // 2. 删除注册表记录
        using var store = new ProtectionStore();
        store.DeleteBackup(normalized);

        Console.WriteLine("\n✔  文件已解除 Ring0 保护！");
        Console.WriteLine("  - 驱动已停止拦截该文件的 SET_SECURITY");
        Console.WriteLine("  - 文件 ACL 保持原样，无需恢复");

        return ExitSuccess;
    }

    static int HandleUnprotectUserMode(string path, string normalized)
    {
        Console.WriteLine($"正在解除保护: {path}");

        using var store = new ProtectionStore();

        if (!store.LoadBackup(normalized))
        {
            Console.Error.WriteLine("错误: 未找到该文件的保护备份。无法解除保护。");
            Console.Error.WriteLine("如果文件权限已被锁定但无备份记录，请手动：");
            Console.Error.WriteLine("  1. 以管理员身份打开 PowerShell");
            Console.Error.WriteLine("  2. takeown /f \"文件路径\"");
            Console.Error.WriteLine("  3. icacls \"文件路径\" /reset");
            return ExitError;
        }

        // 如果是 Ring0 记录（无实际 SDDL），提示用户用 --ring0 解除
        if (store.BackupSddl == "(ring0)")
        {
            Console.Error.WriteLine("该文件是通过 Ring0 驱动的保护的，请使用 --ring0 参数解除:");
            Console.Error.WriteLine($"  FileProtect unprotect --ring0 \"{path}\"");
            return ExitError;
        }

        Console.Write("正在恢复原始权限 (可能需要几秒)... ");
        var result = AclProtector.Unprotect(path, store.BackupSddl!);
        if (!result.Success)
        {
            Console.Error.WriteLine($"失败: {result.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");

        store.DeleteBackup(normalized);

        Console.WriteLine("\n✔  文件已成功解除保护，原始权限已恢复！");
        return ExitSuccess;
    }

    // ======================================================================
    // 命令: list
    // ======================================================================

    static int HandleList()
    {
        using var store = new ProtectionStore();
        var userFiles = store.ListProtectedFiles();

        // 尝试从驱动获取 Ring0 受保护文件
        List<ProtectedFileInfo> ring0Files = new();
        try
        {
            using var ring0 = new Ring0Protector();
            int count = ring0.GetProtectedCount();
            if (count > 0)
            {
                ring0Files = ring0.QueryProtectedFiles();
            }
        }
        catch
        {
            // 驱动不可用时忽略
        }

        if (userFiles.Count == 0 && ring0Files.Count == 0)
        {
            Console.WriteLine("当前没有任何受保护的文件。");
            return ExitSuccess;
        }

        // 合并列表（去重）
        var allFiles = new Dictionary<string, (string Source, DateTime? ProtectedAt)>();

        foreach (var f in userFiles)
        {
            allFiles[f.NormalizedPath] = ("用户态", f.ProtectedAtUtc);
        }

        bool ring0Active = false;
        foreach (var f in ring0Files)
        {
            ring0Active = true;
            if (!allFiles.ContainsKey(f.NormalizedPath))
            {
                allFiles[f.NormalizedPath] = ("Ring0", f.ProtectedAtUtc);
            }
            else if (allFiles[f.NormalizedPath].Source == "用户态")
            {
                allFiles[f.NormalizedPath] = ("用户态+Ring0", f.ProtectedAtUtc);
            }
        }

        Console.WriteLine($"受保护文件列表 ({allFiles.Count} 项):");
        if (ring0Active) Console.WriteLine("  Ring0 驱动: 运行中");
        Console.WriteLine(new string('-', 90));

        foreach (var kv in allFiles.OrderBy(x => x.Key))
        {
            string localTime = kv.Value.ProtectedAt?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "未知";
            bool exists = File.Exists(kv.Key);
            string status = exists ? "✓ 存在" : "✗ 不存在";
            Console.WriteLine($"  [{status}] {kv.Key}");
            Console.WriteLine($"          来源: {kv.Value.Source}  保护时间: {localTime}");
            Console.WriteLine();
        }

        return ExitSuccess;
    }

    // ======================================================================
    // 命令: check
    // ======================================================================

    static int HandleCheck(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("用法: FileProtect check <文件路径>");
            return ExitError;
        }

        string filePath = args[1];
        string fullPath = Path.GetFullPath(filePath);
        string normalized = AclProtector.NormalizePath(fullPath);

        if (!File.Exists(fullPath))
        {
            Console.Error.WriteLine($"文件不存在: {fullPath}");
            return ExitError;
        }

        // 检查用户态保护
        var checkResult = AclProtector.CheckProtection(fullPath);
        using var store = new ProtectionStore();
        bool inStore = store.IsProtected(normalized);

        // 检查 Ring0 驱动保护
        bool ring0Protected = false;
        string ring0Status = "未安装";
        try
        {
            using var ring0 = new Ring0Protector();
            if (ring0.IsDriverRunning())
            {
                ring0Status = "运行中";
                // 查询驱动列表是否包含该文件
                var list = ring0.QueryProtectedFiles();
                ring0Protected = list.Any(f =>
                    f.NormalizedPath.Equals(normalized, StringComparison.OrdinalIgnoreCase));
            }
            else if (Ring0Protector.IsDriverInstalled())
            {
                ring0Status = "已安装未启动";
            }
        }
        catch { /* 驱动不可用 */ }

        Console.WriteLine($"文件: {fullPath}");
        Console.WriteLine($"用户态保护: {(checkResult.IsProtected ? "✔ 受保护" : "✗ 未保护")}");
        Console.WriteLine($"  - 详情: {checkResult.Detail}");
        Console.WriteLine($"  - 注册表记录: {(inStore ? "有" : "无")}");
        Console.WriteLine($"Ring0 驱动: {ring0Status}");
        Console.WriteLine($"  - 驱动级保护: {(ring0Protected ? "✔ 是" : "✗ 否")}");

        if (checkResult.IsProtected && !inStore)
        {
            Console.WriteLine("\n⚠  文件有用户态保护标记但无注册表记录，可能被其他工具锁定。");
        }

        return ExitSuccess;
    }

    // ======================================================================
    // 命令: driver
    // ======================================================================

    static int HandleDriver(string[] args)
    {
        if (args.Length < 2)
        {
            PrintDriverHelp();
            return ExitError;
        }

        string subCmd = args[1].ToLowerInvariant();
        using var ring0 = new Ring0Protector();

        return subCmd switch
        {
            "install" => HandleDriverInstall(ring0),
            "start" => HandleDriverStart(ring0),
            "stop" => HandleDriverStop(ring0),
            "uninstall" => HandleDriverUninstall(ring0),
            "status" => HandleDriverStatus(ring0),
            _ => HandleUnknownCommand($"driver {args[1]}"),
        };
    }

    static int HandleDriverInstall(Ring0Protector ring0)
    {
        Console.Write("正在安装 Ring0 驱动服务... ");
        var result = ring0.InstallDriver();
        if (!result.Success)
        {
            Console.Error.WriteLine($"失败: {result.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");
        Console.WriteLine("驱动服务已安装。使用 'driver start' 启动。");
        return ExitSuccess;
    }

    static int HandleDriverStart(Ring0Protector ring0)
    {
        Console.Write("正在启动 Ring0 驱动... ");
        var result = ring0.StartDriver();
        if (!result.Success)
        {
            Console.Error.WriteLine($"失败: {result.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");
        Console.WriteLine("驱动已运行。现在可以使用 'protect --ring0' 命令。");
        return ExitSuccess;
    }

    static int HandleDriverStop(Ring0Protector ring0)
    {
        Console.Write("正在停止 Ring0 驱动... ");
        var result = ring0.StopDriver();
        if (!result.Success)
        {
            Console.Error.WriteLine($"失败: {result.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");
        Console.WriteLine("驱动已停止。Ring0 保护已失效。");
        return ExitSuccess;
    }

    static int HandleDriverUninstall(Ring0Protector ring0)
    {
        Console.Write("正在卸载 Ring0 驱动... ");
        var result = ring0.UninstallDriver();
        if (!result.Success)
        {
            Console.Error.WriteLine($"失败: {result.ErrorMessage}");
            return ExitError;
        }
        Console.WriteLine("✓");
        Console.WriteLine("驱动服务已删除。");
        return ExitSuccess;
    }

    static int HandleDriverStatus(Ring0Protector ring0)
    {
        bool installed = Ring0Protector.IsDriverInstalled();
        bool running = ring0.IsDriverRunning();
        int count = ring0.GetProtectedCount();

        Console.WriteLine("Ring0 驱动状态:");
        Console.WriteLine($"  安装状态: {(installed ? "✔ 已安装" : "✗ 未安装")}");
        Console.WriteLine($"  运行状态: {(running ? "✔ 运行中" : "✗ 未运行")}");
        Console.WriteLine($"  受保护文件数: {(count >= 0 ? count.ToString() : "N/A")}");

        if (!installed)
        {
            Console.WriteLine("\n提示: 确保 FileProtectFS.sys 在程序目录下，执行:");
            Console.WriteLine("  FileProtect driver install");
            Console.WriteLine("  FileProtect driver start");
        }

        return ExitSuccess;
    }

    // ======================================================================
    // 辅助
    // ======================================================================

    static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static int HandleUnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"未知命令: {cmd}");
        Console.Error.WriteLine("使用 'FileProtect help' 查看帮助。");
        return ExitError;
    }

    static void PrintDriverHelp()
    {
        Console.WriteLine("用法: FileProtect driver <子命令>");
        Console.WriteLine();
        Console.WriteLine("子命令:");
        Console.WriteLine("  install     安装 Ring0 驱动服务");
        Console.WriteLine("  start       启动 Ring0 驱动");
        Console.WriteLine("  stop        停止 Ring0 驱动");
        Console.WriteLine("  uninstall   卸载 Ring0 驱动服务");
        Console.WriteLine("  status      查看驱动状态");
    }

    static void PrintHelp()
    {
        string version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "1.0";

        Console.WriteLine($"""
            ═══════════════════════════════════════════════
              FileProtect v{version} — Windows 文件权限锁定工具
              防止指定文件的权限被篡改
            ═══════════════════════════════════════════════

            用法:
              FileProtect <命令> [参数]

            保护命令:
              protect   [--ring0] <路径>   保护文件
              unprotect [--ring0] <路径>   解除保护
              list                         列出所有受保护文件
              check     <路径>             检查保护状态

            驱动管理:
              driver install               安装 Ring0 驱动服务
              driver start                 启动 Ring0 驱动
              driver stop                  停止 Ring0 驱动
              driver uninstall             卸载 Ring0 驱动服务
              driver status                查看驱动状态

            帮助:
              help                         显示此帮助

            保护模式:
              默认:        用户态 ACL 保护（修改文件ACL，可被takeown绕过）
              --ring0:     Ring0 内核级保护（拦截SET_SECURITY，不可绕过）

            示例:
              FileProtect protect C:\config.ini
              FileProtect protect --ring0 C:\secret.key
              FileProtect unprotect --ring0 C:\secret.key
              FileProtect driver install && driver start
              FileProtect list
              FileProtect check C:\data.db

            注意: 所有命令均需要管理员权限
            """);
    }
}
