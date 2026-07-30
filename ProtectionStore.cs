using Microsoft.Win32;

namespace FileProtect;

/// <summary>
/// 管理受保护文件的ACL备份存储（基于注册表）
/// </summary>
public sealed class ProtectionStore : IDisposable
{
    private const string RegistryRoot = @"Software\FileProtect";
    private const string FilesKey = RegistryRoot + @"\Files";
    private const string SettingsKey = RegistryRoot + @"\Settings";

    /// <summary>保护时的原始安全描述符（SDDL）</summary>
    public string? BackupSddl { get; private set; }

    /// <summary>保护时间（UTC）</summary>
    public DateTime? ProtectedAtUtc { get; private set; }

    // ------------------------------------------------------------------ 公共API

    /// <summary>
    /// 保存文件保护备份
    /// </summary>
    public void SaveBackup(string normalizedPath, string sddl, string? originalOwnerSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sddl);

        string keyName = EscapePath(normalizedPath);
        using var key = Registry.CurrentUser.CreateSubKey(FilesKey, true)
            ?? throw new InvalidOperationException("无法创建注册表键: " + FilesKey);

        using var subKey = key.CreateSubKey(keyName, true);
        subKey.SetValue("Sddl", sddl, RegistryValueKind.String);
        subKey.SetValue("ProtectedAt", DateTime.UtcNow.ToString("O"), RegistryValueKind.String);
        if (originalOwnerSid != null)
            subKey.SetValue("OriginalOwner", originalOwnerSid, RegistryValueKind.String);

        BackupSddl = sddl;
        ProtectedAtUtc = DateTime.UtcNow;
    }

    /// <summary>
    /// 读取文件保护备份
    /// </summary>
    public bool LoadBackup(string normalizedPath)
    {
        string keyName = EscapePath(normalizedPath);
        using var key = Registry.CurrentUser.OpenSubKey(FilesKey, false);
        if (key == null) return false;

        using var subKey = key.OpenSubKey(keyName, false);
        if (subKey == null) return false;

        BackupSddl = subKey.GetValue("Sddl") as string;
        string? protectedAtStr = subKey.GetValue("ProtectedAt") as string;
        ProtectedAtUtc = protectedAtStr != null ? DateTime.Parse(protectedAtStr, null, System.Globalization.DateTimeStyles.RoundtripKind) : null;

        return BackupSddl != null;
    }

    /// <summary>
    /// 删除文件保护备份
    /// </summary>
    public void DeleteBackup(string normalizedPath)
    {
        string keyName = EscapePath(normalizedPath);
        using var key = Registry.CurrentUser.OpenSubKey(FilesKey, true);
        if (key != null)
        {
            key.DeleteSubKeyTree(keyName, false);
        }
        BackupSddl = null;
        ProtectedAtUtc = null;
    }

    /// <summary>
    /// 列出所有受保护文件的路径
    /// </summary>
    public List<ProtectedFileInfo> ListProtectedFiles()
    {
        var result = new List<ProtectedFileInfo>();
        using var key = Registry.CurrentUser.OpenSubKey(FilesKey, false);
        if (key == null) return result;

        foreach (var subKeyName in key.GetSubKeyNames())
        {
            try
            {
                using var subKey = key.OpenSubKey(subKeyName, false);
                if (subKey == null) continue;

                string? sddl = subKey.GetValue("Sddl") as string;
                string? protectedAt = subKey.GetValue("ProtectedAt") as string;
                string? originalOwner = subKey.GetValue("OriginalOwner") as string;

                result.Add(new ProtectedFileInfo
                {
                    NormalizedPath = UnescapePath(subKeyName),
                    BackupSddl = sddl ?? "",
                    ProtectedAtUtc = protectedAt != null ? DateTime.Parse(protectedAt, null, System.Globalization.DateTimeStyles.RoundtripKind) : null,
                    OriginalOwnerSid = originalOwner
                });
            }
            catch
            {
                // 跳过无法读取的项
            }
        }

        return result;
    }

    /// <summary>
    /// 检查文件是否在受保护列表中
    /// </summary>
    public bool IsProtected(string normalizedPath)
    {
        string keyName = EscapePath(normalizedPath);
        using var key = Registry.CurrentUser.OpenSubKey(FilesKey, false);
        if (key == null) return false;

        using var subKey = key.OpenSubKey(keyName, false);
        return subKey != null;
    }

    // ------------------------------------------------------------------ 存储配置

    /// <summary>
    /// 存储是否为首次运行的标记
    /// </summary>
    public void SetFirstRunComplete()
    {
        using var key = Registry.CurrentUser.CreateSubKey(SettingsKey, true);
        key.SetValue("FirstRun", 1, RegistryValueKind.DWord);
    }

    public bool IsFirstRunComplete()
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey, false);
        return key?.GetValue("FirstRun") is int v && v == 1;
    }

    // ------------------------------------------------------------------ Helper

    /// <summary>将文件路径编码为注册表键名（安全转义）</summary>
    private static string EscapePath(string path)
    {
        // 将完整路径用 Base64 编码以避免路径中特殊字符的问题
        // 但为了可读性，用 URL 风格的编码替换特殊字符
        var sb = new System.Text.StringBuilder(path.Length);
        foreach (char c in path)
        {
            if (char.IsLetterOrDigit(c) || c == '\\' || c == ':' || c == '.' || c == '_' || c == '-')
                sb.Append(c == '\\' ? '/' : c);
            else
                sb.Append($"%{(int)c:X2}");
        }
        return sb.ToString();
    }

    /// <summary>将注册表键名解码回文件路径</summary>
    private static string UnescapePath(string encoded)
    {
        var sb = new System.Text.StringBuilder(encoded.Length);
        for (int i = 0; i < encoded.Length; i++)
        {
            if (encoded[i] == '%' && i + 2 < encoded.Length)
            {
                string hex = encoded.Substring(i + 1, 2);
                if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out int val))
                {
                    sb.Append((char)val);
                    i += 2;
                    continue;
                }
            }
            sb.Append(encoded[i] == '/' ? '\\' : encoded[i]);
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        // 注册表句柄由.NET管理，无需手动释放
    }
}

/// <summary>
/// 受保护文件的信息
/// </summary>
public class ProtectedFileInfo
{
    public string NormalizedPath { get; set; } = "";
    public string BackupSddl { get; set; } = "";
    public DateTime? ProtectedAtUtc { get; set; }
    public string? OriginalOwnerSid { get; set; }

    public DateTime? ProtectedAtLocal => ProtectedAtUtc?.ToLocalTime();
}
