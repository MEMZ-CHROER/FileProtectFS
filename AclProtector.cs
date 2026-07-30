using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FileProtect;

/// <summary>
/// 核心ACL保护逻辑 — 通过P/Invoke直接调用Windows API操作安全描述符
/// </summary>
public static class AclProtector
{
    // ------------------------------------------------------------------ 常量

    private const uint ERROR_SUCCESS = 0;
    private const uint ERROR_ACCESS_DENIED = 5;
    private const uint ERROR_INVALID_PARAMETER = 87;

    // SE_OBJECT_TYPE
    private const uint SE_FILE_OBJECT = 1;

    // SECURITY_INFORMATION
    private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    private const uint GROUP_SECURITY_INFORMATION = 0x00000002;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;
    private const uint SACL_SECURITY_INFORMATION = 0x00000008;
    private const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;

    // TOKEN
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint SE_PRIVILEGE_ENABLED = 0x2;

    // 特权名
    private const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

    // SDDL 保护模板
    // O:SY          — 所有者 = SYSTEM
    // G:SY          — 主组 = SYSTEM
    // D:            — DACL开始
    // (D;;WDWOSD;;;WD) — Deny Everyone: WD(WriteDac) WO(WriteOwner) SD(Delete)
    // (D;;WDWO;;;BA)   — Deny Administrators: WD WO
    // (D;;WDWO;;;SY)   — Deny SYSTEM: WD WO
    // (A;;0x001F01FF;;;SY) — Allow SYSTEM: FILE_ALL_ACCESS
    // (A;;0x001F01FF;;;BA) — Allow Administrators: FILE_ALL_ACCESS
    // (A;;0x001200A9;;;WD) — Allow Everyone: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    private const string ProtectedSddlTemplate =
        "O:SYG:SYD:" +
        "(D;;WDWOSD;;;WD)" +
        "(D;;WDWO;;;BA)" +
        "(D;;WDWO;;;SY)" +
        "(A;;0x001F01FF;;;SY)" +
        "(A;;0x001F01FF;;;BA)" +
        "(A;;0x001200A9;;;WD)";

    // ------------------------------------------------------------------ P/Invoke

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetNamedSecurityInfo(
        string pObjectName, uint ObjectType, uint SecurityInfo,
        out IntPtr pSidOwner, out IntPtr pSidGroup,
        out IntPtr pDacl, out IntPtr pSacl,
        out IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfo(
        string pObjectName, uint ObjectType, uint SecurityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr SecurityDescriptor, uint RequestedStringSDRevision,
        uint SecurityInformation,
        out IntPtr StringSecurityDescriptor, out uint StringSecurityDescriptorLen);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor, uint StringSDRevision,
        out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(
        string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength,
        IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr pSid);

    // 安全描述符查询API
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorOwner(
        IntPtr pSecurityDescriptor, out IntPtr pOwner,
        [MarshalAs(UnmanagedType.Bool)] out bool lpbOwnerDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorGroup(
        IntPtr pSecurityDescriptor, out IntPtr pGroup,
        [MarshalAs(UnmanagedType.Bool)] out bool lpbGroupDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclPresent,
        out IntPtr pDacl, [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorSacl(
        IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool lpbSaclPresent,
        out IntPtr pSacl, [MarshalAs(UnmanagedType.Bool)] out bool lpbSaclDefaulted);

    // ------------------------------------------------------------------ 结构体

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    // ------------------------------------------------------------------ 公共API

    /// <summary>
    /// 备份文件当前安全描述符为SDDL
    /// </summary>
    public static BackupResult? BackupSecurity(string filePath)
    {
        string normalized = NormalizePath(filePath);
        if (!File.Exists(normalized))
            return new BackupResult { ErrorMessage = $"文件不存在: {normalized}" };

        uint result = GetNamedSecurityInfo(
            normalized, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            out IntPtr ownerSid, out IntPtr groupSid,
            out IntPtr dacl, out IntPtr sacl,
            out IntPtr securityDescriptor);

        if (result != ERROR_SUCCESS)
            return new BackupResult { ErrorMessage = $"获取安全描述符失败，错误码: {result}" };

        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    securityDescriptor, 1,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    out IntPtr sddlPtr, out _))
            {
                return new BackupResult { ErrorMessage = "转换安全描述符为SDDL失败" };
            }

            string sddl = Marshal.PtrToStringUni(sddlPtr) ?? "";
            LocalFree(sddlPtr);

            string? ownerSidStr = null;
            if (ownerSid != IntPtr.Zero && IsValidSid(ownerSid))
                ownerSidStr = ConvertSidToString(ownerSid);

            return new BackupResult { Success = true, Sddl = sddl, OwnerSid = ownerSidStr };
        }
        finally
        {
            LocalFree(securityDescriptor);
        }
    }

    /// <summary>
    /// 保护文件 — 锁定权限，防止任何修改
    /// </summary>
    public static OperationResult Protect(string filePath)
    {
        string normalized = NormalizePath(filePath);
        if (!File.Exists(normalized))
            return OperationResult.Fail($"文件不存在: {normalized}");

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                ProtectedSddlTemplate, 1,
                out IntPtr protectedSd, out _))
        {
            return OperationResult.Fail("构建保护安全描述符失败");
        }

        try
        {
            uint result = GetSecurityDescriptorInfo(
                protectedSd,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out IntPtr ownerSid, out IntPtr groupSid,
                out IntPtr dacl, out _);

            if (result != ERROR_SUCCESS)
                return OperationResult.Fail("解析保护安全描述符失败");

            // 启用特权以设置所有者
            EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);

            // 第一步：设置所有者和组
            result = SetNamedSecurityInfo(
                normalized, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
                ownerSid, groupSid, IntPtr.Zero, IntPtr.Zero);

            if (result != ERROR_SUCCESS)
            {
                return OperationResult.Fail(
                    $"设置所有者失败 (错误码: {result})。请以管理员身份运行。");
            }

            // 第二步：设置DACL — 此时进程已获取所有权，有隐式WRITE_DAC
            result = SetNamedSecurityInfo(
                normalized, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);

            if (result != ERROR_SUCCESS)
                return OperationResult.Fail($"设置DACL失败 (错误码: {result})");

            return OperationResult.Ok();
        }
        finally
        {
            LocalFree(protectedSd);
        }
    }

    /// <summary>
    /// 解除保护 — 从备份恢复原始安全描述符
    /// </summary>
    public static OperationResult Unprotect(string filePath, string backupSddl)
    {
        string normalized = NormalizePath(filePath);
        if (!File.Exists(normalized))
            return OperationResult.Fail($"文件不存在: {normalized}");

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                backupSddl, 1, out IntPtr backupSd, out _))
        {
            return OperationResult.Fail("解析备份SDDL失败，文件可能已损坏");
        }

        try
        {
            uint result = GetSecurityDescriptorInfo(
                backupSd,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out IntPtr ownerSid, out IntPtr groupSid,
                out IntPtr dacl, out _);

            if (result != ERROR_SUCCESS)
                return OperationResult.Fail("解析备份安全描述符失败");

            // 获取当前用户SID用于获取所有权
            IntPtr currentUserSid = GetCurrentUserSid();
            if (currentUserSid == IntPtr.Zero)
                return OperationResult.Fail("无法获取当前用户SID");

            try
            {
                EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);

                // 第一步：获取文件所有权
                result = SetNamedSecurityInfo(
                    normalized, SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    currentUserSid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (result != ERROR_SUCCESS)
                {
                    return OperationResult.Fail(
                        $"获取文件所有权失败 (错误码: {result})。请以管理员身份运行。");
                }

                // 第二步：恢复备份的完整安全描述符
                result = SetNamedSecurityInfo(
                    normalized, SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    ownerSid, groupSid, dacl, IntPtr.Zero);

                if (result != ERROR_SUCCESS)
                    return OperationResult.Fail($"恢复安全描述符失败 (错误码: {result})");
            }
            finally
            {
                Marshal.FreeHGlobal(currentUserSid);
            }

            return OperationResult.Ok();
        }
        finally
        {
            LocalFree(backupSd);
        }
    }

    /// <summary>
    /// 检查文件保护状态
    /// </summary>
    public static ProtectionCheckResult CheckProtection(string filePath)
    {
        string normalized = NormalizePath(filePath);
        if (!File.Exists(normalized))
            return ProtectionCheckResult.NotProtected("文件不存在");

        uint result = GetNamedSecurityInfo(
            normalized, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            out _, out _, out IntPtr dacl, out _,
            out IntPtr securityDescriptor);

        if (result != ERROR_SUCCESS)
            return ProtectionCheckResult.NotProtected($"无法获取安全描述符 (错误码: {result})");

        try
        {
            if (dacl == IntPtr.Zero)
                return ProtectionCheckResult.NotProtected("无DACL (文件不受保护)");

            // 读取ACL并解析
            ushort aclSize = (ushort)Marshal.ReadInt16(dacl, 2);
            byte[] aclBytes = new byte[aclSize];
            Marshal.Copy(dacl, aclBytes, 0, aclSize);

            var rawAcl = new RawAcl(aclBytes, 0);
            var worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            foreach (CommonAce? ace in rawAcl)
            {
                if (ace == null) continue;

                if (ace.AceQualifier == AceQualifier.AccessDenied &&
                    ace.SecurityIdentifier.Equals(worldSid))
                {
                    int denyMask = (int)ace.AccessMask;
                    if ((denyMask & 0x00040000) != 0) // WRITE_DAC
                    {
                        return ProtectionCheckResult.Protected("受保护 — DACL拒绝修改权限");
                    }
                }
            }

            // 如果DACL检查没有结论，检查所有者
            uint ownerResult = GetNamedSecurityInfo(
                normalized, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                out IntPtr ownerSid, out _, out _, out _, out _);

            if (ownerResult == ERROR_SUCCESS && ownerSid != IntPtr.Zero)
            {
                var sid = new SecurityIdentifier(ownerSid);
                if (sid.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)))
                {
                    return ProtectionCheckResult.Protected("受保护 — 所有者为SYSTEM");
                }
            }

            return ProtectionCheckResult.NotProtected("未检测到保护");
        }
        finally
        {
            LocalFree(securityDescriptor);
        }
    }

    // ------------------------------------------------------------------ 辅助方法

    /// <summary>规范化文件路径，支持长路径</summary>
    public static string NormalizePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        if (fullPath.Length >= 260 && !fullPath.StartsWith(@"\\?\"))
            fullPath = @"\\?\" + fullPath;
        return fullPath;
    }

    /// <summary>启用指定特权</summary>
    private static bool EnablePrivilege(string privilegeName)
    {
        IntPtr hProcess = GetCurrentProcess();
        if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
            return false;

        try
        {
            if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
                return false;

            var privileges = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                }
            };

            return AdjustTokenPrivileges(
                hToken, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(hToken);
        }
    }

    /// <summary>从安全描述符中提取OWNER/GROUP/DACL/SACL</summary>
    private static uint GetSecurityDescriptorInfo(
        IntPtr securityDescriptor, uint securityInfo,
        out IntPtr ownerSid, out IntPtr groupSid,
        out IntPtr dacl, out IntPtr sacl)
    {
        ownerSid = IntPtr.Zero;
        groupSid = IntPtr.Zero;
        dacl = IntPtr.Zero;
        sacl = IntPtr.Zero;

        try
        {
            if ((securityInfo & OWNER_SECURITY_INFORMATION) != 0)
            {
                if (!GetSecurityDescriptorOwner(securityDescriptor, out IntPtr owner, out _))
                    return (uint)Marshal.GetLastWin32Error();
                ownerSid = owner;
            }

            if ((securityInfo & GROUP_SECURITY_INFORMATION) != 0)
            {
                if (!GetSecurityDescriptorGroup(securityDescriptor, out IntPtr group, out _))
                    return (uint)Marshal.GetLastWin32Error();
                groupSid = group;
            }

            if ((securityInfo & DACL_SECURITY_INFORMATION) != 0)
            {
                if (!GetSecurityDescriptorDacl(securityDescriptor, out bool hasDacl, out IntPtr acl, out _))
                    return (uint)Marshal.GetLastWin32Error();
                dacl = hasDacl ? acl : IntPtr.Zero;
            }

            if ((securityInfo & SACL_SECURITY_INFORMATION) != 0)
            {
                if (!GetSecurityDescriptorSacl(securityDescriptor, out bool hasSacl, out IntPtr saclPtr, out _))
                    return (uint)Marshal.GetLastWin32Error();
                sacl = hasSacl ? saclPtr : IntPtr.Zero;
            }

            return ERROR_SUCCESS;
        }
        catch
        {
            return ERROR_ACCESS_DENIED;
        }
    }

    /// <summary>获取当前用户的SID指针（调用者需调用 Marshal.FreeHGlobal 释放）</summary>
    private static IntPtr GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User;
        if (sid == null) return IntPtr.Zero;

        byte[] sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        IntPtr sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
        Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
        return sidPtr;
    }

    /// <summary>将SID指针转换为字符串</summary>
    private static string? ConvertSidToString(IntPtr sidPtr)
    {
        try
        {
            return new SecurityIdentifier(sidPtr).Value;
        }
        catch
        {
            return null;
        }
    }
}

// ------------------------------------------------------------------ 结果类型

public class BackupResult
{
    public bool Success { get; set; }
    public string? Sddl { get; set; }
    public string? OwnerSid { get; set; }
    public string? ErrorMessage { get; set; }
}

public class OperationResult
{
    public bool Success { get; private set; }
    public string? ErrorMessage { get; private set; }

    public static OperationResult Ok() => new() { Success = true };
    public static OperationResult Fail(string msg) => new() { Success = false, ErrorMessage = msg };
}

public class ProtectionCheckResult
{
    public bool IsProtected { get; private set; }
    public string? Detail { get; private set; }

    public static ProtectionCheckResult Protected(string detail) =>
        new() { IsProtected = true, Detail = detail };

    public static ProtectionCheckResult NotProtected(string detail) =>
        new() { IsProtected = false, Detail = detail };
}
