using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace FileProtect;

/// <summary>
/// Ring0 驱动通信与管理 — 通过 IOCTL 与 FileProtectFS.sys 交互
/// </summary>
public sealed class Ring0Protector : IDisposable
{
    // ---------------------------------------------------------------- IOCTL 定义

    private const uint FILE_DEVICE_UNKNOWN = 0x800F;
    private const uint METHOD_BUFFERED = 0;

    // CTL_CODE(DeviceType, Function, Method, Access) — 在 C# 中用静态只读字段
    // CTL_CODE = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    private static readonly uint IOCTL_FILEPROTECT_ADD_FILE =
        (FILE_DEVICE_UNKNOWN << 16) | (0x800 << 2) | METHOD_BUFFERED;
    private static readonly uint IOCTL_FILEPROTECT_REMOVE_FILE =
        (FILE_DEVICE_UNKNOWN << 16) | (0x801 << 2) | METHOD_BUFFERED;
    private static readonly uint IOCTL_FILEPROTECT_CLEAR_ALL =
        (FILE_DEVICE_UNKNOWN << 16) | (0x802 << 2) | METHOD_BUFFERED;
    private static readonly uint IOCTL_FILEPROTECT_QUERY_LIST =
        (FILE_DEVICE_UNKNOWN << 16) | (0x803 << 2) | METHOD_BUFFERED;
    private static readonly uint IOCTL_FILEPROTECT_GET_COUNT =
        (FILE_DEVICE_UNKNOWN << 16) | (0x804 << 2) | METHOD_BUFFERED;

    private const int FILEPROTECT_MAX_PATH = 1024;

    private const string DeviceName = @"\\.\FileProtectFS";
    private const string DriverServiceName = "FileProtectFS";
    private const string DriverSysName = "FileProtectFS.sys";
    private const string DriverRegistryPath = @"SYSTEM\CurrentControlSet\Services\FileProtectFS";

    // ---------------------------------------------------------------- P/Invoke

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        byte[]? lpInBuffer, uint nInBufferSize,
        byte[]? lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    // ---------------------------------------------------------------- SCM API

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(
        string? lpMachineName, string? lpDatabaseName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr hSCManager, string lpServiceName,
        string lpDisplayName, uint dwDesiredAccess,
        uint dwServiceType, uint dwStartType,
        uint dwErrorControl, string lpBinaryPathName,
        string? lpLoadOrderGroup, IntPtr lpdwTagId,
        string? lpDependencies, string? lpServiceStartName,
        string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(
        IntPtr hSCManager, string lpServiceName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(
        IntPtr hService, uint dwNumServiceArgs,
        string?[]? lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(
        IntPtr hService, uint dwControl,
        ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(
        IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

    // ---------------------------------------------------------------- 结构体

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private const uint SERVICE_STOPPED = 0x00000001;
    private const uint SERVICE_RUNNING = 0x00000004;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const uint SERVICE_KERNEL_DRIVER = 0x00000001;
    private const uint SERVICE_DEMAND_START = 0x00000003;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;

    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;

    private const uint GENERIC_READ = 0x80000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;

    // ---------------------------------------------------------------- 内部状态

    private SafeFileHandle? _deviceHandle;
    private readonly string _driverSysPath;

    public Ring0Protector()
    {
        // 自动定位驱动文件
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string testPath = Path.Combine(baseDir, DriverSysName);
        if (File.Exists(testPath))
            _driverSysPath = testPath;
        else
            _driverSysPath = testPath; // 默认路径，可被改写
    }

    public void Dispose()
    {
        CloseDevice();
    }

    // ---------------------------------------------------------------- 驱动管理

    /// <summary>
    /// 检测驱动是否已安装
    /// </summary>
    public static bool IsDriverInstalled()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(DriverRegistryPath, false);
        return key != null;
    }

    /// <summary>
    /// 检测驱动是否正在运行
    /// </summary>
    public bool IsDriverRunning()
    {
        IntPtr hSCM = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero) return false;

        IntPtr hService = OpenService(hSCM, DriverServiceName, SERVICE_ALL_ACCESS);
        if (hService == IntPtr.Zero)
        {
            CloseServiceHandle(hSCM);
            return false;
        }

        var status = new SERVICE_STATUS();
        bool result = QueryServiceStatus(hService, ref status);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);

        return result && status.dwCurrentState == SERVICE_RUNNING;
    }

    /// <summary>
    /// 安装驱动服务（如果尚未安装）
    /// </summary>
    public OperationResult InstallDriver()
    {
        if (IsDriverInstalled())
            return OperationResult.Ok(); // 已安装

        IntPtr hSCM = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
            return OperationResult.Fail("无法打开服务管理器 (需要管理员权限)");

        try
        {
            if (!File.Exists(_driverSysPath))
                return OperationResult.Fail($"驱动文件不存在: {_driverSysPath}\n请先编译驱动并将 {DriverSysName} 放到程序目录。");

            IntPtr hService = CreateService(
                hSCM, DriverServiceName, "FileProtectFS — Ring0 File ACL Guard",
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                _driverSysPath, "FSFilter Activity Monitor", IntPtr.Zero,
                null, null, null);

            if (hService == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                // ERROR_SERVICE_EXISTS (1073) 表示已存在，不视为错误
                if (err == 1073)
                    return OperationResult.Ok();
                return OperationResult.Fail($"创建服务失败 (错误码: {err})");
            }

            CloseServiceHandle(hService);
            return OperationResult.Ok();
        }
        finally
        {
            CloseServiceHandle(hSCM);
        }
    }

    /// <summary>
    /// 启动驱动
    /// </summary>
    public OperationResult StartDriver()
    {
        if (IsDriverRunning())
            return OperationResult.Ok();

        IntPtr hSCM = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
            return OperationResult.Fail("无法打开服务管理器");

        try
        {
            IntPtr hService = OpenService(hSCM, DriverServiceName, SERVICE_ALL_ACCESS);
            if (hService == IntPtr.Zero)
                return OperationResult.Fail($"驱动服务未安装。请先执行 'driver install'。错误码: {Marshal.GetLastWin32Error()}");

            try
            {
                if (!StartService(hService, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 1056) // SERVICE_ALREADY_RUNNING
                        return OperationResult.Ok();
                    return OperationResult.Fail($"启动驱动失败 (错误码: {err})");
                }

                // 等待驱动启动
                System.Threading.Thread.Sleep(500);
                return OperationResult.Ok();
            }
            finally
            {
                CloseServiceHandle(hService);
            }
        }
        finally
        {
            CloseServiceHandle(hSCM);
        }
    }

    /// <summary>
    /// 停止驱动
    /// </summary>
    public OperationResult StopDriver()
    {
        if (!IsDriverRunning())
            return OperationResult.Ok();

        IntPtr hSCM = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
            return OperationResult.Fail("无法打开服务管理器");

        try
        {
            IntPtr hService = OpenService(hSCM, DriverServiceName, SERVICE_ALL_ACCESS);
            if (hService == IntPtr.Zero)
                return OperationResult.Fail("驱动服务未安装");

            try
            {
                var status = new SERVICE_STATUS();
                if (!ControlService(hService, SERVICE_CONTROL_STOP, ref status))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 1062) // SERVICE_NOT_ACTIVE
                        return OperationResult.Ok();
                    return OperationResult.Fail($"停止驱动失败 (错误码: {err})");
                }

                return OperationResult.Ok();
            }
            finally
            {
                CloseServiceHandle(hService);
            }
        }
        finally
        {
            CloseServiceHandle(hSCM);
        }
    }

    /// <summary>
    /// 卸载驱动服务
    /// </summary>
    public OperationResult UninstallDriver()
    {
        // 先停止
        var stopResult = StopDriver();
        if (!stopResult.Success)
            return stopResult;

        IntPtr hSCM = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (hSCM == IntPtr.Zero)
            return OperationResult.Fail("无法打开服务管理器");

        try
        {
            IntPtr hService = OpenService(hSCM, DriverServiceName, SERVICE_ALL_ACCESS);
            if (hService == IntPtr.Zero)
                return OperationResult.Ok(); // 已不存在

            try
            {
                if (!DeleteService(hService))
                {
                    int err = Marshal.GetLastWin32Error();
                    return OperationResult.Fail($"删除服务失败 (错误码: {err})");
                }

                return OperationResult.Ok();
            }
            finally
            {
                CloseServiceHandle(hService);
            }
        }
        finally
        {
            CloseServiceHandle(hSCM);
        }
    }

    // ---------------------------------------------------------------- 设备通信

    /// <summary>打开设备</summary>
    private bool OpenDevice()
    {
        if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            return true;

        _deviceHandle = CreateFile(
            DeviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        return _deviceHandle != null && !_deviceHandle.IsInvalid;
    }

    /// <summary>关闭设备</summary>
    private void CloseDevice()
    {
        if (_deviceHandle != null && !_deviceHandle.IsInvalid)
        {
            _deviceHandle.Close();
            _deviceHandle = null;
        }
    }

    /// <summary>
    /// 确保驱动就绪：安装并启动
    /// </summary>
    public OperationResult EnsureDriverReady()
    {
        // 先尝试直接打开设备
        if (OpenDevice())
            return OperationResult.Ok();

        // 尝试安装并启动
        var installResult = InstallDriver();
        if (!installResult.Success)
            return installResult;

        var startResult = StartDriver();
        if (!startResult.Success)
            return startResult;

        // 等待设备就绪
        for (int i = 0; i < 10; i++)
        {
            System.Threading.Thread.Sleep(200);
            if (OpenDevice())
                return OperationResult.Ok();
        }

        return OperationResult.Fail("驱动已启动但设备不可用");
    }

    /// <summary>
    /// 添加受保护文件（Ring0）
    /// </summary>
    public OperationResult AddProtectedFile(string filePath)
    {
        if (!OpenDevice())
            return OperationResult.Fail("驱动未运行。请先执行 'driver start'。");

        string fullPath = Path.GetFullPath(filePath);
        byte[] inBuf = EncodePathBuffer(fullPath);

        if (!DeviceIoControl(_deviceHandle!, IOCTL_FILEPROTECT_ADD_FILE,
                inBuf, (uint)inBuf.Length, null, 0, out _, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 0) err = Marshal.GetLastWin32Error();
            return OperationResult.Fail($"驱动拒绝添加 (错误码: {err})");
        }

        return OperationResult.Ok();
    }

    /// <summary>
    /// 移除受保护文件（Ring0）
    /// </summary>
    public OperationResult RemoveProtectedFile(string filePath)
    {
        if (!OpenDevice())
            return OperationResult.Fail("驱动未运行");

        string fullPath = Path.GetFullPath(filePath);
        byte[] inBuf = EncodePathBuffer(fullPath);

        if (!DeviceIoControl(_deviceHandle!, IOCTL_FILEPROTECT_REMOVE_FILE,
                inBuf, (uint)inBuf.Length, null, 0, out _, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            return OperationResult.Fail($"驱动拒绝移除 (错误码: {err})");
        }

        return OperationResult.Ok();
    }

    /// <summary>
    /// 清空受保护文件列表（Ring0）
    /// </summary>
    public OperationResult ClearProtectedFiles()
    {
        if (!OpenDevice())
            return OperationResult.Fail("驱动未运行");

        if (!DeviceIoControl(_deviceHandle!, IOCTL_FILEPROTECT_CLEAR_ALL,
                null, 0, null, 0, out _, IntPtr.Zero))
        {
            return OperationResult.Fail("驱动拒绝清空列表");
        }

        return OperationResult.Ok();
    }

    /// <summary>
    /// 查询受保护文件列表（Ring0）
    /// </summary>
    public List<ProtectedFileInfo> QueryProtectedFiles()
    {
        var result = new List<ProtectedFileInfo>();

        if (!OpenDevice())
            return result;

        var outBuf = new byte[sizeof_QueryEntry * 256];
        if (!DeviceIoControl(_deviceHandle!, IOCTL_FILEPROTECT_QUERY_LIST,
                null, 0, outBuf, (uint)outBuf.Length, out uint bytesReturned, IntPtr.Zero))
        {
            return result;
        }

        int count = (int)(bytesReturned / sizeof_QueryEntry);
        for (int i = 0; i < count; i++)
        {
            int offset = i * sizeof_QueryEntry;
            string path = System.Text.Encoding.Unicode.GetString(outBuf, offset, FILEPROTECT_MAX_PATH * 2);
            path = path.TrimEnd('\0');

            long ft = BitConverter.ToInt64(outBuf, offset + FILEPROTECT_MAX_PATH * 2);
            DateTime? addTime = ft > 0
                ? DateTime.FromFileTimeUtc(ft)
                : null;

            result.Add(new ProtectedFileInfo
            {
                NormalizedPath = path,
                ProtectedAtUtc = addTime
            });
        }

        return result;
    }

    /// <summary>
    /// 获取驱动中受保护文件数量
    /// </summary>
    public int GetProtectedCount()
    {
        if (!OpenDevice()) return -1;

        byte[] outBuf = new byte[4];
        if (!DeviceIoControl(_deviceHandle!, IOCTL_FILEPROTECT_GET_COUNT,
                null, 0, outBuf, 4, out _, IntPtr.Zero))
        {
            return -1;
        }

        return BitConverter.ToInt32(outBuf, 0);
    }

    // ---------------------------------------------------------------- 辅助

    private static int sizeof_QueryEntry = FILEPROTECT_MAX_PATH * 2 + 8;

    private static byte[] EncodePathBuffer(string path)
    {
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(path + '\0');
        if (bytes.Length > FILEPROTECT_MAX_PATH * 2)
            Array.Resize(ref bytes, FILEPROTECT_MAX_PATH * 2);
        return bytes;
    }
}
