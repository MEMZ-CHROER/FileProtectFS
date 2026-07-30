/*++
 * FileProtect — Ring0 文件权限锁定驱动
 *
 * 通过 Minifilter 框架拦截 IRP_MJ_SET_SECURITY，
 * 在内核层阻止任何用户态进程（包括管理员）
 * 修改受保护文件的 ACL。
 *
 * 架构:
 *   - Minifilter 回调: PreSetSecurity 拒绝受保护文件的权限修改
 *   - 控制设备:       \Device\FileProtectFS 接收用户态 IOCTL
 *
 * 构建: WDK 10/11, MSBuild
--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "fileprotect.h"

#pragma prefast(disable: __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

// ======================================================================
// 全局数据
// ======================================================================

// Filter 句柄
PFLT_FILTER g_FilterHandle = NULL;

// 控制设备对象
PDEVICE_OBJECT g_ControlDeviceObject = NULL;

// 受保护文件列表 — 双向链表 + FastMutex 保护
typedef struct _PROTECTED_FILE_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING FilePath;
    LARGE_INTEGER AddTime;
} PROTECTED_FILE_ENTRY, *PPROTECTED_FILE_ENTRY;

static LIST_ENTRY g_ProtectedFileList;
static FAST_MUTEX  g_ListLock;

// 安全描述符 — 用于拒绝 WRITE_DAC/WRITE_OWNER 的 SDDL 模板（预解析缓存）
static PSECURITY_DESCRIPTOR g_ProtectedSdCache = NULL;

// ======================================================================
// 受保护文件列表管理
// ======================================================================

NTSTATUS
AddFileNameToList(
    _In_ PCWSTR FileName
)
{
    NTSTATUS status;
    UNICODE_STRING uniPath;
    PPROTECTED_FILE_ENTRY entry;
    PPROTECTED_FILE_ENTRY existing;

    // 将路径统一转换为小写
    RtlInitUnicodeString(&uniPath, FileName);
    if (!NT_SUCCESS(RtlDowncaseUnicodeString(&uniPath, &uniPath)))
        return STATUS_INSUFFICIENT_RESOURCES;

    // 分配新条目
    entry = (PPROTECTED_FILE_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PROTECTED_FILE_ENTRY), 'EPF');
    if (entry == NULL) {
        RtlFreeUnicodeString(&uniPath);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 拷贝路径
    entry->FilePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, uniPath.MaximumLength, 'PF');
    if (entry->FilePath.Buffer == NULL) {
        ExFreePool(entry);
        RtlFreeUnicodeString(&uniPath);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(entry->FilePath.Buffer, uniPath.Buffer, uniPath.MaximumLength);
    entry->FilePath.Length = uniPath.Length;
    entry->FilePath.MaximumLength = uniPath.MaximumLength;
    KeQuerySystemTime(&entry->AddTime);

    // 查重
    ExAcquireFastMutex(&g_ListLock);
    for (PLIST_ENTRY le = g_ProtectedFileList.Flink; le != &g_ProtectedFileList; le = le->Flink) {
        existing = CONTAINING_RECORD(le, PROTECTED_FILE_ENTRY, ListEntry);
        if (RtlEqualUnicodeString(&existing->FilePath, &uniPath, TRUE)) {
            ExReleaseFastMutex(&g_ListLock);
            ExFreePool(entry->FilePath.Buffer);
            ExFreePool(entry);
            RtlFreeUnicodeString(&uniPath);
            return STATUS_OBJECT_NAME_EXISTS;
        }
    }

    InsertTailList(&g_ProtectedFileList, &entry->ListEntry);
    ExReleaseFastMutex(&g_ListLock);

    RtlFreeUnicodeString(&uniPath);
    return STATUS_SUCCESS;
}

NTSTATUS
RemoveFileNameFromList(
    _In_ PCWSTR FileName
)
{
    UNICODE_STRING uniPath;
    PPROTECTED_FILE_ENTRY entry;

    RtlInitUnicodeString(&uniPath, FileName);
    if (!NT_SUCCESS(RtlDowncaseUnicodeString(&uniPath, &uniPath)))
        return STATUS_INSUFFICIENT_RESOURCES;

    ExAcquireFastMutex(&g_ListLock);
    for (PLIST_ENTRY le = g_ProtectedFileList.Flink; le != &g_ProtectedFileList; le = le->Flink) {
        entry = CONTAINING_RECORD(le, PROTECTED_FILE_ENTRY, ListEntry);
        if (RtlEqualUnicodeString(&entry->FilePath, &uniPath, TRUE)) {
            RemoveEntryList(&entry->ListEntry);
            ExReleaseFastMutex(&g_ListLock);
            RtlFreeUnicodeString(&entry->FilePath);
            ExFreePool(entry);
            RtlFreeUnicodeString(&uniPath);
            return STATUS_SUCCESS;
        }
    }
    ExReleaseFastMutex(&g_ListLock);

    RtlFreeUnicodeString(&uniPath);
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

BOOLEAN
IsFilePathProtected(
    _In_ PUNICODE_STRING FilePath
)
{
    BOOLEAN found = FALSE;
    UNICODE_STRING pathCopy;
    PPROTECTED_FILE_ENTRY entry;

    // 小写化路径以便比较
    if (!NT_SUCCESS(RtlDowncaseUnicodeString(&pathCopy, FilePath)))
        return FALSE;

    ExAcquireFastMutex(&g_ListLock);
    for (PLIST_ENTRY le = g_ProtectedFileList.Flink; le != &g_ProtectedFileList; le = le->Flink) {
        entry = CONTAINING_RECORD(le, PROTECTED_FILE_ENTRY, ListEntry);
        if (RtlEqualUnicodeString(&entry->FilePath, &pathCopy, TRUE)) {
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_ListLock);

    RtlFreeUnicodeString(&pathCopy);
    return found;
}

VOID
ClearProtectedList(VOID)
{
    ExAcquireFastMutex(&g_ListLock);
    while (!IsListEmpty(&g_ProtectedFileList)) {
        PLIST_ENTRY le = RemoveHeadList(&g_ProtectedFileList);
        PPROTECTED_FILE_ENTRY entry = CONTAINING_RECORD(le, PROTECTED_FILE_ENTRY, ListEntry);
        RtlFreeUnicodeString(&entry->FilePath);
        ExFreePool(entry);
    }
    ExReleaseFastMutex(&g_ListLock);
}

ULONG
GetProtectedListCount(VOID)
{
    ULONG count = 0;
    ExAcquireFastMutex(&g_ListLock);
    for (PLIST_ENTRY le = g_ProtectedFileList.Flink; le != &g_ProtectedFileList; le = le->Flink)
        count++;
    ExReleaseFastMutex(&g_ListLock);
    return count;
}

// ======================================================================
// 路径获取 — 从 PreSetSecurity 的 CallbackData 中提取文件路径
// ======================================================================

NTSTATUS
GetFilePathFromCallbackData(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FilePath
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    // 只在 PASSIVE_LEVEL 获取文件名
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS,
        &nameInfo);

    if (!NT_SUCCESS(status))
        return status;

    // 解析文件名信息，提取完整路径
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    // 复制路径
    status = RtlDuplicateUnicodeString(RTL_DUPSTR_ADD_NULL, &nameInfo->Name, FilePath);

    FltReleaseFileNameInformation(nameInfo);
    return status;
}

// ======================================================================
// Minifilter 回调 — PreSetSecurity
// ======================================================================

FLT_PREOP_CALLBACK_STATUS
FileProtectPreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_opt_result_maybenull_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS status;
    UNICODE_STRING filePath;
    BOOLEAN protected = FALSE;

    // 只拦截 DACL 和 OWNER 修改（权限修改的关键）
    SECURITY_INFORMATION secInfo = Data->Iopb->Parameters.SetSecurity.SecurityInformation;
    if (!(secInfo & (DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION)))
        return FLT_PREOP_SUCCESS;

    // 获取文件路径并检查是否受保护
    RtlZeroMemory(&filePath, sizeof(filePath));
    status = GetFilePathFromCallbackData(Data, &filePath);
    if (NT_SUCCESS(status)) {
        protected = IsFilePathProtected(&filePath);
        RtlFreeUnicodeString(&filePath);
    }

    if (protected) {
        // ===== 关键：在内核层直接拒绝 SET_SECURITY =====
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS;
}

// ======================================================================
// IOCTL 处理
// ======================================================================

NTSTATUS
FileProtectDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;   // METHOD_BUFFERED
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG bytesReturned = 0;

    switch (code) {

    case IOCTL_FILEPROTECT_ADD_FILE: {
        if (inLen < sizeof(FILEPROTECT_IOCTL_BUFFER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFILEPROTECT_IOCTL_BUFFER buf = (PFILEPROTECT_IOCTL_BUFFER)inBuf;
        status = AddFileNameToList(buf->FilePath);
        break;
    }

    case IOCTL_FILEPROTECT_REMOVE_FILE: {
        if (inLen < sizeof(FILEPROTECT_IOCTL_BUFFER)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PFILEPROTECT_IOCTL_BUFFER buf = (PFILEPROTECT_IOCTL_BUFFER)inBuf;
        status = RemoveFileNameFromList(buf->FilePath);
        break;
    }

    case IOCTL_FILEPROTECT_CLEAR_ALL: {
        ClearProtectedList();
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_FILEPROTECT_QUERY_LIST: {
        if (outLen < sizeof(FILEPROTECT_QUERY_ENTRY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PFILEPROTECT_QUERY_ENTRY outBufQuery = (PFILEPROTECT_QUERY_ENTRY)outBuf;
        ULONG maxEntries = outLen / sizeof(FILEPROTECT_QUERY_ENTRY);
        ULONG entriesWritten = 0;

        ExAcquireFastMutex(&g_ListLock);
        for (PLIST_ENTRY le = g_ProtectedFileList.Flink;
             le != &g_ProtectedFileList && entriesWritten < maxEntries;
             le = le->Flink)
        {
            PPROTECTED_FILE_ENTRY entry = CONTAINING_RECORD(le, PROTECTED_FILE_ENTRY, ListEntry);
            RtlZeroMemory(&outBufQuery[entriesWritten], sizeof(FILEPROTECT_QUERY_ENTRY));
            ULONG copyLen = min(entry->FilePath.Length,
                                (sizeof(outBufQuery[entriesWritten].FilePath) - sizeof(WCHAR)));
            RtlCopyMemory(outBufQuery[entriesWritten].FilePath,
                          entry->FilePath.Buffer, copyLen);
            outBufQuery[entriesWritten].FilePath[copyLen / sizeof(WCHAR)] = L'\0';
            outBufQuery[entriesWritten].AddTime = entry->AddTime;
            entriesWritten++;
        }
        ExReleaseFastMutex(&g_ListLock);

        bytesReturned = entriesWritten * sizeof(FILEPROTECT_QUERY_ENTRY);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_FILEPROTECT_GET_COUNT: {
        if (outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(PULONG)outBuf = GetProtectedListCount();
        bytesReturned = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    // 完成 IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
FileProtectCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ======================================================================
// 控制设备管理
// ======================================================================

NTSTATUS
CreateControlDevice(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;

    RtlInitUnicodeString(&deviceName, L"\\Device\\FileProtectFS");
    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\FileProtectFS");

    // 创建设备
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_ControlDeviceObject);

    if (!NT_SUCCESS(status))
        return status;

    // 设备默认不缓冲，IOCTL 使用 METHOD_BUFFERED
    g_ControlDeviceObject->Flags |= DO_BUFFERED_IO;

    // 创建符号链接
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
        return status;
    }

    // 设置 MajorFunction
    DriverObject->MajorFunction[IRP_MJ_CREATE] = FileProtectCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FileProtectCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FileProtectDeviceControl;

    return STATUS_SUCCESS;
}

VOID
DeleteControlDevice(VOID)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\FileProtectFS");
    IoDeleteSymbolicLink(&symLinkName);

    if (g_ControlDeviceObject) {
        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
    }
}

// ======================================================================
// Minifilter 注册
// ======================================================================

FLT_PREOP_CALLBACK_STATUS
FileProtectPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_opt_result_maybenull_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS;
}

NTSTATUS
FileProtectInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    // 只在 NTFS 和 ReFS 卷上加载
    if (VolumeFilesystemType == FLT_FSTYPE_NTFS ||
        VolumeFilesystemType == FLT_FSTYPE_REFS)
    {
        return STATUS_SUCCESS;
    }

    return STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS
FileProtectInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

VOID
FileProtectInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

VOID
FileProtectInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// ======================================================================
// 注册结构
// ======================================================================

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_SET_SECURITY, 0, FileProtectPreSetSecurity, NULL },
    { IRP_MJ_CREATE, 0, FileProtectPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FileProtectInstanceSetup,
    FileProtectInstanceQueryTeardown,
    FileProtectInstanceTeardownStart,
    FileProtectInstanceTeardownComplete,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// ======================================================================
// 驱动入口 / 卸载
// ======================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DbgPrint("FileProtectFS: DriverEntry\n");

    // 初始化受保护文件列表
    InitializeListHead(&g_ProtectedFileList);
    ExInitializeFastMutex(&g_ListLock);

    // 注册 Minifilter
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileProtectFS: FltRegisterFilter failed, status=0x%08x\n", status);
        return status;
    }

    // 创建控制设备
    status = CreateControlDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileProtectFS: CreateControlDevice failed, status=0x%08x\n", status);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    // 启动 filtering
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FileProtectFS: FltStartFiltering failed, status=0x%08x\n", status);
        DeleteControlDevice();
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    DbgPrint("FileProtectFS: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

NTSTATUS
FileProtectUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("FileProtectFS: Driver unload\n");

    // 清理受保护文件列表
    ClearProtectedList();

    // 删除控制设备
    DeleteControlDevice();

    // 注销 filter
    FltUnregisterFilter(g_FilterHandle);

    DbgPrint("FileProtectFS: Driver unloaded\n");
    return STATUS_SUCCESS;
}
