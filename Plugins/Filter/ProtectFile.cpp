#include "DriverCommon.h"

// ---- 最近写入方环形缓冲 ----
//
// 目录监听拿不到 PID,Restart Manager 只能看到「此刻仍开着」的句柄。
// 文件写完就关的场景(解包、释放副本、编译产物)两条路都查不到,弹窗只能显示「未识别」。
// 这里在写回调里留一份「最近 128 次不同文件的写入者」,用户态按路径哈希查一次即可。
//
// 只存哈希:内核里存全路径要么动态分配(高频路径),要么每槽 2KB。
// 相邻的重复写入(同一个进程连续写同一个文件)只更新时间戳,不占新槽 ——
// 编译器/解包器那种高频场景不会把环冲干净。

typedef struct _PYAS_WRITE_ENTRY {
    ULONGLONG Hash;
    ULONGLONG Stamp;
    ULONG ProcessId;
    ULONG Valid;
} PYAS_WRITE_ENTRY;

static PYAS_WRITE_ENTRY g_WriteOwnerRing[PYAS_WRITE_RING_CAPACITY];
static KSPIN_LOCK g_WriteOwnerLock;
static ULONG g_WriteOwnerNext = 0;

VOID PyasInitializeWriteOwner(VOID) {
    RtlZeroMemory(g_WriteOwnerRing, sizeof(g_WriteOwnerRing));
    KeInitializeSpinLock(&g_WriteOwnerLock);
    g_WriteOwnerNext = 0;
}

ULONGLONG PyasHashPath(PCUNICODE_STRING Path) {
    // FNV-1a over UTF-16,先做大小写折叠 —— Windows 路径比较不区分大小写,
    // 驱动给的规范化名字与用户态拼出来的路径大小写常常不一致。
    ULONGLONG hash = 14695981039346656037ULL;
    ULONG count = Path->Length / sizeof(WCHAR);

    for (ULONG i = 0; i < count; i++) {
        WCHAR ch = Path->Buffer[i];
        ch = RtlUpcaseUnicodeChar(ch);
        hash ^= (ULONGLONG)(USHORT)ch;
        hash *= 1099511628211ULL;
    }

    return hash;
}

VOID PyasRecordWriteOwner(PCUNICODE_STRING Path, ULONG ProcessId) {
    if (!Path || !Path->Buffer || Path->Length == 0 || ProcessId == 0) return;

    ULONGLONG hash = PyasHashPath(Path);
    ULONGLONG now = KeQueryInterruptTime();
    KIRQL irql;

    KeAcquireSpinLock(&g_WriteOwnerLock, &irql);

    if (g_WriteOwnerNext > 0) {
        PYAS_WRITE_ENTRY* last = &g_WriteOwnerRing[(g_WriteOwnerNext - 1) % PYAS_WRITE_RING_CAPACITY];

        if (last->Valid && last->Hash == hash && last->ProcessId == ProcessId) {
            last->Stamp = now;
            KeReleaseSpinLock(&g_WriteOwnerLock, irql);
            return;
        }
    }

    PYAS_WRITE_ENTRY* slot = &g_WriteOwnerRing[g_WriteOwnerNext % PYAS_WRITE_RING_CAPACITY];
    slot->Hash = hash;
    slot->Stamp = now;
    slot->ProcessId = ProcessId;
    slot->Valid = 1;
    g_WriteOwnerNext++;

    KeReleaseSpinLock(&g_WriteOwnerLock, irql);
}

NTSTATUS PyasQueryWriteOwner(PCUNICODE_STRING Path, PPYAS_WRITE_OWNER_REPLY Reply) {
    if (!Path || !Path->Buffer || Path->Length == 0 || !Reply) return STATUS_INVALID_PARAMETER;

    ULONGLONG hash = PyasHashPath(Path);
    ULONGLONG best = 0;
    ULONG pid = 0;
    KIRQL irql;

    KeAcquireSpinLock(&g_WriteOwnerLock, &irql);

    for (ULONG i = 0; i < PYAS_WRITE_RING_CAPACITY; i++) {
        if (!g_WriteOwnerRing[i].Valid || g_WriteOwnerRing[i].Hash != hash) continue;

        if (g_WriteOwnerRing[i].Stamp >= best) {
            best = g_WriteOwnerRing[i].Stamp;
            pid = g_WriteOwnerRing[i].ProcessId;
        }
    }

    KeReleaseSpinLock(&g_WriteOwnerLock, irql);

    Reply->Found = best ? 1 : 0;
    Reply->ProcessId = pid;
    return STATUS_SUCCESS;
}

#include "DriverCommon.h"

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer || nameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();

    // 先记账再判定规则:无论这次写入最后放行还是拦截,
    // 弹窗都需要知道这个文件是谁写的。
    PyasRecordWriteOwner(&nameInfo->Name, (ULONG)(ULONG_PTR)Pid);

    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    BOOLEAN IsCreateAction = (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_OPEN_IF);
    ULONG DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    ULONG Operation = 0;
    if (IsCreateAction) Operation |= OP_CREATE;
    if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE)) Operation |= OP_WRITE;
    if (DesiredAccess & (DELETE | FILE_DELETE_CHILD)) Operation |= OP_DELETE;

    if (Operation != 0) {
        ULONG RuleCode = 0;
        BOOLEAN Kill = FALSE;
        if (EvaluateFileRule(Pid, &nameInfo->Name, Operation, NULL, 0, &RuleCode, &Kill)) {
            SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
            QueueRuleProcessTermination(Pid, Kill);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            callbackStatus = FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileDispositionInformation && infoClass != FileRenameInformation && infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo)) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG Operation = 0;

    if (infoClass == FileDispositionInformation) {
        Operation = OP_DELETE;
    }
    else {
        Operation = OP_RENAME;
    }

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (EvaluateFileRule(Pid, &nameInfo->Name, Operation, NULL, 0, &RuleCode, &Kill)) {
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
        QueueRuleProcessTermination(Pid, Kill);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        callbackStatus = FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_NOCACHE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG WriteLength = Data->Iopb->Parameters.Write.Length;
    if (WriteLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) || !nameInfo) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltParseFileNameInformation(nameInfo)) || !nameInfo->Name.Buffer) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE Pid = PsGetCurrentProcessId();
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    PVOID SystemBuffer = NULL;
    PMDL Mdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (!Mdl && Data->Iopb->Parameters.Write.WriteBuffer && KeGetCurrentIrql() <= APC_LEVEL) {
        if (NT_SUCCESS(FltLockUserBuffer(Data))) Mdl = Data->Iopb->Parameters.Write.MdlAddress;
    }
    if (Mdl) SystemBuffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

    ULONG RuleCode = 0;
    BOOLEAN Kill = FALSE;
    if (EvaluateFileRule(Pid, &nameInfo->Name, OP_WRITE, SystemBuffer, WriteLength, &RuleCode, &Kill)) {
        SendMessageToUser(RuleCode, (ULONG)(ULONG_PTR)Pid, nameInfo->Name.Buffer, nameInfo->Name.Length);
        QueueRuleProcessTermination(Pid, Kill);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        callbackStatus = FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return callbackStatus;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_SetSecurity(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS ProtectFile_FileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}