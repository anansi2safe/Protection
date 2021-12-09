/*
*Author: Anansi
*Date: 2021/11/24
*驱动进程保护
*/

#include<ntifs.h>

//进程管理器结束代码
#define PROCESS_TERMINATE_0       0x1001
//taskkill指令结束代码
#define PROCESS_TERMINATE_1       0x0001 
//taskkill指令加/f参数强杀进程结束码
#define PROCESS_KILL_F			  0x1401

extern UCHAR *PsGetProcessImageFileName
(
	_In_ PEPROCESS Process
);

#if _WIN64
//64位LDR_DATA_TABLE_ENTRY结构体,用于绕过MmVerifyCallbackFunction函数
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;
#else
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32    InLoadOrderLinks;
	LIST_ENTRY32    InMemoryOrderLinks;
	LIST_ENTRY32    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY32    ForwarderLinks;
	LIST_ENTRY32    ServiceTagLinks;
	LIST_ENTRY32    StaticLinks;
	PVOID            ContextInformation;
	ULONG32          OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#endif

NTSTATUS DriverEntry
(
	_In_ PDRIVER_OBJECT PDO,
	_In_ PUNICODE_STRING STR
);

NTSTATUS DriverUnload
(
	_In_ PDRIVER_OBJECT pdo
);

//设置回调
NTSTATUS ProtectProcess();

//根据进程pid获取进程名
char*GetProcessImageNameByProcessID
(
	_In_ ULONG ulProcessID
);

//回调函数
OB_PREOP_CALLBACK_STATUS preCall
(
	_In_ PVOID Context,
	_In_ POB_PRE_OPERATION_INFORMATION Opation
);

