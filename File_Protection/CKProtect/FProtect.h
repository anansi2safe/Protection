/*
* Author: Anansi
* Date: 2021/12/3
* minifilter文件保护，禁止删除、写入、重命名
*/
#include <ntifs.h>
#include <fltKernel.h>


FLT_PREOP_CALLBACK_STATUS FLTAPI FileProtect(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_Out_	PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS FLTAPI FilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_In_	PVOID CompletionContext,
	_In_	FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS FLTAPI FileHideOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_In_	PVOID CompletionContext,
	_In_	FLT_POST_OPERATION_FLAGS Flags
);

PFLT_FILTER_UNLOAD_CALLBACK FilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS UnloadDriver(
	_In_ PDRIVER_OBJECT  DriverObject
);