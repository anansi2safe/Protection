#include "FProtect.h"
//被保护的目录文件部分路径或名称
#define Protect_Path L"1122334.txt"

PFLT_FILTER FilterHandle;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegisterPath
)
{
	UNREFERENCED_PARAMETER(RegisterPath);
	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrint("[FileProtect]start!");
	DriverObject->DriverUnload = UnloadDriver;
	const FLT_OPERATION_REGISTRATION Callbacks[] = {
		{IRP_MJ_CREATE,				0x00,	FileProtect,			FilePostOperation},
		{IRP_MJ_SET_INFORMATION,	0x00,	FileProtect,			FilePostOperation},
		{IRP_MJ_WRITE,				0x00,	FileProtect,			FilePostOperation},
		{IRP_MJ_DIRECTORY_CONTROL,	0x00,	NULL,					FileHideOperation},
		{IRP_MJ_OPERATION_END}
	};
	const FLT_REGISTRATION Registration = {
		sizeof(FLT_REGISTRATION),
		FLT_REGISTRATION_VERSION,
		0,
		NULL,
		Callbacks,
		FilterUnload,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	Status = FltRegisterFilter(DriverObject, &Registration, &FilterHandle);

	if (NT_SUCCESS(Status))
		FltStartFiltering(FilterHandle);
	else
		DbgPrint("[FileProtect]%lx", Status);
	return Status;
}

PFLT_FILTER_UNLOAD_CALLBACK FilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();
	FltUnregisterFilter(FilterHandle);
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI FileProtect(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_Out_	PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION FileInfo;
	if (Data)
	{
		Status = FltGetFileNameInformation(
			Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&FileInfo);
		if (NT_SUCCESS(Status))
		{
			Status = FltParseFileNameInformation(FileInfo);
			if (NT_SUCCESS(Status))
			{
				if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
					if(!FlagOn(Data->
						Iopb->
						Parameters.
						Create.Options, FILE_DELETE_ON_CLOSE))
					return Status;
					
				if (wcsstr(FileInfo->Name.Buffer, Protect_Path))
				{
					Data->IoStatus.Information = 0;
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					FltReleaseFileNameInformation(FileInfo);
					return FLT_PREOP_COMPLETE;
				}
			}
			FltReleaseFileNameInformation(FileInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI FilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_In_	PVOID CompletionContext,
	_In_	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI FileHideOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_	PCFLT_RELATED_OBJECTS FltObjects,
	_In_	PVOID CompletionContext,
	_In_	FLT_POST_OPERATION_FLAGS Flags
)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS UnloadDriver(
	_In_ PDRIVER_OBJECT  DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[FileProtect]end");
	return STATUS_SUCCESS;
}