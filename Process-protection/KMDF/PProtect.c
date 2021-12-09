#include"PProtect.h"

//定义一个void*类型的变量，它将会作为ObRegisterCallbacks函数的第二个参数。
PVOID obHandle;
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObj, 
	_In_ PUNICODE_STRING pRegistryString
)
{
#if _WIN64
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY64 ldr;

	pDriverObj->DriverUnload = DriverUnload;
	//绕过MmVerifyCallbackFunction。
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;

	ProtectProcess();
	DbgPrint("hello start");
#else
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY32 ldr;

	pDriverObj->DriverUnload = DriverUnload;
	//绕过MmVerifyCallbackFunction。
	ldr = (PLDR_DATA_TABLE_ENTRY32)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;

	ProtectProcess();
	DbgPrint("hello start");
#endif

	return STATUS_SUCCESS;
}

//设置ObRegisterCallBacks回调函数
NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	//初始化结构体变量
	memset(&opReg, 0, sizeof(opReg)); 
	//下面请注意这个结构体的成员字段的设置
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//在这里注册一个回调函数指针
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; 
	//注意这一条语句
	obReg.OperationRegistration = &opReg; 
	//在这里注册回调函数
	return ObRegisterCallbacks(&obReg, &obHandle); 
}


OB_PREOP_CALLBACK_STATUS preCall(
	_In_ PVOID RegistrationContext, 
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	//获取pid,这里的HANDLE保存的其实是一个进程pid
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	strcpy(szProcName, GetProcessImageNameByProcessID((ULONG)pid));
	//比较字符串，返回0，则字符串相同
	if (!_stricmp(szProcName, "Project1.exe"))
	{
		//如果创建句柄
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//OriginalDesiredAccess为原本权限，DesiredAccess为即将要更改的新权限
			//如果要结束进程,进程管理器结束进程发送0x1001，taskkill指令结束进程发送0x0001，taskkil加/f参数结束进程发送0x1401
			int code = pOperationInformation->
				Parameters->
				CreateHandleInformation.
				OriginalDesiredAccess;

			if ((code == PROCESS_TERMINATE_0) || 
				(code == PROCESS_TERMINATE_1) || 
				(code == PROCESS_KILL_F))
				//给进程赋予新权限
				pOperationInformation->
				Parameters->
				CreateHandleInformation.
				DesiredAccess = 0x0;
			//在进程管理器“进程”栏页面结束进程，在返回0x1001值后还会返回1041值，在1041值收到后
			//再赋予其常规所有操作权限，即可解决“进程”栏页面结束进程导致进程崩溃的情况
			if (code == 0x1041)
				pOperationInformation->
				Parameters->
				CreateHandleInformation.
				DesiredAccess = STANDARD_RIGHTS_ALL;
		}
	}
	return OB_PREOP_SUCCESS;
}

//获取进程名函数，根据进程pid获取进程名称
char* GetProcessImageNameByProcessID(
	_In_ ULONG ulProcessID
)
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;

	Status = PsLookupProcessByProcessId(
		(HANDLE)ulProcessID, 
		&EProcess);    //EPROCESS

	//通过句柄获取EProcess
	if (!NT_SUCCESS(Status))
		return FALSE;
	ObDereferenceObject(EProcess);
	//通过EProcess获得进程名称
	return (char*)PsGetProcessImageFileName(EProcess);
}


NTSTATUS DriverUnload(
	_In_ PDRIVER_OBJECT pDriverObj
)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	DbgPrint("driver unloading...\n");
	//obHandle是上面定义的 PVOID obHandle;
	ObUnRegisterCallbacks(obHandle); 
	return STATUS_SUCCESS;
}