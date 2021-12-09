#include"PProtect.h"

//����һ��void*���͵ı�������������ΪObRegisterCallbacks�����ĵڶ���������
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
	//�ƹ�MmVerifyCallbackFunction��
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;

	ProtectProcess();
	DbgPrint("hello start");
#else
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY32 ldr;

	pDriverObj->DriverUnload = DriverUnload;
	//�ƹ�MmVerifyCallbackFunction��
	ldr = (PLDR_DATA_TABLE_ENTRY32)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;

	ProtectProcess();
	DbgPrint("hello start");
#endif

	return STATUS_SUCCESS;
}

//����ObRegisterCallBacks�ص�����
NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	//��ʼ���ṹ�����
	memset(&opReg, 0, sizeof(opReg)); 
	//������ע������ṹ��ĳ�Ա�ֶε�����
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//������ע��һ���ص�����ָ��
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; 
	//ע����һ�����
	obReg.OperationRegistration = &opReg; 
	//������ע��ص�����
	return ObRegisterCallbacks(&obReg, &obHandle); 
}


OB_PREOP_CALLBACK_STATUS preCall(
	_In_ PVOID RegistrationContext, 
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	//��ȡpid,�����HANDLE�������ʵ��һ������pid
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	strcpy(szProcName, GetProcessImageNameByProcessID((ULONG)pid));
	//�Ƚ��ַ���������0�����ַ�����ͬ
	if (!_stricmp(szProcName, "Project1.exe"))
	{
		//����������
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//OriginalDesiredAccessΪԭ��Ȩ�ޣ�DesiredAccessΪ����Ҫ���ĵ���Ȩ��
			//���Ҫ��������,���̹������������̷���0x1001��taskkillָ��������̷���0x0001��taskkil��/f�����������̷���0x1401
			int code = pOperationInformation->
				Parameters->
				CreateHandleInformation.
				OriginalDesiredAccess;

			if ((code == PROCESS_TERMINATE_0) || 
				(code == PROCESS_TERMINATE_1) || 
				(code == PROCESS_KILL_F))
				//�����̸�����Ȩ��
				pOperationInformation->
				Parameters->
				CreateHandleInformation.
				DesiredAccess = 0x0;
			//�ڽ��̹����������̡���ҳ��������̣��ڷ���0x1001ֵ�󻹻᷵��1041ֵ����1041ֵ�յ���
			//�ٸ����䳣�����в���Ȩ�ޣ����ɽ�������̡���ҳ��������̵��½��̱��������
			if (code == 0x1041)
				pOperationInformation->
				Parameters->
				CreateHandleInformation.
				DesiredAccess = STANDARD_RIGHTS_ALL;
		}
	}
	return OB_PREOP_SUCCESS;
}

//��ȡ���������������ݽ���pid��ȡ��������
char* GetProcessImageNameByProcessID(
	_In_ ULONG ulProcessID
)
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;

	Status = PsLookupProcessByProcessId(
		(HANDLE)ulProcessID, 
		&EProcess);    //EPROCESS

	//ͨ�������ȡEProcess
	if (!NT_SUCCESS(Status))
		return FALSE;
	ObDereferenceObject(EProcess);
	//ͨ��EProcess��ý�������
	return (char*)PsGetProcessImageFileName(EProcess);
}


NTSTATUS DriverUnload(
	_In_ PDRIVER_OBJECT pDriverObj
)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	DbgPrint("driver unloading...\n");
	//obHandle�����涨��� PVOID obHandle;
	ObUnRegisterCallbacks(obHandle); 
	return STATUS_SUCCESS;
}