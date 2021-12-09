/*
* Author: Anansi
* Date: 2021/12/8
* 注册表子项、键、键值写入保护
*/
#pragma once
#include <ntifs.h>

#define REG_TAG "rootkit"

NTSTATUS UnloadDriver(
	_In_ PDRIVER_OBJECT pDriver_Obj
);

/// <summary>
/// 回调函数
/// </summary>
/// <param name="CallbackContext">上下文参数</param>
/// <param name="Argument1">注册表操作类型</param>
/// <param name="Argument2">注册表类型信息结构</param>
/// <returns></returns>
NTSTATUS RegistryCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
);


BOOLEAN GetNameForRegistryObject(
	_Out_	 PUNICODE_STRING pRegistryPath,
	_In_	 PUNICODE_STRING pPartialRegistryPath,
	_In_	 PVOID pRegistryObject
);
