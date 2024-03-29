#pragma once
#include "MemoryUtils.h"

namespace KHook {
	BOOL HookFunc(VOID* kernel_func_addr);
	NTSTATUS hookHandler(PVOID called_param);
}