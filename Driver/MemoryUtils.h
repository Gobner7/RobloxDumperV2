#pragma once
#include "definitions.h"

namespace MemoryUtils {
	PVOID getSystemModuleBase(const char* module_name);
	PVOID getSystemModuleExport(const char* module_name, LPCSTR routine_name);
	bool writeMemory(void* address, void* buffer, size_t size);
	bool writeToReadOnlyMemory(void* address, void* buffer, size_t size);
	bool safeCopy(PVOID address, PVOID buffer, size_t size);
	ULONG64 getModuleBase64(PEPROCESS proc, UNICODE_STRING module_name);
	NTSTATUS
		FindVAD(
			IN PEPROCESS pProcess,
			IN ULONG_PTR address,
			OUT PMMVAD_SHORT* pResult
		);
}