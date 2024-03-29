#pragma once
#include "SharedTypes.h"
#include "MemoryUtils.h"
#include <intrin.h>

namespace API {
	NTSTATUS AllocMemory(PKERNEL_REQUEST req);
	NTSTATUS ReadMemory(PKERNEL_REQUEST req);
	NTSTATUS WriteMemory(PKERNEL_REQUEST req);
	NTSTATUS ProtectMemory(PKERNEL_REQUEST req);
	NTSTATUS FreeMemory(PKERNEL_REQUEST req);
	NTSTATUS QueryVirtualMemory(PKERNEL_REQUEST req);
	NTSTATUS GetHandle(PKERNEL_REQUEST req);
	NTSTATUS GetBase(PKERNEL_REQUEST req);
	NTSTATUS GetThreadHandle(PKERNEL_REQUEST req);
	NTSTATUS GetVADFlags(PKERNEL_REQUEST req);
	NTSTATUS SetVADFlags(PKERNEL_REQUEST req);
	NTSTATUS RemoveVAD(PKERNEL_REQUEST req);
}