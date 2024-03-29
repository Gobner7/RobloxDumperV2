#pragma once
#include "NT.h"

typedef enum _KERNEL_REQUEST_OPERATION {
	AllocateMemory = 0,
	ReadMemory = 1,
	WriteMemory = 2,
	ProtectMemory = 3,
	FreeMemory = 4,
	QueryVirtualMemory = 5,
	GetHandle = 6,
	GetBase = 7,
	GetThreadHandle = 8,
	GetVADFlags = 9,
	SetVADFlags = 10,
	RemoveVAD = 11
} KERNEL_REQUEST_OPERATION;

typedef struct _KERNEL_REQUEST {
	int operation;
	ULONG pid;
	size_t alloc_size;
	DWORD alloc_protect_size;
	PVOID alloc_output;
	DWORD64 read_address;
	ULONG read_size;
	PVOID read_output;
	PVOID write_buffer;
	DWORD64 write_address;
	ULONG write_size;
	PVOID protect_io;
	DWORD protect_size;
	PVOID protect_address;
	PVOID free_address;
	PVOID query_address;
	PVOID query_output;
	PVOID handle_output;
	ULONG handle_access;
	PULONG64 module_base_output;
	char* module_name;
	ULONG tid;
	PVOID vadf_addres;
	PVOID vadf_output;
	MMVAD_FLAGS VADFlags;
	PVOID vad_address;
} KERNEL_REQUEST, * PKERNEL_REQUEST;