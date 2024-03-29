#include "Hook.h"
#include "SharedTypes.h"
#include "API.h"

BOOL KHook::HookFunc(VOID* kernel_func_addr) {
	if (!kernel_func_addr) {
		return FALSE;
	}

	PVOID* function = reinterpret_cast<PVOID*>(MemoryUtils::getSystemModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtOpenCompositionSurfaceSectionInfo"));

	if (!function) {
		return FALSE;
	}

	BYTE orig[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x18, 0x4D, 0x89, 0x4B, 0x20, 0x49, 0x89, 0x4B, 0x08 };
	BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; // jmp raxs

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_func_addr);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	MemoryUtils::writeToReadOnlyMemory(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS KHook::hookHandler(PVOID called_param) {
	PKERNEL_REQUEST request = (PKERNEL_REQUEST)called_param;

	switch (request->operation) {
	case AllocateMemory:
	{
		API::AllocMemory(request);
		DbgPrint("Alloc request!");
		return STATUS_SUCCESS;
	}
	case ReadMemory:
	{
		API::ReadMemory(request);
		return STATUS_SUCCESS;
	}
	case WriteMemory:
	{
		API::WriteMemory(request);
		DbgPrint("Write request!");
		return STATUS_SUCCESS;
	}
	case ProtectMemory:
	{
		API::ProtectMemory(request);
		DbgPrint("Protect request!");
		return STATUS_SUCCESS;
	}
	case FreeMemory:
	{
		API::FreeMemory(request);
		DbgPrint("Free request!");
		return STATUS_SUCCESS;
	}
	case QueryVirtualMemory:
	{
		API::QueryVirtualMemory(request);
		DbgPrint("Query request!");
		return STATUS_SUCCESS;
	}
	case GetHandle:
	{
		API::GetHandle(request);
		DbgPrint("Handle query request!");
		return STATUS_SUCCESS;
	}
	case GetBase:
	{
		API::GetBase(request);
		DbgPrint("GetBase request!");
		return STATUS_SUCCESS;
	}
	case GetThreadHandle:
	{
		API::GetThreadHandle(request);
		DbgPrint("GetThreadHandle request!");
		return STATUS_SUCCESS;
	}
	case GetVADFlags:
	{
		API::GetVADFlags(request);
		DbgPrint("GetVADFlags request!");
		return STATUS_SUCCESS;
	}
	case SetVADFlags:
	{
		API::SetVADFlags(request);
		DbgPrint("SetVADFlags request!");
		return STATUS_SUCCESS;
	}
	case RemoveVAD:
	{
		API::RemoveVAD(request);
		DbgPrint("RemoveVAD request!");
		return STATUS_SUCCESS;
	}
	}

	return STATUS_SUCCESS;
}