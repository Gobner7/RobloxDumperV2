#include "Hook.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pRegistryPath);
	UNREFERENCED_PARAMETER(pDriverObject);

	KHook::HookFunc(&KHook::hookHandler);
	DbgPrint("[RBXDumper] Loaded!");

	return STATUS_SUCCESS;
}