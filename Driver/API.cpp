#include "API.h"

#pragma comment(lib, "ntoskrnl.lib")

NTSTATUS API::AllocMemory(PKERNEL_REQUEST req) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)req->pid, &Process);
	if (NT_SUCCESS(Status)) {
		PVOID Address = NULL;
		SIZE_T size = req->alloc_size;
		DWORD protect = req->alloc_protect_size;

		KAPC_STATE state;
		KeStackAttachProcess(Process, &state);
		ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
		KeUnstackDetachProcess(&state);

		MemoryUtils::safeCopy(req->alloc_output, &Address, sizeof(Address));
		ObDereferenceObject(Process);
	}

	return Status;
}

NTSTATUS API::ReadMemory(PKERNEL_REQUEST req) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	SIZE_T result = 0;

	__try {

		status = MmCopyVirtualMemory(
			process,
			(PVOID)req->read_address,
			PsGetCurrentProcess(),
			req->read_output,
			req->read_size,
			KernelMode,
			&result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		status = GetExceptionCode();
	}

	ObDereferenceObject(process);
	return status;
}

NTSTATUS API::WriteMemory(PKERNEL_REQUEST req) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	SIZE_T result = 0;

	__try {
		status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			req->write_buffer,
			process,
			(PVOID)req->write_address,
			req->write_size,
			KernelMode,
			&result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	ObDereferenceObject(process);

	return status;
}

NTSTATUS API::ProtectMemory(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);
	if (NT_SUCCESS(status)) {
		DWORD protect = NULL;
		SIZE_T return_size = NULL;

		if (MemoryUtils::safeCopy(&protect, req->protect_io, sizeof(protect))) {
			SIZE_T size = req->protect_size;
			PVOID address = req->protect_address;

			KAPC_STATE state;
			KeStackAttachProcess(process, &state);
			status = ZwProtectVirtualMemory(NtCurrentProcess(), &address, &size, protect, &protect);
			KeUnstackDetachProcess(&state);

			MemoryUtils::safeCopy(req->protect_io, &protect, sizeof(protect));
		}
		else {
			status = STATUS_ACCESS_VIOLATION;
		}

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS API::FreeMemory(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);
	if (NT_SUCCESS(status)) {
		SIZE_T size = 0;
		PVOID address = req->free_address;

		KAPC_STATE state;
		KeStackAttachProcess(process, &state);
		ZwFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_RELEASE);
		KeUnstackDetachProcess(&state);

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS API::QueryVirtualMemory(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->pid, &process))) {
		return STATUS_UNSUCCESSFUL;
	}

	MEMORY_BASIC_INFORMATION mbi;
	PVOID address = req->query_address;
	KAPC_STATE state;

	KeStackAttachProcess(process, &state);
	ZwQueryVirtualMemory(NtCurrentProcess(), address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
	KeUnstackDetachProcess(&state);

	MemoryUtils::safeCopy(req->query_output, &mbi, sizeof(mbi));

	return STATUS_SUCCESS;
}

NTSTATUS API::GetHandle(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->pid, &process))) {
		return STATUS_UNSUCCESSFUL;
	}

	OBJECT_ATTRIBUTES attrs;
	InitializeObjectAttributes(&attrs, NULL, 0, NULL, NULL);

	CLIENT_ID client;
	client.UniqueProcess = (HANDLE)req->pid;
	client.UniqueThread = NULL;

	HANDLE handle = NULL;
	ZwOpenProcess(&handle, req->handle_access, &attrs, &client);

	MemoryUtils::safeCopy(req->handle_output, &handle, sizeof(handle));

	ObDereferenceObject(process);
	return STATUS_SUCCESS;
}

NTSTATUS API::GetBase(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Cannot find process!");
		return status;
	}

	ANSI_STRING AS;
	UNICODE_STRING ModuleName;

	RtlInitAnsiString(&AS, req->module_name);
	RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

	ULONG64 baseAddr = MemoryUtils::getModuleBase64(process, ModuleName);
	*req->module_base_output = baseAddr;
	RtlFreeUnicodeString(&ModuleName);


	return STATUS_SUCCESS;
}

NTSTATUS API::GetThreadHandle(PKERNEL_REQUEST req) {
	PEPROCESS process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->pid, &process))) {
		return STATUS_UNSUCCESSFUL;
	}

	OBJECT_ATTRIBUTES attrs;
	InitializeObjectAttributes(&attrs, NULL, 0, NULL, NULL);

	CLIENT_ID client;
	client.UniqueProcess = (HANDLE)req->pid;
	client.UniqueThread = (HANDLE)req->tid;

	HANDLE handle = NULL;
	ZwOpenThread(&handle, req->handle_access, &attrs, &client);

	MemoryUtils::safeCopy(req->handle_output, &handle, sizeof(handle));
	ObDereferenceObject(process);
	return STATUS_SUCCESS;
}

NTSTATUS API::GetVADFlags(PKERNEL_REQUEST req) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)req->pid, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)req->vadf_addres, &pVadShort);

	if (NT_SUCCESS(Status)) {
		MemoryUtils::safeCopy(req->vadf_output, &pVadShort->u.VadFlags, sizeof(MMVAD_FLAGS));
	}

	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS API::SetVADFlags(PKERNEL_REQUEST req) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)req->pid, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)req->vadf_addres, &pVadShort);

	if (NT_SUCCESS(Status)) {
		pVadShort->u.VadFlags.Lock = req->VADFlags.Lock;
		pVadShort->u.VadFlags.LockContended = req->VADFlags.LockContended;
		pVadShort->u.VadFlags.DeleteInProgress = req->VADFlags.DeleteInProgress;
		pVadShort->u.VadFlags.NoChange = req->VADFlags.NoChange;
		pVadShort->u.VadFlags.VadType = req->VADFlags.VadType;
		pVadShort->u.VadFlags.Protection = req->VADFlags.Protection;
		pVadShort->u.VadFlags.PreferredNode = req->VADFlags.PreferredNode;
		pVadShort->u.VadFlags.PageSize = req->VADFlags.PageSize;
		pVadShort->u.VadFlags.PrivateMemory = req->VADFlags.PrivateMemory;
	}

	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS API::RemoveVAD(PKERNEL_REQUEST req) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)req->pid, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)Process + 0x7d8);

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)req->vad_address, &pVadShort);

	RtlAvlRemoveNode(pTable, reinterpret_cast<PMMADDRESS_NODE>(pVadShort));

	return STATUS_SUCCESS;
}