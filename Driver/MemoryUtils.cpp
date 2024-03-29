#include "MemoryUtils.h"

PVOID MemoryUtils::getSystemModuleBase(const char* module_name) {
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes) {
		return NULL;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if (strcmp((char*)module[i].FullPathName, module_name) == 0) {
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules) {
		ExFreePoolWithTag(modules, NULL);
	}

	if (module_base <= NULL) {
		return NULL;
	}

	return module_base;
}

PVOID MemoryUtils::getSystemModuleExport(const char* module_name, LPCSTR routine_name) {
	PVOID lpModule = MemoryUtils::getSystemModuleBase(module_name);

	if (!lpModule) {
		return NULL;
	}

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

bool MemoryUtils::writeMemory(void* address, void* buffer, size_t size) {
	if (!RtlCopyMemory(address, buffer, size)) {
		return false;
	}
	else {
		return true;
	}
}

bool MemoryUtils::writeToReadOnlyMemory(void* address, void* buffer, size_t size) {
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl) {
		return false;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	MemoryUtils::writeMemory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

bool MemoryUtils::safeCopy(PVOID address, PVOID buffer, size_t size) {
	SIZE_T return_size = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, PsGetCurrentProcess(), address, size, KernelMode, &return_size)) && return_size == size) {
		return true;
	}

	return false;
}

ULONG64 MemoryUtils::getModuleBase64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = PsGetProcessPeb(proc);
	if (!pPeb) {
		return NULL;
	}

	KAPC_STATE state;
	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink; list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == NULL) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return NULL;
}

TABLE_SEARCH_RESULT
MiFindNodeOrParent(
	IN PMM_AVL_TABLE Table,
	IN ULONG_PTR StartingVpn,
	OUT PMMADDRESS_NODE* NodeOrParent
) {
	PMMADDRESS_NODE Child;
	PMMADDRESS_NODE NodeToExamine;
	PMMVAD_SHORT    VpnCompare;
	ULONG_PTR       startVpn;
	ULONG_PTR       endVpn;

	if (Table->NumberGenericTableElements == 0) {
		return TableEmptyTree;
	}

	NodeToExamine = (PMMADDRESS_NODE)(Table->BalancedRoot);

	for (;;) {

		VpnCompare = (PMMVAD_SHORT)NodeToExamine;
		startVpn = VpnCompare->StartingVpn;
		endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
		startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

		//
		// Compare the buffer with the key in the tree element.
		//

		if (StartingVpn < startVpn) {

			Child = NodeToExamine->LeftChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsLeft;
			}
		}
		else if (StartingVpn <= endVpn) {

			//
			// This is the node.
			//

			*NodeOrParent = NodeToExamine;
			return TableFoundNode;
		}
		else {

			Child = NodeToExamine->RightChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsRight;
			}
		}

	};
}

NTSTATUS
MemoryUtils::FindVAD(
	IN PEPROCESS pProcess,
	IN ULONG_PTR address,
	OUT PMMVAD_SHORT* pResult
) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR vpnStart = address >> PAGE_SHIFT;

	ASSERT(pProcess != NULL && pResult != NULL);
	if (pProcess == NULL || pResult == NULL)
		return STATUS_INVALID_PARAMETER;


	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)pProcess + 0x7d8);
	PMM_AVL_NODE pNode = (pTable->BalancedRoot);

	if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode) {
		*pResult = (PMMVAD_SHORT)pNode;
	}
	else {
		status = STATUS_NOT_FOUND;
	}

	return status;
}