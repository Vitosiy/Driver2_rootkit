#include "proc.h"

NTSTATUS HookNtQuerySystemInformation(
	IN				SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT			PVOID                    SystemInformation,
	IN				ULONG                    SystemInformationLength,
	OUT OPTIONAL	PULONG                   ReturnLength
) {
	NTSTATUS retStatus, newRetStatus;

	++SyscallNewProcessedCount;

	retStatus = JmpNtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);
	if ((SystemInformationClass == SystemProcessInformation) && NT_SUCCESS(retStatus)) {
		__try {
			newRetStatus = CreateNewProcess((PSYSTEM_PROCESS)SystemInformation, SystemInformationLength);
			if(newRetStatus == STATUS_NO_MEMORY)
				retStatus = newRetStatus;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("\n\nEXCEPTION PROC\n\n");
		}
	}
	
	--SyscallNewProcessedCount;

	return retStatus;
}

__declspec(naked) NTSTATUS NTAPI JmpNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
) {
	__asm {
		push 210h
		jmp[addressForJmpNtQuerySystemInformation]
	}
}

NTSTATUS CreateNewProcess(PSYSTEM_PROCESS proc, ULONG SystemInformationLength) {
	ANSI_STRING ansiChange;
	UNICODE_STRING uniChange;
	PLIST_ENTRY pLink;
	PSYSTEM_PROCESS pProcess = proc;

	for (pLink = glTaskQueueProcess.Flink; pLink != &glTaskQueueProcess; pLink = pLink->Flink) {
		PTASK_QUEUE_PROCESS task = CONTAINING_RECORD(pLink, TASK_QUEUE_PROCESS, link);

		int countProcess = 0;
		ULONG maxNextEntryDelta = 0;
		while (pProcess->NextEntryDelta) {
			if(pProcess->NextEntryDelta > maxNextEntryDelta)
				maxNextEntryDelta = pProcess->NextEntryDelta;
			pProcess = (PSYSTEM_PROCESS)((PUCHAR)pProcess + pProcess->NextEntryDelta);
			countProcess++;
		}

		if (SystemInformationLength <= (countProcess * sizeof(SYSTEM_PROCESS)) ||
			(SystemInformationLength - countProcess * sizeof(SYSTEM_PROCESS)) < sizeof(SYSTEM_PROCESS)) {
			return STATUS_NO_MEMORY;
		}

		RtlInitAnsiString(&ansiChange, (PCSZ)task->change);
		if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniChange, &ansiChange, TRUE))) {
			break;
		}

		if (RtlEqualMemory(pProcess->ProcessName.Buffer, uniChange.Buffer, uniChange.MaximumLength)) {
			break;
		}

		pProcess->NextEntryDelta = maxNextEntryDelta;
		pProcess = (PSYSTEM_PROCESS)((PUCHAR)pProcess + maxNextEntryDelta);
		RtlZeroMemory(pProcess, sizeof(SYSTEM_PROCESS));

		pProcess->ProcessId = (ULONG)task->target;

		RtlCopyMemory((PUCHAR)pProcess + sizeof(SYSTEM_PROCESS), uniChange.Buffer, uniChange.MaximumLength);
		pProcess->ProcessName.Buffer = (PWCH)((PUCHAR)pProcess + sizeof(SYSTEM_PROCESS));
		pProcess->ProcessName.Length = uniChange.Length;
		pProcess->ProcessName.MaximumLength = uniChange.MaximumLength;

		RtlFreeUnicodeString(&uniChange);
	}

	return STATUS_SUCCESS;
}


ULONG StrLenght(PCHAR str) {
	ULONG i = 0;
	while (str[i++] != '\0');
	return i;
}

VOID TaskQueueNewProc(ULONG pid, PCHAR name) {
	if (pid != 0 && name != NULL) {
		PTASK_QUEUE_PROCESS task = (PTASK_QUEUE_PROCESS)ExAllocateFromPagedLookasideList(&glPagedTaskQueueProcess);
		
		ULONG len = StrLenght(name);
		task->change = ExAllocatePoolWithTag(PagedPool, len, 'enoN');
		RtlCopyMemory(task->change, name, len);
		((PCHAR)task->change)[len - 1] = '\0';

		task->target = (PVOID)pid;

		InsertTailList(&glTaskQueueProcess, &task->link);
	}
}


VOID FreeListQueueProcess() {

	while (!IsListEmpty(&glTaskQueueProcess)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueProcess);
		PTASK_QUEUE_PROCESS task = CONTAINING_RECORD(pLink, TASK_QUEUE_PROCESS, link);
		//if (task->target) ExFreePool(task->target);
		if (task->change) ExFreePool(task->change);
		ExFreeToPagedLookasideList(&glPagedTaskQueueProcess, task);
	}

}