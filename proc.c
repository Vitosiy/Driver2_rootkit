#include "proc.h"

NTSTATUS HookNtQuerySystemInformation(
	IN				SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT			PVOID                    SystemInformation,
	IN				ULONG                    SystemInformationLength,
	OUT OPTIONAL	PULONG                   ReturnLength
) {
	NTSTATUS retStatus;
	
	retStatus = glRealNtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);

	if ((SystemInformationClass == SystemProcessInformation) && NT_SUCCESS(retStatus)) {

		__try {
			ChangeProcessName((PSYSTEM_PROCESS)SystemInformation);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("\n\nEXCEPTION PROC\n\n");
		}

	}
	

	return retStatus;
}

VOID ChangeProcessName(PSYSTEM_PROCESS proc) {
	PLIST_ENTRY pLink;
	PSYSTEM_PROCESS pProcess = proc;

	while (TRUE) {
		if (pProcess->ProcessName.Length) {
			//DbgPrint("process %wZ %d len:%d %d\n", &pProcess->ProcessName, pProcess->ProcessId, pProcess->ProcessName.Length, pProcess->ProcessName.MaximumLength);
			for (pLink = glTaskQueueProcess.Flink; pLink != &glTaskQueueProcess; pLink = pLink->Flink) {
				PTASK_QUEUE_PROCESS task = CONTAINING_RECORD(pLink, TASK_QUEUE_PROCESS, link);
				if (task->flag & TASK_QUEUE_NUMBER) {
					if ((ULONG)pProcess->ProcessId == (ULONG)task->target) {
						ANSI_STRING ansiChange;
						UNICODE_STRING uniChange;

						//DbgPrint("BEFORE %wZ %d len:%d %d\n", &pProcess->ProcessName, pProcess->ProcessId, pProcess->ProcessName.Length, pProcess->ProcessName.MaximumLength);

						RtlInitAnsiString(&ansiChange, (PCSZ)task->change);

						if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniChange, &ansiChange, TRUE))) {
							break;
						}

						RtlZeroMemory(pProcess->ProcessName.Buffer, pProcess->ProcessName.MaximumLength);

						if (pProcess->ProcessName.MaximumLength >= uniChange.MaximumLength) {
							RtlCopyMemory(pProcess->ProcessName.Buffer, uniChange.Buffer, uniChange.MaximumLength);
							pProcess->ProcessName.Length = uniChange.Length;
							pProcess->ProcessName.MaximumLength = uniChange.MaximumLength;
						}
						else {
							RtlCopyMemory(pProcess->ProcessName.Buffer, uniChange.Buffer, pProcess->ProcessName.MaximumLength);
							pProcess->ProcessName.Length = uniChange.Length;
						}

						//DbgPrint("AFTER %wZ %d len:%d %d\n", &pProcess->ProcessName, pProcess->ProcessId, pProcess->ProcessName.Length, pProcess->ProcessName.MaximumLength);

						RtlFreeUnicodeString(&uniChange);
					}
				}
				else if (task->flag & TASK_QUEUE_POINTER) {
					ANSI_STRING ansiTarget;
					UNICODE_STRING uniTarget;
					
					RtlInitAnsiString(&ansiTarget, (PCSZ)task->target);
					if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniTarget, &ansiTarget, TRUE))) {
						break;
					}
					
					if (!wcscmp(pProcess->ProcessName.Buffer, uniTarget.Buffer)) {
						ANSI_STRING ansiChange;
						UNICODE_STRING uniChange;
						//DbgPrint("BEFORE %wZ %d len:%d %d\n", &pProcess->ProcessName, pProcess->ProcessId, pProcess->ProcessName.Length, pProcess->ProcessName.MaximumLength);
					
						RtlInitAnsiString(&ansiChange, (PCSZ)task->change);
						if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniChange, &ansiChange, TRUE))) {
							break;
						}
						RtlZeroMemory(pProcess->ProcessName.Buffer, pProcess->ProcessName.MaximumLength);
					
						if (pProcess->ProcessName.MaximumLength >= uniChange.MaximumLength) {
							RtlCopyMemory(pProcess->ProcessName.Buffer, uniChange.Buffer, uniChange.MaximumLength);
							pProcess->ProcessName.Length = uniChange.Length;
							pProcess->ProcessName.MaximumLength = uniChange.MaximumLength;
						}
						else {
							RtlCopyMemory(pProcess->ProcessName.Buffer, uniChange.Buffer, pProcess->ProcessName.MaximumLength);
							pProcess->ProcessName.Length = uniChange.Length;
						}
						//DbgPrint("AFTER %wZ %d len:%d %d\n", &pProcess->ProcessName, pProcess->ProcessId, pProcess->ProcessName.Length, pProcess->ProcessName.MaximumLength);
					
						RtlFreeUnicodeString(&uniChange);
					}
					
					RtlFreeUnicodeString(&uniTarget);
				}
			}
		}
		if (pProcess->NextEntryDelta) {
			pProcess = (PSYSTEM_PROCESS)((PUCHAR)pProcess + pProcess->NextEntryDelta);
		} else break;
	}
}


ULONG StrLenght(PCHAR str) {
	ULONG i = 0;
	while (str[i++] != '\0');
	return i;
}

VOID TaskQueueByPID(ULONG pid, PCHAR change) {
	

	if (pid != 0 && change != NULL) {
		PTASK_QUEUE_PROCESS task = (PTASK_QUEUE_PROCESS)ExAllocateFromPagedLookasideList(&glPagedTaskQueueProcess);
		
		ULONG len = StrLenght(change);
		task->change = ExAllocatePoolWithTag(PagedPool, len, 'enoN');
		RtlCopyMemory(task->change, change, len);
		((PCHAR)task->change)[len - 1] = '\0';

		task->target = (PVOID)pid;

		task->flag = TASK_QUEUE_NUMBER;


		InsertTailList(&glTaskQueueProcess, &task->link);
	}

}

VOID TaskQueueByName(PCHAR name, PCHAR change) {


	if (name != NULL && change != NULL) {
		PTASK_QUEUE_PROCESS task = (PTASK_QUEUE_PROCESS)ExAllocateFromPagedLookasideList(&glPagedTaskQueueProcess);
		
		ULONG len = StrLenght(name);
		task->target = ExAllocatePoolWithTag(PagedPool, len, 'oneN');
		RtlCopyMemory(task->target, name, len);
		((PCHAR)task->target)[len-1] = '\0';

		len = StrLenght(change);
		task->change = ExAllocatePoolWithTag(PagedPool, len, 'enoN');
		RtlCopyMemory(task->change, change, len);
		((PCHAR)task->change)[len-1] = '\0';

		task->flag = TASK_QUEUE_POINTER;

		InsertTailList(&glTaskQueueProcess, &task->link);
	}

}

VOID FreeListQueueProcess() {

	while (!IsListEmpty(&glTaskQueueProcess)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueProcess);
		PTASK_QUEUE_PROCESS task = CONTAINING_RECORD(pLink, TASK_QUEUE_PROCESS, link);
		if (task->target && (task->flag & TASK_QUEUE_POINTER)) ExFreePool(task->target);
		if (task->change) ExFreePool(task->change);
		ExFreeToPagedLookasideList(&glPagedTaskQueueProcess, task);
	}

}

VOID PrintTaskQueueProcessList() {
	PLIST_ENTRY pLink;
	for (pLink = glTaskQueueProcess.Flink; pLink != &glTaskQueueProcess; pLink = pLink->Flink) {
		PTASK_QUEUE_PROCESS task = CONTAINING_RECORD(pLink, TASK_QUEUE_PROCESS, link);

		if (task->flag & TASK_QUEUE_POINTER) {
			DbgPrint("TASK NAME:%s\t->\tCHANGE:%s\n", (PCHAR)task->target, (PCHAR)task->change);
		}
		else if (task->flag & TASK_QUEUE_NUMBER) {
			DbgPrint("TASK PID:%d\t->\tCHANGE:%s\n", (ULONG)task->target, (PCHAR)task->change);
		}
	}
}