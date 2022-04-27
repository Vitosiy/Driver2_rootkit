#ifndef _RENAME_PROC_H_
#define _RENAME_PROC_H_

#include "inc.h"

#define NUMBER_NT_QUERY_SYSTEM_INFORMATION 0xAD // 173

ULONG addressForJmpNtQuerySystemInformation;
UCHAR saveByteNtQuerySystemInformation[5];
volatile ULONG SyscallNewProcessedCount;

//for SYSTEM_INFORMATION_CLASS
//but wdk cannot open include file
//#include <Winternl.h>
//struct taked from Winternl.h
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREADS {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitchCount;
    //THREAD_STATE State;
    UCHAR State;
    KWAIT_REASON WaitReason;
} SYSTEM_THREADS;

typedef struct _SYSTEM_PROCESS {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    ULONG InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    ULONG PrivatePageCount;
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESS, *PSYSTEM_PROCESS;

typedef NTSTATUS(*NT_QUERY_SYSTEM_INFORMATION) (
	IN				SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT			PVOID                    SystemInformation,
	IN				ULONG                    SystemInformationLength,
	OUT OPTIONAL	PULONG                   ReturnLength
	);

typedef struct _TASK_QUEUE_PROCESS {

    UCHAR flag;
    PVOID target;
    PVOID change;
    LIST_ENTRY link;

} TASK_QUEUE_PROCESS, *PTASK_QUEUE_PROCESS;
LIST_ENTRY glTaskQueueProcess;
PAGED_LOOKASIDE_LIST glPagedTaskQueueProcess;

NTSTATUS HookNtQuerySystemInformation(
	IN				SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT			PVOID                    SystemInformation,
	IN				ULONG                    SystemInformationLength,
	OUT OPTIONAL	PULONG                   ReturnLength
);

NTSTATUS JmpNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

//NT_QUERY_SYSTEM_INFORMATION glRealNtQuerySystemInformation;
NTSTATUS CreateNewProcess(PSYSTEM_PROCESS proc, ULONG SystemInformationLength);
VOID TaskQueueNewProc(ULONG pid, PCHAR name);
VOID FreeListQueueProcess();
#endif