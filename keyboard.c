#include "keyboard.h"
#define STOP_FLAG 999
CHAR glASCIITable[] = "  1234567890-+  QWERTYUIOP[]\0\0ASDFGHJKL;'`\0\0ZXCVBNM,./\0*\0 \0\0\0\0\0\0\0\0\0\0\0\0\0789-456+1230.\0\0";

NTSTATUS InitHookKeyboard(PDRIVER_OBJECT pDriverObject){

    PDEVICE_OBJECT pDeviceObject;
	PDRIVER_DISPATCH* majorFunction;
    NTSTATUS status;
    UNICODE_STRING glAttachedDeviceName;

    majorFunction = pDriverObject->MajorFunction;

    // устанавливаем один обработчик для всех IRP
    majorFunction[IRP_MJ_CREATE] =
        majorFunction[IRP_MJ_CREATE_NAMED_PIPE] =
        majorFunction[IRP_MJ_CLOSE] =
        majorFunction[IRP_MJ_READ] =
        majorFunction[IRP_MJ_WRITE] =
        majorFunction[IRP_MJ_QUERY_INFORMATION] =
        majorFunction[IRP_MJ_SET_INFORMATION] =
        majorFunction[IRP_MJ_QUERY_EA] =
        majorFunction[IRP_MJ_SET_EA] =
        majorFunction[IRP_MJ_FLUSH_BUFFERS] =
        majorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] =
        majorFunction[IRP_MJ_SET_VOLUME_INFORMATION] =
        majorFunction[IRP_MJ_DIRECTORY_CONTROL] =
        majorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] =
        majorFunction[IRP_MJ_DEVICE_CONTROL] =
        majorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
        majorFunction[IRP_MJ_SHUTDOWN] =
        majorFunction[IRP_MJ_LOCK_CONTROL] =
        majorFunction[IRP_MJ_CLEANUP] =
        majorFunction[IRP_MJ_CREATE_MAILSLOT] =
        majorFunction[IRP_MJ_QUERY_SECURITY] =
        majorFunction[IRP_MJ_SET_SECURITY] =
        majorFunction[IRP_MJ_POWER] =
        majorFunction[IRP_MJ_SYSTEM_CONTROL] =
        majorFunction[IRP_MJ_DEVICE_CHANGE] =
        majorFunction[IRP_MJ_QUERY_QUOTA] =
        majorFunction[IRP_MJ_SET_QUOTA] =
        majorFunction[IRP_MJ_PNP] = DispatchRoutine;


    RtlInitUnicodeString(&glAttachedDeviceName, ATTACHED_DEVICE_NAME);

    // создание устройства
    status = IoCreateDevice(pDriverObject,     // указатель на объект драйвера
        0,                  // размер области дополнительной памяти устройства
        NULL,               // без имени
        FILE_DEVICE_UNKNOWN,    // идентификатор типа устройства
        0,                  // дополнительная информация об устройстве
        FALSE,              // без эксклюзивного доступа
        &pDeviceObject);    // адрес для сохранения указателя на объект устройства
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // По имени устройства получаем указатель на объекта устройства.
    // Будет возвращён указатель на устройство, которое находится
    // на вершине стека, в который входит устройство, имя которого передано.
    // Также возвращается указатель на открытый файл этого устройства,
    // устройство не может быть выгружено, пока не будет закрыт этот файл.
    status = IoGetDeviceObjectPointer(&glAttachedDeviceName, FILE_READ_DATA, &glAttachedFile, &glAttachedDevice);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
        DbgPrint("Error get device: %08X\n", status);
        return status;
    }

    // Присоединяемся к стеку драйверов. Функция возвращает устройство,
    // которое было на вершине стека.
    // В результате наш драйвер оказывается на вершине стека.
    glAttachedDevice = IoAttachDeviceToDeviceStack(pDeviceObject, glAttachedDevice);
    if (glAttachedDevice == NULL) {
        IoDeleteDevice(pDeviceObject);
        DbgPrint("Error attach device: %08X\n", status);
        return STATUS_DEVICE_BUSY;
    }

    pDeviceObject->Flags = glAttachedDevice->Flags;
    DbgPrint("Attach to device %wZ\n", &glAttachedDeviceName);

    RtlZeroMemory(&glTaskKeyboard, sizeof(TASK_KEYBOARD));

    return STATUS_SUCCESS;
}

//
// Единая функция обработки всех IRP.
//
NTSTATUS DispatchRoutine(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp) {

    NTSTATUS status = STATUS_SUCCESS;   // статус завершения операции ввода/вывода
    PIO_STACK_LOCATION pIrpStack;

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    if (pIrpStack->MajorFunction == IRP_MJ_READ) {
        // обрабатываем только запросы на чтение

        InterlockedIncrement(&glProcessingIrpCount);

        // копируем данные из нашей ячейки стека в следующую
        IoCopyCurrentIrpStackLocationToNext(pIrp);
        // устанавливаем функцию завершения в следующей ячейке стека
        IoSetCompletionRoutine(pIrp, ReadCompleteRoutine, NULL, TRUE, TRUE, TRUE);
    }
    else {
        // остальные запросы игнорируем
        // поэтому отдаём нашу ячейку стека нижележащему драйверу
        IoSkipCurrentIrpStackLocation(pIrp);
    }

    // передаём IRP нижележащему драйверу
    status = IoCallDriver(glAttachedDevice, pIrp);

    return status;
}

ULONG FindPosion(CHAR byte) {
    ULONG i;
    for (i = 0; i < 86; i++) {
        if (glASCIITable[i] == byte) {
            return i;
        }
    }
    return STOP_FLAG;
}

//
// Функция завершения обработки запроса на чтение.
//
NTSTATUS ReadCompleteRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext) {

    ULONG posion;
    ULONG_PTR i;
    KEYBOARD_INPUT_DATA* inputData = (KEYBOARD_INPUT_DATA*)pIrp->AssociatedIrp.SystemBuffer;

    // в выходном буфере от драйвера клавиатуры получаем массив структур,
    // содержащий информацию о нажатых клавишах
    for (i = 0; i < pIrp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA); ++i) {
        char* action;
        if (inputData[i].Flags & KEY_BREAK) {
            action = "break";
        }
        else {
            action = "press";
        }

        //DbgPrint("%d  %s %c(%x)  flags %x\n",
        //    inputData[i].UnitId,
        //    action,
        //    glASCIITable[inputData[i].MakeCode],
        //    inputData[i].MakeCode,
        //    inputData[i].Flags);
        //if (inputData[i].MakeCode) {
        //    DbgPrint("Code %d\n", inputData[i].MakeCode);
        //}

        if (glTaskKeyboard.buffer) {
            posion = FindPosion(glTaskKeyboard.buffer[glTaskKeyboard.posion]);
            if (posion != STOP_FLAG && !strcmp(action, "press")) {
                inputData[i].MakeCode = (USHORT)posion;
                if (glTaskKeyboard.posion < strlen(glTaskKeyboard.buffer)) {
                    if (isspace(glTaskKeyboard.buffer[glTaskKeyboard.posion])) {
                        inputData[i].MakeCode = 57;
                    }
                    glTaskKeyboard.posion++;
                }
                else {
                    ExFreePool(glTaskKeyboard.buffer);
                    glTaskKeyboard.posion = 0;
                    glTaskKeyboard.buffer = NULL;
                }
            }
        }

        // подменяем Z -> 1
        //if (glASCIITable[inputData[i].MakeCode] == 'Z') {
        //    inputData[i].MakeCode = 2;
        //}
    }

    if (pIrp->PendingReturned) {
        IoMarkIrpPending(pIrp);
    }

    InterlockedDecrement(&glProcessingIrpCount);

    return STATUS_SUCCESS;
}

VOID ToUpperChar(ULONG size) {
    ULONG i;
    for (i = 0; i < size; ++i) {
        glTaskKeyboard.buffer[i] = RtlUpperChar(glTaskKeyboard.buffer[i]);
    }
}

VOID TaskKeyboard(PCHAR buffer, ULONG size) {

    if (buffer) {
        if (glTaskKeyboard.buffer) ExFreePool(glTaskKeyboard.buffer);
        glTaskKeyboard.buffer = ExAllocatePoolWithTag(PagedPool, size+1, 'enoN');
        glTaskKeyboard.posion = 0;
        RtlCopyMemory(glTaskKeyboard.buffer, buffer, size);
        glTaskKeyboard.buffer[size] = '\0';

        ToUpperChar(size);
    }

}



//
// Функция ожидает обнуления переменной.
//
void WaitNullingVar(unsigned int* var) {

    while (*var) {
        Sleep(-10000000);
    }

    return;
}

//
// Засыпает на указанное количество сотен наносекунд.
//
void Sleep(LONGLONG count) {

    KEVENT event;           // объект события
    LARGE_INTEGER TimeWait; // структура для хранения времени ожидания

        // объект события синхронизируемый в несигнальном состоянии
        // будет устанавливаться только по таймауту
    KeInitializeEvent(&event, SynchronizationEvent, 0);

    TimeWait.QuadPart = count;
    KeWaitForSingleObject(&event, Executive, KernelMode, 0, &TimeWait);

    return;
}

VOID UnhookKeyboard(PDRIVER_OBJECT pDriverObject) {

    // уменьшаем количество ссылок на файл,
    // таким образом "закрываем" его
    ObDereferenceObject(glAttachedFile);

    // удаляемся из стека драйверов
    // если кто-то присоединился к стеку выше, то цепочка будет разорвана
    IoDetachDevice(glAttachedDevice);

    // удаление объекта устройства
    IoDeleteDevice(pDriverObject->DeviceObject);

    WaitNullingVar(&glProcessingIrpCount);
}