#include <windows.h>
#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>

//----------------------------------------

// Выводит на консоль текстовое пояснение переданного кода ошибки
void PrintErrorMessage(DWORD err){
	char *msg;
    char *conmsg;
	DWORD res= FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_ALLOCATE_BUFFER,
			NULL,
			err,    // код ошибки
			0,      // идентификатор языка по-умолчанию
			(LPTSTR) &msg, 0, NULL);
	if(res) {
        conmsg=(char*)malloc(strlen(msg) + 1);
        CharToOemA(msg,conmsg);
		printf("%s",conmsg);    // вывод сообщения на экран
		LocalFree(msg);     // освобождение буфера с текстом сообщения
		free(conmsg);
	    }
    
    return;
}

//----------------------------------------

BOOLEAN InstallDriver(char* DriverName, char* LoadPath){
	
SC_HANDLE   SCManager;
SC_HANDLE   service;
DWORD       err;

    // открываю менеджер служб
    SCManager=OpenSCManager(0,          // локальный компьютер
                            0,          // текущая база данных сервисов
                            SC_MANAGER_ALL_ACCESS   // права доступа
                            );

    if(!SCManager){
        PrintErrorMessage(GetLastError());
        return FALSE;
        }
    

    service = CreateServiceA(SCManager,              // описатель диспетчера сервисов
                               DriverName,              // имя устанавливаемого сервиса
                               DriverName,              // отображаемое имя устанавливаемого сервиса
                               SERVICE_ALL_ACCESS,      // тип доступа к сервису
                               SERVICE_KERNEL_DRIVER,   // тип сервиса
                               SERVICE_DEMAND_START,    // параметр запуска:
                                                        // SERVICE_AUTO_START - загружается автоматически менеджером сервисов
                                                        // SERVICE_BOOT_START - загружается при загрузке системы
                                                        // SERVICE_DEMAND_START - загружается менеджером сервисов по требованию
                               SERVICE_ERROR_NORMAL,    // реакция на ошибки при старте сервиса
                               LoadPath,                // путь к исполняемому файлу
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL
                               );

    if(service == NULL){
        err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            return TRUE;
        else{
            PrintErrorMessage(err);
            return FALSE;
            }
        }

    CloseServiceHandle(service);

    CloseServiceHandle(SCManager);

    return TRUE;
}

//----------------------------------------

BOOLEAN RemoveDriver(char* DriverName){

SC_HANDLE   service;
SC_HANDLE   SCManager;

    SCManager=OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
    if(!SCManager){
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    service = OpenServiceA(SCManager,
                          DriverName,
                          SERVICE_ALL_ACCESS
                          );

    if (service == NULL) {
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    if(!DeleteService(service)) {
        PrintErrorMessage(GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(SCManager);
        return FALSE;
        }

    CloseServiceHandle(service);

    CloseServiceHandle(SCManager);

    return TRUE;
}

//----------------------------------------

BOOLEAN StartDriver(char* DriverName){
    
SC_HANDLE   service;
SC_HANDLE   SCManager;
DWORD err;

    SCManager=OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
    if(!SCManager){
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    service = OpenServiceA(SCManager, DriverName, SERVICE_ALL_ACCESS);

    if (service == NULL) {
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    if (!StartService(service, 0, NULL)) {

        err = GetLastError();

        if(err == ERROR_SERVICE_ALREADY_RUNNING)
            return TRUE;
        else{
            PrintErrorMessage(GetLastError());
            return FALSE;
            }
        }

    CloseServiceHandle(service);

    CloseServiceHandle(SCManager);

    return TRUE;
}

//----------------------------------------

BOOLEAN StopDriver(char* DriverName){

SC_HANDLE   service;
SC_HANDLE   SCManager;
SERVICE_STATUS serstatus;

    SCManager=OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
    if(!SCManager){
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    service = OpenServiceA(SCManager, DriverName, SERVICE_ALL_ACCESS);

    if (service == NULL) {
        PrintErrorMessage(GetLastError());
        return FALSE;
        }

    if (!ControlService(service, SERVICE_CONTROL_STOP, &serstatus)){
        PrintErrorMessage(GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(SCManager);
        return FALSE;
        }

    CloseServiceHandle(service);

    CloseServiceHandle(SCManager);

    return TRUE;

}

//----------------------------------------


