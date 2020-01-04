#pragma once
#include <Windows.h>
#include "ntos.h"

typedef long(__fastcall *RTLADJUSTPRIVILEGE64)(ULONG, ULONG, ULONG, PVOID);
typedef NTSTATUS(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef VOID(WINAPI *fRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR ourceString);
typedef NTSTATUS(WINAPI *fLdrLoadDll)(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING  ModuleFileName, OUT PHANDLE ModuleHandle);
typedef DWORD64(WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, *PTHREAD_DATA;

class DllInjector {
private:
	RTLADJUSTPRIVILEGE64 RtlAdjustPrivilege;
	const ULONG SeDebugPrivilege = 20;
	BOOL EnableDebugPrivilege();
	HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf);
public:
	DllInjector();
	bool DllInjectRing3W(DWORD dwProcessId, LPCWSTR lpcwDllPath);
};