#include "DllInjector.h"

HANDLE WINAPI ThreadProc(PTHREAD_DATA data){
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd(){
	return 0;
}

BOOL DllInjector::EnableDebugPrivilege(){
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(FALSE);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;
	return TRUE;
}

HANDLE DllInjector::MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf){
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;
	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)	{
		return NULL;
	}
	((_NtCreateThreadEx64)pFunc)(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
	if (!hThread)	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
		if (hThread == NULL)		{
			return NULL;
		}
	}
	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))	{
		return NULL;
	}
	return hThread;
}

bool DllInjector::DllInjectRing3W(DWORD dwProcessId, LPCWSTR lpcwDllPath)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	LPVOID pCode = NULL;
	LPVOID pThreadData = NULL;
	__try
	{
		if (!EnableDebugPrivilege()){
			return -1;
		}
		//打开目标进程;
		pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwProcessId);
		DWORD dwError = GetLastError();
		if (hProcess == NULL) {
			OBJECT_ATTRIBUTES oa = { 0 };
			CLIENT_ID cid;
			cid.UniqueProcess = (HANDLE)dwProcessId;
			cid.UniqueThread = NULL;
			myNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
		}
		if (hProcess == NULL)
			__leave;
		//申请空间，把我们的代码和数据写入目标进程空间里;
		//写入数据;
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
		memcpy(data.DllName, lpcwDllPath, (wcslen(lpcwDllPath) + 1) * sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
			__leave;
		BOOL bWriteOK = WriteProcessMemory(hProcess, pThreadData, &data, sizeof(data), NULL);
		if (!bWriteOK)
			__leave;
		//写入代码;
		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		pCode = VirtualAllocEx(hProcess, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			__leave;
		}
		bWriteOK = WriteProcessMemory(hProcess, pCode, (PVOID)ThreadProc, SizeOfCode, NULL);
		if (!bWriteOK)
			__leave;
		//创建远程线程，把ThreadProc作为线程起始函数，pThreadData作为参数;
		hThread = MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
			__leave;
		//等待完成;
		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(hProcess, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return bRet;
}

DllInjector::DllInjector() {
	DWORD dwRetVal;
	RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE64)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "RtlAdjustPrivilege");
	RtlAdjustPrivilege(SeDebugPrivilege, true, NULL, &dwRetVal);
}