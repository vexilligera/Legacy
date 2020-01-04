#pragma once
#pragma comment(lib,"shlwapi.lib")
#include <Windows.h>
#include <shlwapi.h>

class UACHelper {
public:
	LSTATUS BypassUacRun(LPCTSTR szPath);
	bool IsAdmin();
	void CleanUp();
};