#pragma once
#include <Windows.h>
#include <Iphlpapi.h>
#include <VersionHelpers.h>
#include <string>
#include <vector>
#include "ShellCmd.h"
#pragma comment(lib,"Iphlpapi.lib")

class Environment {
private:
	bool fRunnable;
	std::vector<std::string> MACAddr;
	DWORD dwMajorVer, dwMinorVer, dwBuildNumber;
	int SystemBit;
	std::string BiosSerialNumber;
public:
	Environment();
	bool IsRunnable();
	bool GetMacAddress(std::string &macAddr);
	bool GetSystemVersion(DWORD &MajorVer);
	int GetSystemBit();
	bool IsInsideVM();
	const char* GetBiosSerialNumber();
};