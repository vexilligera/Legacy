#include "Environment.h"

Environment::Environment() {
	std::string str;
	fRunnable = IsWindows7OrGreater();
	GetMacAddress(str);
	GetSystemVersion(dwMajorVer);
	SystemBit = GetSystemBit();
	GetBiosSerialNumber();
}

bool Environment::IsRunnable() {
	return fRunnable;
}

bool Environment::GetMacAddress(std::string &macAddr) {
	ULONG ulSize = 0;
	PIP_ADAPTER_INFO pInfo = NULL;
	int temp = 0;
	temp = GetAdaptersInfo(pInfo, &ulSize);
	pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
	temp = GetAdaptersInfo(pInfo, &ulSize);
	char mac[256];
	int iCount = 0;
	while (pInfo) {
		for (int i = 0; i<(int)pInfo->AddressLength; i++) {
			byte2Hex(pInfo->Address[i], (unsigned char*)&mac[iCount]);
			iCount += 2;
			if (i<(int)pInfo->AddressLength - 1)
				mac[iCount++] = ':';
			else
				mac[iCount++] = ',';
		}
		pInfo = pInfo->Next;
	}
	if (iCount > 0) {
		mac[iCount] = '\0';
		macAddr = mac;
		std::string tmp;
		for (auto i = macAddr.begin(); i != macAddr.end(); ++i) {
			if (*i != ',')
				tmp += *i;
			else {
				tmp += '\0';
				MACAddr.push_back(tmp);
				tmp.clear();
			}
		}
		*(macAddr.end() - 1) = '\0';
		return true;
	}
	else return false;
}

bool Environment::GetSystemVersion(DWORD &MajorVer) {
	bool bRet = false;
	HMODULE hModNtdll = NULL;
	if (hModNtdll = LoadLibrary(TEXT("ntdll.dll")))
	{
		typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*, DWORD*, DWORD*);
		pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
		pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
		if (pfRtlGetNtVersionNumbers)
		{
			pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer, &dwBuildNumber);
			dwBuildNumber &= 0x0ffff;
			MajorVer = dwBuildNumber;
			bRet = true;
		}

		FreeLibrary(hModNtdll);
		hModNtdll = NULL;
	}

	return bRet;
}

int Environment::GetSystemBit() {
	SYSTEM_INFO si;
	int ret;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		ret = 64;
	else
		ret = 32;
	SystemBit = ret;
	return ret;
}

bool Environment::IsInsideVM() {
	ShellCmd cmd;
	std::string output;
	if(!cmd.Cmd("wmic bios",output))
		return false;
	if (output.find("VMWare") != std::string::npos || output.find("VMW") != std::string::npos)
		return true;
	return false;
}

const char* Environment::GetBiosSerialNumber() {
	std::string output;
	ShellCmd cmd;
	cmd.Cmd("wmic bios get serialnumber", output);
	size_t pos;
	char sz[] = "SerialNumber";
	if ((pos = output.find(sz)) != std::string::npos)
		output.replace(output.begin() + pos, output.begin() + pos + strlen(sz), "");
	char str[2] = "\r";
	while ((pos = output.find(str)) != std::string::npos)
		output.replace(output.begin() + pos, output.begin() + pos + strlen(str), "");
	*str = '\n';
	while ((pos = output.find(str)) != std::string::npos)
		output.replace(output.begin() + pos, output.begin() + pos + strlen(str), "");
	*str = ' ';
	while ((pos = output.find(str)) != std::string::npos)
		output.replace(output.begin() + pos, output.begin() + pos + strlen(str), "");
	BiosSerialNumber = output;
	return BiosSerialNumber.c_str();
}