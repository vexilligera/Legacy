#include "ShellCmd.h"

bool ShellCmd::Run(const char *in, std::string &out) {
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
		return false;
	const char *command = in;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfo(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	wchar_t wcmd[2048];
	ctow(wcmd, command);
	if (!CreateProcess(NULL, wcmd, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {
		CloseHandle(hWrite);
		CloseHandle(hRead);
		return false;
	}
	CloseHandle(hWrite);
	char buffer[4096] = { 0 };
	DWORD bytesRead;
	size_t totalbytes = 0;
	while (true) {
		if (ReadFile(hRead, buffer + totalbytes, 4095, &bytesRead, NULL) == NULL)
			break;
		totalbytes += bytesRead;
	}
	out = buffer;
	CloseHandle(hRead);
	return true;
}

bool ShellCmd::Cmd(const char *in, std::string &out) {
	char command[1024];
	strcpy_s(command, 1024, "Cmd.exe /C ");
	strcat_s(command, 1024, in);
	return Run(command, out);
}

bool ShellCmd::Powershell(const char *in, std::string &out) {
	char command[1024];
	strcpy_s(command, 1024, "Powershell.exe /C ");
	strcat_s(command, 1024, in);
	return Run(command, out);
}