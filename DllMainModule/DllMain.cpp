#include "DllMain.h"

bool APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, TEXT("ATTACH"), TEXT("ATTACH"), MB_OK);
		break;
	default:
		break;
	}
	return TRUE;
}