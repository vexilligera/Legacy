#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _DEBUG_
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

int DbgMsgBox(TCHAR *szCaption, TCHAR *szFormat, ...);
int DbgMsgBoxA(CHAR *szCaption, CHAR *szFormat, ...);