#include "Debug.h"

int DbgMsgBox(TCHAR *szCaption, TCHAR *szFormat, ...) {
	TCHAR szBuffer[1024];
	va_list pArgList;
	va_start(pArgList, szFormat);
	_vsntprintf(szBuffer, sizeof(szBuffer) / sizeof(TCHAR), szFormat, pArgList);
	va_end(pArgList);
	return MessageBox(NULL, szBuffer, szCaption, MB_OK);
}

int DbgMsgBoxA(CHAR *szCaption, CHAR *szFormat, ...) {
	CHAR szBuffer[1024];
	va_list pArgList;
	va_start(pArgList, szFormat);
	vsnprintf(szBuffer, sizeof(szBuffer) / sizeof(CHAR), szFormat, pArgList);
	va_end(pArgList);
	return MessageBoxA(NULL, szBuffer, szCaption, MB_OK);
}