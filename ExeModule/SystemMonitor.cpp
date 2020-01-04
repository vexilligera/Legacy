#include "SystemMonitor.h"
#include "Debug.h"

int GetEncoderClsid(const WCHAR* format, CLSID* pCLSID) {
	using namespace Gdiplus;
	//�õ���ʽΪformat��ͼ���ļ��ı���ֵ�����ʸø�ʽͼ���COM�����GUIDֵ������pCLSID��  
	UINT num = 0;
	UINT size = 0;
	ImageCodecInfo* pImageCodecInfo = NULL;
	GetImageEncodersSize(&num, &size);
	if (size == 0)
		return FALSE;   //   ������Ϣ������ 
	pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
	if (pImageCodecInfo == NULL)
		return FALSE;   //   ����ʧ�� 
						//���ϵͳ�п��õı��뷽ʽ��������Ϣ  
	GetImageEncoders(num, size, pImageCodecInfo);
	//�ڿ��ñ�����Ϣ�в���format��ʽ�Ƿ�֧��  
	for (UINT i = 0; i < num; ++i)
	{
		//MimeType�����뷽ʽ�ľ�������  
		if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0)
		{
			*pCLSID = pImageCodecInfo[i].Clsid;
			free(pImageCodecInfo);
			return TRUE;
		}
	}
	free(pImageCodecInfo);
	return FALSE;
}

bool SystemMonitor::GetScreenShot(BinaryData &out) {
	using namespace Gdiplus;
	SetProcessDPIAware();
	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	int nScreenWidth = GetSystemMetrics(SM_CXSCREEN);
	int nScreenHeight = GetSystemMetrics(SM_CYSCREEN);
	HWND hDesktopWnd = GetDesktopWindow();
	HDC hDesktopDC = GetDC(hDesktopWnd);
	HDC hCaptureDC = CreateCompatibleDC(hDesktopDC);
	HBITMAP hCaptureBitmap = CreateCompatibleBitmap(hDesktopDC, nScreenWidth, nScreenHeight);
	SelectObject(hCaptureDC, hCaptureBitmap);
	BitBlt(hCaptureDC, 0, 0, nScreenWidth, nScreenHeight, hDesktopDC, 0, 0, SRCCOPY | CAPTUREBLT);
	Bitmap *bitmap = new Bitmap(hCaptureBitmap, NULL);
	Image *image = bitmap;
	CLSID encoderClsid;
	GetEncoderClsid(L"image/png", &encoderClsid);
	IStream *pStream = nullptr;
	bool ret;
	CreateStreamOnHGlobal(nullptr, false, &pStream);
	LARGE_INTEGER seekPos = { 0 };
	pStream->Seek(seekPos, STREAM_SEEK_SET, 0);
	Status stat = image->Save(pStream, &encoderClsid);
	STATSTG statstg;
	pStream->Stat(&statstg, STATFLAG_NONAME);
	ULONG nDatalen = statstg.cbSize.QuadPart;
	char *buffer = new char[nDatalen];
	memset(buffer, 0, nDatalen);
	pStream->Seek(seekPos, STREAM_SEEK_SET, 0);
	pStream->Read(buffer, nDatalen, &nDatalen);
	out.SetData(buffer, nDatalen);
	if (stat == Ok)
		ret = true;
	else ret = false;
	if (!nDatalen)
		ret = false;
	delete[] buffer;
	pStream->Release();
	ReleaseDC(hDesktopWnd, hDesktopDC);
	DeleteDC(hCaptureDC);
	DeleteObject(hCaptureBitmap);
	delete bitmap;
	GdiplusShutdown(gdiplusToken);
	return ret;
}

bool SystemMonitor::GetCameraShot(BinaryData &out, ULONG mode) {
	
	return false;
}