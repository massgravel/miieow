#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

/* ------------------------------- CFG ------------------------------- */

#include <slpublic.h>
#pragma comment(lib, "slc.lib")

#define DRIVER_NAME L"miieow"

#define PROCESS_NAME L"sppsvc.exe"
#define MODULE_NAME L"sppsvc.exe"

#define OFFSET 0
#define SIGNATURE_SZ 10
#define SIGNATURE { 0x8B, 0x7D, 0x00, 0x85, 0xFF, 0x75, 0x00, 0x49, 0x8B, 0x06 }
#define MASK { 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 }

#define PATCH { 0x31, 0xff, 0x90 }
#define PATCH_SZ 3

static HSLC hSLC = NULL;
void Pre()
{
	// Spin up an sppsvc.exe instance
	SLOpen(&hSLC);
}

void Post()
{
	SLClose(hSLC);
}

/* ------------------------------- CFG ------------------------------- */


/* --------------------------- MIIEow API --------------------------- */

// MIIEow Interface
#define MwCtlReadProcessMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define MwCtlWriteProcessMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define MwCtlProtectProcessMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define MwCtlGetModuleInfo CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

struct MwVmRequest
{
	_In_  DWORD ProcessId;
	_In_  PVOID Src;
	_In_  SIZE_T Size;
	_Out_ PVOID Dst;
};

struct MwVpRequest
{
	_In_  DWORD ProcessId;
	_In_  PVOID Address;
	_In_  ULONG NewProt;
	_In_  SIZE_T Size;
	_Out_ ULONG* pOldProt;
};

struct MwMiRequest
{
	_In_  DWORD ProcessId;
	_In_  WCHAR Module[256];
	_Out_ PVOID BaseAddr;
	_Out_ ULONG Size;
};
// MIIEow Interface

struct MIIEow
{
	HANDLE hDriver;
	DWORD ProcessId;
};

struct MIIEow*
MwcCreate(_In_ DWORD ProcessId)
{
	struct MIIEow* pMIIEow = (struct MIIEow*)malloc(sizeof(struct MIIEow));
	if (pMIIEow != NULL)
	{
		pMIIEow->ProcessId = ProcessId;
		pMIIEow->hDriver = CreateFileW(L"\\\\.\\" DRIVER_NAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		return pMIIEow;
	}
	else
	{
		MessageBoxW(NULL, L"Failed to init Mwc", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
}

void
MwcReadProcessMemory(struct MIIEow *pMIIEow, _In_ PVOID Address, _In_ SIZE_T Size, _Out_ PVOID pBuffer)
{
	struct MwVmRequest r;
	r.ProcessId = pMIIEow->ProcessId;
	r.Src = Address;
	r.Dst = pBuffer;
	r.Size = Size;

	if (DeviceIoControl(pMIIEow->hDriver, MwCtlReadProcessMemory, (PVOID)&r, sizeof(r), (PVOID)&r, sizeof(r), NULL, NULL) == FALSE)
	{
		MessageBoxW(NULL, L"Failed to read memory", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
}

void
MwcWriteProcessMemory(struct MIIEow* pMIIEow, _In_ PVOID Address, _In_ SIZE_T Size, _In_ PVOID pBuffer)
{
	struct MwVmRequest r;
	r.ProcessId = pMIIEow->ProcessId;
	r.Src = pBuffer;
	r.Dst = Address;
	r.Size = Size;

	if (DeviceIoControl(pMIIEow->hDriver, MwCtlWriteProcessMemory, (PVOID)&r, sizeof(r), (PVOID)&r, sizeof(r), NULL, NULL) == FALSE)
	{
		MessageBoxW(NULL, L"Failed to write memory", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
}

void
MwcProtectProcessMemory(struct MIIEow* pMIIEow, _In_ PVOID Address, _In_ SIZE_T Size, _In_ ULONG NewProt, _Out_ ULONG* pOldProt)
{
	struct MwVpRequest r;
	r.ProcessId = pMIIEow->ProcessId;
	r.Address = Address;
	r.NewProt = NewProt;
	r.Size = Size;
	r.pOldProt = pOldProt;

	if (DeviceIoControl(pMIIEow->hDriver, MwCtlProtectProcessMemory, (PVOID)&r, sizeof(r), (PVOID)&r, sizeof(r), NULL, NULL) == FALSE)
	{
		MessageBoxW(NULL, L"Failed to virtual protect memory", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
}

struct MwMiRequest
MwcGetModuleInfo(struct MIIEow* pMIIEow, LPCWSTR ModuleName)
{
	struct MwMiRequest r;
	r.ProcessId = pMIIEow->ProcessId;
	wcscpy_s(r.Module, 256, ModuleName);
	
	if (DeviceIoControl(pMIIEow->hDriver, MwCtlGetModuleInfo, (PVOID)&r, sizeof(r), (PVOID)&r, sizeof(r), NULL, NULL) == FALSE)
	{
		MessageBoxW(NULL, L"Failed to get base address", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
	
	return r;
}

void
MwcDelete(struct MIIEow* pMIIEow)
{
	if (pMIIEow != NULL)
	{
		if (pMIIEow->hDriver != INVALID_HANDLE_VALUE)
		{
			CloseHandle(pMIIEow->hDriver);
		}
		free(pMIIEow);
	}
}

/* --------------------------- MIIEow API --------------------------- */

PVOID
SignatureScan(struct MIIEow* pMIIEow, PVOID BaseAddress, SIZE_T Size)
{
	PVOID EndAddress = (PVOID)((SIZE_T)BaseAddress + Size);

	const BYTE Signature[SIGNATURE_SZ] = SIGNATURE;
	const BYTE Mask[SIGNATURE_SZ] = MASK;

	for (BYTE* Address = BaseAddress; Address < ((SIZE_T)EndAddress - SIGNATURE_SZ); Address++)
	{
		// TODO: Do this by page, ioctl is expensive
		BYTE Buffer[SIGNATURE_SZ] = { 0 };
		MwcReadProcessMemory(pMIIEow, Address, SIGNATURE_SZ, Buffer);

		BOOL Found = TRUE;
		for (int i = 0; i < SIGNATURE_SZ; i++)
		{
			if (Mask[i] == 0 && Buffer[i] != Signature[i])
			{
				Found = FALSE;
				break;
			}
		}
		if (Found) return Address + OFFSET;
	}
	return NULL;
}


DWORD
GetProcessIdByName(LPCWSTR processName)
{
	PROCESSENTRY32 Entry;
	Entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(Snapshot, &Entry) == TRUE)
	{
		while (Process32Next(Snapshot, &Entry) == TRUE)
		{
			if (_wcsicmp(Entry.szExeFile, processName) == 0)
			{
				CloseHandle(Snapshot);
				return Entry.th32ProcessID;
			}
		}
	}
	CloseHandle(Snapshot);
	return (DWORD)-1;
}

int main()
{
	Pre();

	LPCWSTR TargetProcessName = PROCESS_NAME;
	DWORD ProcessId = GetProcessIdByName(TargetProcessName);

	if (ProcessId == (DWORD)-1)
	{
		MessageBoxW(NULL, L"Failed to find target process", L"Error", MB_OK | MB_ICONERROR);
		ExitProcess(1);
	}
	printf("[+] Located target process\n");

	struct MIIEow* pMIIEow = MwcCreate(ProcessId);
	printf("[+] MIIEow initialised\n");

	struct MwMiRequest ModuleInfo = MwcGetModuleInfo(pMIIEow, MODULE_NAME);
	printf("[+] Got base address : %zx\n", (SIZE_T)ModuleInfo.BaseAddr);

	PVOID PatchAddr = SignatureScan(pMIIEow, ModuleInfo.BaseAddr, ModuleInfo.Size);
	printf("[+] Scan result : %zx\n", (SIZE_T)PatchAddr);

	BYTE SanityByte;
	MwcReadProcessMemory(pMIIEow, PatchAddr, 1, &SanityByte);
	printf("[+] Sanity byte : %zx\n", (SIZE_T)SanityByte);

	ULONG OldProt;
	MwcProtectProcessMemory(pMIIEow, PatchAddr, 4096, PAGE_EXECUTE_READWRITE, &OldProt);

	printf("[+] Set protection to RWX\n");

	const BYTE Patch[PATCH_SZ] = PATCH;
	MwcWriteProcessMemory(pMIIEow, PatchAddr, PATCH_SZ, Patch);
	printf("[+] Patched\n");

	ULONG _;
	MwcProtectProcessMemory(pMIIEow, PatchAddr, 4096, OldProt, &_);
	printf("[+] Restored protection\n");

	MwcDelete(pMIIEow);

	Post();

	return 0;
}
