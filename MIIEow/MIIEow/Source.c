#include <ntifs.h>
#include <minwindef.h>

#include "Undocumented.h"

#define DRIVER_NAME "miieow"

static UNICODE_STRING DriverName;
static UNICODE_STRING DeviceName;
static UNICODE_STRING SymbolicLink;

NTSTATUS
MwCreate(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp);

NTSTATUS
MwClose(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp);

NTSTATUS
MwCtl(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp);

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

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);


	NTSTATUS Status = STATUS_SUCCESS;

	RtlInitUnicodeString(&DriverName, L"\\Driver\\" DRIVER_NAME);
	RtlInitUnicodeString(&DeviceName, L"\\Device\\" DRIVER_NAME);
	RtlInitUnicodeString(&SymbolicLink, L"\\DosDevices\\" DRIVER_NAME);
	
	if (pDriverObject == NULL)
	{
		return IoCreateDriver(&DriverName, &DriverEntry);
	}

	PDEVICE_OBJECT pDeviceObject = NULL;
	Status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}

	Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
	if (Status != STATUS_SUCCESS)
	{
		return Status;
	}

	SetFlag(pDeviceObject->Flags, DO_BUFFERED_IO);
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MwCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MwClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MwCtl;

	ClearFlag(pDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	return Status;
}

NTSTATUS
MwCopyVirtualMemory(_In_ PEPROCESS pSourceProcess, _In_ PVOID SourceAddress, _In_ PEPROCESS pDestinationProcess, _In_ PVOID DestinationAddress, _In_ SIZE_T Size)
{
	NTSTATUS Status;

	SIZE_T ReturnSize;
	Status = MmCopyVirtualMemory(pSourceProcess, SourceAddress, pDestinationProcess, DestinationAddress, Size, KernelMode, &ReturnSize);

	return Status;
}

NTSTATUS
MwCreate(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS
MwClose(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS
MwCtl(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(pIrp);

	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pTargetProcess = NULL;

	pIrp->IoStatus.Information = 0;

	PIO_STACK_LOCATION pStackIrp = IoGetCurrentIrpStackLocation(pIrp);
	if (pStackIrp == NULL || pIrp->AssociatedIrp.SystemBuffer == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}

	const ULONG ControlCode = pStackIrp->Parameters.DeviceIoControl.IoControlCode;
	switch (ControlCode)
	{
	case MwCtlReadProcessMemory:
	{
		struct MwVmRequest *Request = (struct MwVmRequest *)pIrp->AssociatedIrp.SystemBuffer;
		
		Status = PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &pTargetProcess);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		Status = MwCopyVirtualMemory(pTargetProcess, Request->Src, PsGetCurrentProcess(), Request->Dst, Request->Size);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		pIrp->IoStatus.Information = sizeof(struct MwVmRequest);
		break;
	}

	case MwCtlWriteProcessMemory:
	{
		struct MwVmRequest* Request = (struct MwVmRequest*)pIrp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &pTargetProcess);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		Status = MwCopyVirtualMemory(PsGetCurrentProcess(), Request->Src, pTargetProcess, Request->Dst, Request->Size);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		pIrp->IoStatus.Information = sizeof(struct MwVmRequest);
		break;
	}

	case MwCtlProtectProcessMemory:
	{
		struct MwVpRequest* Request = (struct MwVpRequest*)pIrp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &pTargetProcess);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		// Locals used in usermode address space scope must be stack relative
		// due to cr3 being modified. However, the stack is still paged in and
		// other normal registers are preserved
		PVOID Address = Request->Address;
		SIZE_T Size = Request->Size;
		ULONG NewProt = Request->NewProt;
		ULONG OldProt;

		KAPC_STATE state = { 0 };
		KeStackAttachProcess(pTargetProcess, &state);
		{
			Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &Address, &Size, NewProt, &OldProt);
		}
		KeUnstackDetachProcess(&state);

		*Request->pOldProt = OldProt;
		pIrp->IoStatus.Information = sizeof(struct MwVpRequest);
		break;
	}

	case MwCtlGetModuleInfo:
	{
		struct MwMiRequest* pRequest = (struct MwMiRequest*)pIrp->AssociatedIrp.SystemBuffer;

		Status = PsLookupProcessByProcessId((HANDLE)pRequest->ProcessId, &pTargetProcess);
		if (Status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		PEB* pPeb = PsGetProcessPeb(pTargetProcess);

		UNICODE_STRING TargetModule;
		RtlInitUnicodeString(&TargetModule, pRequest->Module);

		PVOID ModuleBase = NULL;
		ULONG ModuleSize = 0;
		{
			KAPC_STATE State;
			KeStackAttachProcess(pTargetProcess, &State);
			{
				for (PLIST_ENTRY entry = pPeb->Ldr->InLoadOrderModuleList.Flink; entry != &pPeb->Ldr->InLoadOrderModuleList; entry = entry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY _entry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					if (RtlCompareUnicodeString(&TargetModule, &_entry->BaseDllName, TRUE) == 0)
					{
						ModuleBase = _entry->DllBase;
						ModuleSize = _entry->SizeOfImage;
					}
				}
			}
			KeUnstackDetachProcess(&State);
		}

		pRequest->BaseAddr = ModuleBase;
		pRequest->Size = ModuleSize;

		pIrp->IoStatus.Information = sizeof(struct MwMiRequest);
		break;
	}

	default:
	{
		Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = 0;
		break;
	}
	}

Cleanup:
	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}