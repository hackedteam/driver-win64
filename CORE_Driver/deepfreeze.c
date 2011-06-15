#define INITGUID

#include <ntifs.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include "stdarg.h"
#include "stdio.h"
#include <ntddvol.h>
#include <ntiologc.h>

#include <mountdev.h>
#include "sector.h"
#include "driver.h"
#include "main.h"


PVOID saved_major[IRP_MJ_MAXIMUM_FUNCTION+1];

WCHAR mdev_name[] = DEEPUNFREEZE_DEVICE;
WCHAR mdev_uniq[] = DEEPUNFREEZE_UNIQUE_ID;
WCHAR mdev_mask[] = L"\\DosDevices\\%c:";
WCHAR mdev_link[64];
INT mounted = 0;

PDEVICE_OBJECT freezed_device;
PDEVICE_OBJECT thawed_device;


typedef NTSTATUS (* DispFunc_t)(IN PDEVICE_OBJECT dobj, IN PIRP Irp);


// Suspend current thread for a number of milliseconds
void KSleep (int milliSeconds)
{
#define malloc(size) ((void *) ExAllocatePoolWithTag( NonPagedPool, size, 'MMRD' ))
#define free(memblock) ExFreePoolWithTag( memblock, 'MMRD' )

	PKTIMER timer = (PKTIMER) malloc(sizeof (KTIMER));
	LARGE_INTEGER duetime;

	if (!timer)
		return;

	duetime.QuadPart = (__int64) milliSeconds * -10000;
	KeInitializeTimerEx(timer, NotificationTimer);
	KeSetTimerEx(timer, duetime, 0, NULL);

	KeWaitForSingleObject (timer, Executive, KernelMode, FALSE, NULL);

	free(timer);
}

NTSTATUS DrvDeviceIOControl(PWSTR deviceName, ULONG IoControlCode,
							void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	PFILE_OBJECT fileObject;
	PDEVICE_OBJECT deviceObject;
	KEVENT event;
	UNICODE_STRING name;

	RtlInitUnicodeString(&name, deviceName);
	ntStatus = IoGetDeviceObjectPointer (&name, FILE_READ_ATTRIBUTES, &fileObject, &deviceObject);

	if (ntStatus != STATUS_SUCCESS) 
		return ntStatus;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
		deviceObject,
		InputBuffer, InputBufferSize,
		OutputBuffer, OutputBufferSize,
		FALSE,
		&event,
		&ioStatusBlock);
	if (irp == NULL) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto ret;
	}

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, Executive, KernelMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

ret:
	ObDereferenceObject (fileObject);

	DTRACE("DrvDeviceIOControl returned %X", ntStatus);
	return ntStatus;
}


NTSTATUS MountManagerMount (WCHAR *NTName, WCHAR *DOSName)
{
	NTSTATUS ntStatus; 
	WCHAR arrVolume[256];
	char buf[400];
	PMOUNTMGR_TARGET_NAME in = (PMOUNTMGR_TARGET_NAME) buf;
	PMOUNTMGR_CREATE_POINT_INPUT point = (PMOUNTMGR_CREATE_POINT_INPUT) buf;
	UNICODE_STRING symName, devName;
	ULONG i;
	int count = 0;

	wcscpy(arrVolume, NTName);
	in->DeviceNameLength = (USHORT) wcslen (arrVolume) * 2;
	wcscpy(in->DeviceName, arrVolume);

	ntStatus = DrvDeviceIOControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
		in, sizeof (in->DeviceNameLength) + wcslen (arrVolume) * 2, 0, 0);

	DTRACE("IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION returned %X", ntStatus);

#if 0
	memset (buf, 0, sizeof buf);
	DTRACE("DOSName: [%x] [%S] ", wcslen(DOSName), DOSName);
	wcscpy((PWSTR) &point[1], DOSName);

	point->SymbolicLinkNameOffset = sizeof (MOUNTMGR_CREATE_POINT_INPUT);
	point->SymbolicLinkNameLength = (USHORT) wcslen ((PWSTR) &point[1]) * 2;

	RtlInitUnicodeString(&symName, (PWSTR) (buf + point->SymbolicLinkNameOffset));

	point->DeviceNameOffset = point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength;
	DTRACE("NTName: [%x] [%S] ", wcslen(NTName), NTName);
	wcscpy ((PWSTR) (buf + point->DeviceNameOffset), NTName);
	point->DeviceNameLength = (USHORT) wcslen ((PWSTR) (buf + point->DeviceNameOffset)) * 2;

	RtlInitUnicodeString(&devName, (PWSTR) (buf + point->DeviceNameOffset));

	DTRACE("CREATE_MOUNT_POINT: [%x] [%S][%x]", point->SymbolicLinkNameLength, &point[1], wcslen(&point[1]));
	DTRACE("CREATE_MOUNT_POINT: [%x] [%S][%x]", point->DeviceNameLength, (buf + point->DeviceNameOffset), wcslen(buf + point->DeviceNameOffset));

	DumpMemory((PVOID)buf, 64);

	ntStatus = DrvDeviceIOControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_CREATE_POINT, point,
	point->DeviceNameOffset + point->DeviceNameLength, 0, 0);

	DTRACE("IOCTL_MOUNTMGR_CREATE_POINT returned %X", ntStatus);
#endif

	return ntStatus;
}


NTSTATUS MountManagerUnMount (WCHAR *DosName)
{
	NTSTATUS ntStatus; 
	char buf[256], out[300];
	PMOUNTMGR_MOUNT_POINT in = (PMOUNTMGR_MOUNT_POINT) buf;

	memset (buf, 0, sizeof buf);

	wcscpy((PWSTR) &in[1], DosName);

	in->SymbolicLinkNameOffset = sizeof (MOUNTMGR_MOUNT_POINT);
	in->SymbolicLinkNameLength = (USHORT) wcslen ((PWCHAR) &in[1]) * 2;

	ntStatus = DrvDeviceIOControl (MOUNTMGR_DEVICE_NAME, IOCTL_MOUNTMGR_DELETE_POINTS,
		in, sizeof(MOUNTMGR_MOUNT_POINT) + in->SymbolicLinkNameLength, out, sizeof out);

	DTRACE("MountManagerUnMount returned %X", ntStatus);

	return ntStatus;
}



NTSTATUS DrvFsctl (PFILE_OBJECT fileObject, LONG IoControlCode,
					  void *InputBuffer, int InputBufferSize, void *OutputBuffer, int OutputBufferSize)
{
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	PIRP irp;
	KEVENT event;
	PIO_STACK_LOCATION stack;
	PDEVICE_OBJECT deviceObject = IoGetRelatedDeviceObject (fileObject);

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest (IoControlCode,
		deviceObject,
		InputBuffer, InputBufferSize,
		OutputBuffer, OutputBufferSize,
		FALSE,
		&event,
		&ioStatusBlock);

	if (irp == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	stack = IoGetNextIrpStackLocation(irp);

	stack->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
	stack->MinorFunction = IRP_MN_USER_FS_REQUEST;
	stack->FileObject = fileObject;

	ntStatus = IoCallDriver (deviceObject, irp);
	if (ntStatus == STATUS_PENDING)
	{
		KeWaitForSingleObject (&event, Executive, KernelMode, FALSE, NULL);
		ntStatus = ioStatusBlock.Status;
	}

	return ntStatus;
}

// Opens a mounted volume on filesystem level
NTSTATUS DrvOpenFsVolume (WCHAR *volumeName, PHANDLE volumeHandle, PFILE_OBJECT * fileObject)
{
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fullFileName;
	IO_STATUS_BLOCK ioStatus;

	RtlInitUnicodeString (&fullFileName, volumeName);
	InitializeObjectAttributes (&objectAttributes, &fullFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = ZwCreateFile (volumeHandle,
		SYNCHRONIZE | GENERIC_READ,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS (ntStatus))
		return ntStatus;

	ntStatus = ObReferenceObjectByHandle (*volumeHandle, FILE_READ_DATA, NULL, KernelMode, fileObject, NULL);

	if (!NT_SUCCESS (ntStatus)) {
		ZwClose(*volumeHandle);
		return ntStatus;
	}

	return ntStatus;
}


NTSTATUS HookFunc(IN PDEVICE_OBJECT dobj, IN PIRP Irp)
{
	PVOID Buf;
	ULONG BufLen; //Buffer length for user provided buffer

	PIO_STACK_LOCATION currIrp;
	DispFunc_t pDispFunc;

	currIrp = IoGetCurrentIrpStackLocation(Irp);

	if (Irp->Flags & 0x80000000) {
		Irp->Flags &= (~0x80000000);
		IoSkipCurrentIrpStackLocation(Irp);	
		// manda l'IRP al device sotto a deepfreeze (che e' il disco fisico)
		return IoCallDriver(IoGetLowerDeviceObject(dobj), Irp);
	}
	if (currIrp->MajorFunction > IRP_MJ_MAXIMUM_FUNCTION) {
		DTRACE("OOOPPSS MajorFunction greater than IRP_MJ_MAXIMUM_FUNCTION !!!");
		return STATUS_UNSUCCESSFUL;
	}

	pDispFunc = (DispFunc_t) saved_major[currIrp->MajorFunction];

	return pDispFunc(dobj, Irp);
}


NTSTATUS FindAvailDriveLetter(WCHAR *letter)
{
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING objectName;
	WCHAR link[128];
	HANDLE handle;

	for (*letter = L'Z'; *letter > L'A'; (*letter)--) {		
		DTRACE("Trying drive %c", *letter);
		swprintf(link, mdev_mask, *letter);
		RtlInitUnicodeString (&objectName, link);
		InitializeObjectAttributes (&objectAttributes, &objectName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		if (NT_SUCCESS (ZwOpenSymbolicLinkObject (&handle, GENERIC_READ, &objectAttributes))) {
			ZwClose (handle);
			continue;
		}

		DTRACE("Letter found: %c", *letter);
		return STATUS_SUCCESS;
	}

	// special value if not found
	*letter = L'!';
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS CreateMountPoint(IN PDRIVER_OBJECT dobj, WCHAR freezedletter, WCHAR *thawedletter)
{
	NTSTATUS ntStatus;
	PDRIVER_OBJECT  pDiskObject;
	PDEVICE_OBJECT  pDevice;
	UNICODE_STRING	deviceName, symLink;
	UNICODE_STRING  driver_name;
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	PDEVICE_OBJECT pDevicePtr;
	PFILE_OBJECT pFileObj;
	WCHAR freezed_link[64];
	WCHAR thawedletter_tmp;
	int i;

	// special case when failed
	*thawedletter = L'!'; 

	if (mounted)
		return STATUS_UNSUCCESSFUL;

	/************************************************************************/
	/* CERCA UNA LETTERA DISPONIBILE per thawedletter                       */
	/************************************************************************/
	if (FindAvailDriveLetter(&thawedletter_tmp) != STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	swprintf(mdev_link, mdev_mask, thawedletter_tmp);
	RtlInitUnicodeString (&symLink, mdev_link);

	/************************************************************************/
	/* CERCA IL VOLUME DATA LA LETTERA freezedletter                        */
	/************************************************************************/

	swprintf(freezed_link, mdev_mask, freezedletter);
	RtlInitUnicodeString(&driver_name, freezed_link);
	InitializeObjectAttributes (&objAttr, &driver_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	freezed_device = NULL;

	ntStatus = ZwCreateFile(&hFile, SYNCHRONIZE | FILE_ANY_ACCESS, &objAttr, &ioStatus, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0);
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = ObReferenceObjectByHandle(hFile, FILE_READ_DATA, NULL, KernelMode, &pFileObj, NULL);
		if (NT_SUCCESS(ntStatus)) {
			pDevicePtr = IoGetRelatedDeviceObject(pFileObj);
			while (pDevicePtr) {
				pDevicePtr = IoGetLowerDeviceObject(pDevicePtr);
				if (pDevicePtr != NULL)
					freezed_device = pDevicePtr;
			}
			ObDereferenceObject(pFileObj);
		}
		ZwClose(hFile);
	}
	if (!freezed_device || freezed_device->DeviceType != FILE_DEVICE_DISK)
		return STATUS_UNSUCCESSFUL;
	
	DTRACE("freezed_device %x\n", freezed_device);

	/************************************************************************/
	/* HOOK SUL DRIVER DI DEEPFREEZ                                         */
	/************************************************************************/
	RtlInitUnicodeString(&driver_name, L"\\Driver\\DeepFrz");   
	if (ObReferenceObjectByName(&driver_name, 64, 0, 0, *IoDriverObjectType, KernelMode, 0, &pDiskObject) < 0) {
		return STATUS_UNSUCCESSFUL;
	}

	for (i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++) {
		saved_major[i] = pDiskObject->MajorFunction[i];
		if (pDiskObject->MajorFunction[i]) {
			//DTRACE("HOOKING MJ_%.2X %.8X with %.8X", i, pDiskObject->MajorFunction[i], HookFunc);
			pDiskObject->MajorFunction[i] = HookFunc;
		}
	}

	ObDereferenceObject(pDiskObject);
	pDiskObject = NULL;

	/************************************************************************/
	/* CREA IL NOSTRO DEVICE                                                */
	/************************************************************************/
	RtlInitUnicodeString(&deviceName, mdev_name);
	ntStatus = IoCreateDevice(dobj, 0, &deviceName, freezed_device->DeviceType, freezed_device->Characteristics, FALSE, &thawed_device );
	if (!NT_SUCCESS(ntStatus))
		return ntStatus;

	thawed_device->Flags &= ~DO_DEVICE_INITIALIZING;
	thawed_device->Flags |= (freezed_device->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO));
	thawed_device->StackSize += 4;		// Reduce occurrence of NO_MORE_IRP_STACK_LOCATIONS bug check caused by buggy drivers

	DTRACE("thawed_device %x\n", thawed_device);

	ntStatus = MountManagerMount(mdev_name, mdev_link);

	if (NT_SUCCESS(ntStatus)) {
		mounted = 1;
		*thawedletter = thawedletter_tmp;
	}

	ntStatus = IoCreateSymbolicLink (&symLink, &deviceName);
	DTRACE("IoCreateSymbolicLink returned %X\n", ntStatus);

	return ntStatus; 
}


NTSTATUS do_ioctl_thaw(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
	NTSTATUS ntstatus;

	// INPUT: lettera del drive freezed
	// OUTPUT: lettere del drive thawed, trovata partendo dal basso (Z:)
	if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(WCHAR) ) {
		WCHAR freezedletter = *((WCHAR *)Irp->AssociatedIrp.SystemBuffer);
		WCHAR thawedletter = L'!';
		ntstatus = CreateMountPoint(dobj->DriverObject, freezedletter, &thawedletter);
		if (ntstatus == STATUS_SUCCESS) {
			memcpy(Irp->AssociatedIrp.SystemBuffer, &thawedletter, sizeof(WCHAR));
			Irp->IoStatus.Information = sizeof(WCHAR);
		}
	}

	return ntstatus;
}


NTSTATUS do_ioctl_freeze(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
	int i;
	PDRIVER_OBJECT	pDiskObject;
	UNICODE_STRING fname_u;
	NTSTATUS ntStatus;
	HANDLE volumeHandle;
	PFILE_OBJECT volumeFileObject;
	UNICODE_STRING symLink;

	if (!mounted)
		return STATUS_UNSUCCESSFUL;

	/************************************************************************/
	/* UNHOOK DI DEEPFREEZE                                                 */
	/************************************************************************/
	RtlInitUnicodeString(&fname_u, L"\\Driver\\DeepFrz");   
	if (ObReferenceObjectByName(&fname_u, 64, 0, 0, *IoDriverObjectType, KernelMode, 0, &pDiskObject) < 0) {
		return STATUS_UNSUCCESSFUL;
	}

	for (i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++) {
		//DTRACE("DEHOOKING MJ_%.2X %.8X with %.8X", i, pDiskObject->MajorFunction[i], saved_major[i]);
		pDiskObject->MajorFunction[i] = saved_major[i];
	}
	ObDereferenceObject( pDiskObject );

	DTRACE("UnHook effettuato\n");

	/************************************************************************/
	/* UNMOUNT DI NTFS E DISTRUZIONE DEVICE                                 */
	/************************************************************************/
	ntStatus = DrvOpenFsVolume(mdev_link, &volumeHandle, &volumeFileObject);
	DTRACE("DrvOpenFsVolume returned %X", ntStatus);

	if (NT_SUCCESS (ntStatus)) {

		// Lock volume
		ntStatus = DrvFsctl (volumeFileObject, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);
		DTRACE("FSCTL_LOCK_VOLUME returned %X\n", ntStatus);

		KSleep(100);

		// Dismount volume
		for (i = 0; i < 50; ++i) {
			ntStatus = DrvFsctl(volumeFileObject, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
			DTRACE("FSCTL_DISMOUNT_VOLUME returned %X\n", ntStatus);

			if (NT_SUCCESS (ntStatus) || ntStatus == STATUS_VOLUME_DISMOUNTED)
				break;

			KSleep(100);
		}

		// UnLock volume
		ntStatus = DrvFsctl (volumeFileObject, FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0);
		DTRACE("FSCTL_UNLOCK_VOLUME returned %X\n", ntStatus);
	}

	MountManagerUnMount(mdev_link);

	RtlInitUnicodeString (&symLink, mdev_link);
	ntStatus = IoDeleteSymbolicLink (&symLink);
	DTRACE("IoDeleteSymbolicLink returned %X\n", ntStatus);

	ObDereferenceObject (volumeFileObject);
	ZwClose (volumeHandle);

	IoDeleteDevice(thawed_device);
	
	DTRACE("Dismount volume effettuato\n");

	mounted = 0;

	return STATUS_SUCCESS;
}




NTSTATUS DispatchDeepFreeze(IN PDEVICE_OBJECT dobj, IN PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irpSp;

	irpSp = IoGetCurrentIrpStackLocation (Irp);
	status = STATUS_INVALID_DEVICE_REQUEST;

	switch (irpSp->MajorFunction) {
		case IRP_MJ_DEVICE_CONTROL:
			{
				switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
					case IOCTL_MOUNTDEV_LINK_CREATED:
						{
							Irp->IoStatus.Status = STATUS_SUCCESS;
							Irp->IoStatus.Information = 0;
							IoCompleteRequest (Irp, IO_NO_INCREMENT);
							return Irp->IoStatus.Status;
						}
						break;
					case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
						{
							ULONG outLength;
							UNICODE_STRING ntUnicodeString;
							PMOUNTDEV_NAME outputBuffer = (PMOUNTDEV_NAME) Irp->AssociatedIrp.SystemBuffer;

							RtlInitUnicodeString (&ntUnicodeString, mdev_name);
							outputBuffer->NameLength = ntUnicodeString.Length;
							outLength = ntUnicodeString.Length + sizeof(USHORT);

							if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength) {
								Irp->IoStatus.Information = sizeof (MOUNTDEV_NAME); 
								Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
								IoCompleteRequest (Irp, IO_NO_INCREMENT);
								return Irp->IoStatus.Status;
							}
							RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

							Irp->IoStatus.Status = STATUS_SUCCESS;
							Irp->IoStatus.Information = outLength;
							IoCompleteRequest (Irp, IO_NO_INCREMENT);
							return Irp->IoStatus.Status;
						}
						break;
					case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
						{
							ULONG outLength;
							UNICODE_STRING ntUnicodeString;
							PMOUNTDEV_NAME outputBuffer = (PMOUNTDEV_NAME) Irp->AssociatedIrp.SystemBuffer;

							RtlInitUnicodeString (&ntUnicodeString, mdev_uniq);
							outputBuffer->NameLength = ntUnicodeString.Length;
							outLength = ntUnicodeString.Length + sizeof(USHORT);

							if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength) {
								Irp->IoStatus.Information = sizeof (MOUNTDEV_UNIQUE_ID);
								Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
								IoCompleteRequest (Irp, IO_NO_INCREMENT);
								return Irp->IoStatus.Status;
							}
							RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

							Irp->IoStatus.Status = STATUS_SUCCESS;
							Irp->IoStatus.Information = outLength;
							IoCompleteRequest (Irp, IO_NO_INCREMENT);
							return Irp->IoStatus.Status;
						}
						break;
					case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
						{
							ULONG outLength;
							UNICODE_STRING ntUnicodeString;
							PMOUNTDEV_SUGGESTED_LINK_NAME outputBuffer = (PMOUNTDEV_SUGGESTED_LINK_NAME) Irp->AssociatedIrp.SystemBuffer;

							RtlInitUnicodeString (&ntUnicodeString, mdev_link);
							outLength = FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME,Name) + ntUnicodeString.Length;
							outputBuffer->UseOnlyIfThereAreNoOtherLinks = FALSE;
							outputBuffer->NameLength = ntUnicodeString.Length;

							if(irpSp->Parameters.DeviceIoControl.OutputBufferLength < outLength)
							{
								Irp->IoStatus.Information = sizeof (MOUNTDEV_SUGGESTED_LINK_NAME);
								Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
								IoCompleteRequest (Irp, IO_NO_INCREMENT);
								return Irp->IoStatus.Status;
							}

							RtlCopyMemory ((PCHAR)outputBuffer->Name,ntUnicodeString.Buffer, ntUnicodeString.Length);

							Irp->IoStatus.Status = STATUS_SUCCESS;
							Irp->IoStatus.Information = outLength;
							IoCompleteRequest (Irp, IO_NO_INCREMENT);
							return Irp->IoStatus.Status;
						}
						break;
					case IOCTL_DISK_IS_WRITABLE:
					case IOCTL_DISK_GET_PARTITION_INFO_EX: 
					case IOCTL_DISK_GET_DRIVE_GEOMETRY: 
					case IOCTL_DISK_GET_LENGTH_INFO: 
					case IOCTL_DISK_CHECK_VERIFY:	// this is needed for FAT filesystems
						{
							IoSkipCurrentIrpStackLocation(Irp);
							status = IoCallDriver(freezed_device, Irp);					
							return status;
						}
						break;
					default:
						{
							DTRACE("UNSUPPORTED_IOCTL: %.8X", irpSp->Parameters.DeviceIoControl.IoControlCode);
							Irp->IoStatus.Status = status;
							Irp->IoStatus.Information = 0;
							IoCompleteRequest (Irp, IO_NO_INCREMENT);
							return status;
						}
				}
			}	
			break;
		case IRP_MJ_WRITE:		
		case IRP_MJ_READ:
		case IRP_MJ_FLUSH_BUFFERS:
			{
				IoSkipCurrentIrpStackLocation(Irp);			
				// mark our irp with special flag used in the HookFunc
				Irp->Flags |= 0x80000000;
				status = IoCallDriver(freezed_device, Irp);
				return status;		
			}
			break;

		case IRP_MJ_CREATE:
		case IRP_MJ_CLEANUP:
		case IRP_MJ_CLOSE:
		case IRP_MJ_SHUTDOWN:
		case IRP_MJ_PNP:
			{
				status = STATUS_SUCCESS;
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest (Irp, IO_NO_INCREMENT);
				return status;
			}
			break;
		default:
			{
				DTRACE("UNSUPPORTED_MJ: %.8X", irpSp->MajorFunction);
				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest (Irp, IO_NO_INCREMENT);
				return status;
			}
			break;
	} 
}


NTSTATUS DriverEntryDeepFreeze( IN PDRIVER_OBJECT dobj, IN PUNICODE_STRING regpath)
{
	DTRACE("DriverEntryDeepFreeze");

	return STATUS_SUCCESS;
}

void OnUnloadDeepFreeze(IN PDRIVER_OBJECT dobj)
{
	DTRACE("OnUnloadDeepFreeze");

	do_ioctl_freeze(NULL, NULL, NULL);
}