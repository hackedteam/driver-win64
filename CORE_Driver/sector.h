#ifndef  __SECTORIO_H__
#define  __SECTORIO_H__

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

__declspec(dllimport) PDEVICE_OBJECT  IoGetLowerDeviceObject( PDEVICE_OBJECT  ); 

__declspec(dllimport) NTSTATUS ObReferenceObjectByName(
        PUNICODE_STRING, 
        DWORD, 
        PACCESS_STATE, 
        ACCESS_MASK,
        POBJECT_TYPE,
        KPROCESSOR_MODE,
        PVOID,
        PVOID *Object);

__declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;

__declspec(dllimport)
NTSTATUS
ObQueryNameString(
        PVOID,
        POBJECT_NAME_INFORMATION,
        ULONG Length,
        PULONG ReturnLength
        );

#pragma pack (push, 1)

typedef struct _DISK_OBJ {
	LIST_ENTRY					list;
	BOOLEAN						bIsRawDiskObj;
	BOOLEAN						bGeometryFound;
	DWORD						dwDiskOrdinal;	// If bIsRawDiskObj = TRUE Disk Number is Raw Disk Number else it is Partition Number
	ULONG						ulSectorSize;	// Sector Size on disk
	PDEVICE_OBJECT				pDiskDevObj;	// Pointer to Device Object
} DISK_OBJ, * PDISK_OBJ;

typedef struct _DISK_LOCATION {
	BOOLEAN						bIsRawDiskObj;
	DWORD						dwDiskOrdinal;
	ULONGLONG					ullSectorNum;
} DISK_LOCATION, * PDISK_LOCATION;

typedef struct _DEVICE_EXTENSION {
    LIST_ENTRY                  list_head;
    KSPIN_LOCK                  list_lock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#pragma pack (pop)

#define SECTOR_IO_DEVICE       0x8000

#define IOCTL_SECTOR_READ		CTL_CODE(SECTOR_IO_DEVICE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SECTOR_WRITE		CTL_CODE(SECTOR_IO_DEVICE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_GET_SECTOR_SIZE	CTL_CODE(SECTOR_IO_DEVICE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    );

NTSTATUS DriverDefaultIrpHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

NTSTATUS DriverIoDeviceDispatchRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

NTSTATUS GetAllDiskObjects();
NTSTATUS GetGeometry(PDEVICE_OBJECT pDiskDevObj, PDISK_GEOMETRY pDiskGeo);

VOID DriverUnload(
    IN PDRIVER_OBJECT DriverObject
    );


#endif   /* ----- #ifndef __SECTORIO_H__ ----- */