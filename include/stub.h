#include <windows.h>
#include <winternl.h>
#include "chacha20.h"
#include <intrin.h>

#define KEY_SIZE 32 // bytes

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONGLONG BaseAddress;
	ULONGLONG EntryPoint;
	DWORD64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY64 HashTableEntry;
	ULONGLONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

PIMAGE_NT_HEADERS ntHeader;

// converts rva to file offset
DWORD offset(DWORD rva, PIMAGE_SECTION_HEADER section)
{
	if (!rva) return 0;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (rva >= section->VirtualAddress &&
			rva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			break;
		}

		section++;
	}
	return rva - section->VirtualAddress + section->PointerToRawData;
}