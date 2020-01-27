#include <windows.h>
#include <winternl.h>
#include "chacha20.h"
#include <intrin.h>

#define KEY_SIZE 32 // bytes

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