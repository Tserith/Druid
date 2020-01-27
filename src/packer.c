#include "packer.h"

char* outFile;

int main(int argc, char* argv[])
{
	long stubSize, exeSize, packedSize;
	void* stub, * exe;

	printf("[Druid] A simple polymorphic packer - Written by Tserith\n\n");

	if ((unsigned int)argc < 2)
	{
		printf("Usage: druid [INPUT PROGRAM]\n");
		printf("Accepts 64-bit Windows Executables\n");
		exit(1);
	}

	// allocate outfile name
	outFile = (char*)malloc(strlen(OUT_PREPEND) + strlen(argv[1]) + 1);
	if (!outFile) mFailure();

	strcpy(outFile, OUT_PREPEND);
	strcat(outFile, argv[1]);

	//DWORD a, b;MapFileAndCheckSumA("packed_popup.exe", &a, &b); printf("%x", b); exit(1);
	// read in stub and input executables
	stubSize = readFileRaw(STUB_FILE, &stub);
	exeSize = readFileRaw(argv[1], &exe);

	printf("[+] Read in %s and %s\n", STUB_FILE, argv[1]);

	// pack executable
	packedSize = pack(&exe, &stub, exeSize, stubSize);
	if (packedSize < stubSize)
	{
		printf("[-] An error occured while packing\n");
		exit(1);
	}

	printf("[+] Packed %s\n", argv[1]);

	// write packed executable to disk
	FILE* fd = fopen(outFile, "wb");
	if (!fd)
	{
		printf("[-] Unable to write to file: %s\n", outFile);
		exit(1);
	}
	
	fwrite(stub, 1, packedSize, fd);
	fclose(fd);

	printf("[+] Wrote packed %s binary to disk\n", outFile);

	free(outFile);
	free(stub);
	free(exe);

	return 0;
}

long readFileRaw(char* file, void** buf)
{
	long fsize;

	FILE* fd = fopen(file, "rb");
	if (!fd)
	{
		printf("[-] Unable to open file: %s\n", file);
		exit(1);
	}

	fseek(fd, 0, SEEK_END);
	fsize = ftell(fd);
	rewind(fd);

	*buf = malloc(fsize);
	if (!*buf) mFailure();

	fread(*buf, 1, fsize, fd);
	fclose(fd);

	return fsize;
}

long pack(void** exe, void** stub, size_t exeSize, size_t stubSize)
{
	BYTE key[KEY_SIZE];
	HCRYPTPROV hProv;
	ntHeader = (uint8_t*)* stub + ((IMAGE_DOS_HEADER*)* stub)->e_lfanew;
	PIMAGE_SECTION_HEADER section = (uint8_t*)ntHeader + sizeof(IMAGE_NT_HEADERS);
	PIMAGE_OPTIONAL_HEADER opHeader = &ntHeader->OptionalHeader;
	
	// generate 256-bit symmetric key
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
	if (!CryptGenRandom(hProv, KEY_SIZE, key)) return 0;
	if (!CryptReleaseContext(hProv, 0)) return 0;

	printf("[+] Generated 256-bit symmetric key\n");

	// encrypt executable
	encrypt(exe, &exeSize, key);

	printf("[+] Encryption Finished\n");
	
	uint32_t packedOffset = 0;
	uint32_t dataOffset = 0;
	uint32_t sizeIncrease = 0;
	
	// insert encrypted executable at the beginning of the stub's text section
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (packedOffset) // .text section found
		{
			// fix up pointers in later section headers
			if (section->SizeOfRawData) // not uninitiallized data
			{
				section->VirtualAddress += sizeIncrease;
				section->PointerToRawData += sizeIncrease;
			}
		}
		else if (!strcmp(section->Name, ".text"))
		{
			uint32_t sectionOffset = (uint8_t*)section - (uint8_t*)*stub;

			// calculate and add to size
			sizeIncrease = ((exeSize / opHeader->SectionAlignment) + 1) * opHeader->SectionAlignment;
			section->Misc.VirtualSize += sizeIncrease;
			section->SizeOfRawData += sizeIncrease;
			ntHeader->OptionalHeader.SizeOfImage += sizeIncrease;
			opHeader->SizeOfCode += sizeIncrease;
			opHeader->AddressOfEntryPoint += sizeIncrease;

			packedOffset = section->VirtualAddress;

			// resize stub, shift data, insert packed executable
			stubSize += sizeIncrease;
			*stub = realloc(*stub, stubSize);
			if (!*stub) mFailure();

			// recalculate section and headers
			section = (PIMAGE_SECTION_HEADER)((uint8_t*)* stub + sectionOffset);
			ntHeader = (uint8_t*)* stub + ((IMAGE_DOS_HEADER*)* stub)->e_lfanew;
			opHeader = &ntHeader->OptionalHeader;

			// insert packed executable into section and fill extra space
			memmove(
				(uint8_t*)* stub + section->PointerToRawData + sizeIncrease,
				(uint8_t*)* stub + section->PointerToRawData,
				stubSize - sizeIncrease - section->PointerToRawData
			);

			uint32_t bytesCopied = 0;
			while (bytesCopied < sizeIncrease)
			{
				uint32_t copySize = exeSize;

				if (bytesCopied + exeSize >= sizeIncrease)
					copySize = sizeIncrease - exeSize;
				
				memcpy((uint8_t*)* stub + section->PointerToRawData + bytesCopied, *exe, copySize);
				bytesCopied += copySize;
			}
		}

		if (!strcmp(section->Name, ".data"))
		{
			dataOffset = (uint32_t)((uint8_t*)section - (uint8_t*)* stub);
		}

		section++;
	}

	if (!packedOffset || !dataOffset) exit(1); // couldn't find .text and .data sections
	
	// fix table pointers
	for (int i = 0; i < 15; i++)
	{
		if (opHeader->DataDirectory[i].VirtualAddress)
		{
			opHeader->DataDirectory[i].VirtualAddress += sizeIncrease;
		}
	}
	
	// fix import virtual addresses
	section = IMAGE_FIRST_SECTION(ntHeader);
	IMAGE_DATA_DIRECTORY itable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD itableOffset = offset(itable.VirtualAddress, section);
	if (itable.Size)
	{
		for (PIMAGE_IMPORT_DESCRIPTOR i = (uint8_t*)* stub + itableOffset; i->Name; i++)
		{
			i->Characteristics += sizeIncrease;
			i->Name += sizeIncrease;
			i->FirstThunk += sizeIncrease;

			// 64 bit
			for (uint64_t* j = (uint8_t*)* stub + offset(i->Characteristics, section); *j; j++)
			{
				if (!(*j & 0x8000000000000000)) // if not importing by ordinal
				{
					*j += sizeIncrease;
				}
			}
		}
	}

	// fix relocation virtual addresses
	IMAGE_DATA_DIRECTORY rtable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uint16_t rtableOffset = offset(rtable.VirtualAddress, section);
	uint64_t rtableEnd = (uint8_t*)* stub + rtableOffset + rtable.Size;
	if (rtable.Size)
	{
		for (PIMAGE_BASE_RELOCATION i = (uint8_t*)* stub + rtableOffset; i < rtableEnd; (uint8_t*)i += i->SizeOfBlock)
		{
			i->VirtualAddress += sizeIncrease;
			
			uint16_t* reloc = (uint8_t*)i + sizeof(IMAGE_BASE_RELOCATION);

			for (uint16_t* j = reloc; j < reloc + i->SizeOfBlock; j++)
			{
				uint16_t relocOffset = offset(i->VirtualAddress + (*j & 0xFFF), section);

				if ((*j >> 12 == IMAGE_REL_BASED_HIGHLOW))
				{
					*(uint32_t*)((uint8_t*)* stub + relocOffset) += sizeIncrease;
				}
				else if (*j >> 12 == IMAGE_REL_BASED_DIR64)
				{
					*(uint64_t*)((uint8_t*)* stub + relocOffset) += sizeIncrease;
				}
			}
		}
	}

	// fix exception virtual addresses
	IMAGE_DATA_DIRECTORY etable = opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	uint16_t etableOffset = offset(etable.VirtualAddress, section);
	uint64_t etableEnd = (uint8_t*)* stub + etableOffset + etable.Size;
	if (etable.Size)
	{
		for (PIMAGE_RUNTIME_FUNCTION_ENTRY i = (uint8_t*)* stub + etableOffset; i < etableEnd; i++)
		{
			i->UnwindInfoAddress += sizeIncrease;
		}
	}

	// store key, exe ptr, and size in stub for decryption
	section = (PIMAGE_SECTION_HEADER)((uint8_t*)* stub + dataOffset);

	memcpy((uint8_t*)* stub + section->PointerToRawData, key, KEY_SIZE);
	*(void**)((uint8_t*)* stub + section->PointerToRawData + KEY_SIZE)= opHeader->ImageBase + packedOffset;
	*(size_t*)((uint8_t*)* stub + section->PointerToRawData + KEY_SIZE + sizeof(void*)) = exeSize;

	// write stub to disk
	FILE* fd = fopen(outFile, "wb");
	if (!fd)
	{
		printf("[-] Unable to write to file: %s\n", outFile);
		exit(1);
	}

	fwrite(*stub, 1, stubSize, fd);
	fclose(fd);

	// calculate checksum
	DWORD oldChecksum;
	BOOL result = MapFileAndCheckSumA(outFile, &oldChecksum, &ntHeader->OptionalHeader.CheckSum);
	if (result)
	{
		printf("[-] Unable to calculate checksum of stub\n");
		exit(1);
	}

	return (long)stubSize;
}

void encrypt(void** buf, size_t* bufSize, BYTE* key)
{
	void* encrypted_buf;
	chacha20_ctx ctx;
	uint8_t padSize = (16 - (*bufSize % 16)) % 16;

	chacha20_setup(&ctx, key, KEY_SIZE, key); // confidentiality is not a priority

	if (padSize)
	{
		// pad buffer
		*buf = realloc(*buf, *bufSize + padSize);
		if (!*buf) mFailure();

		memset((uint8_t*)*buf + *bufSize, 0, padSize);
		*bufSize += padSize;

		printf("[+] Padded with %d bytes\n", padSize);
	}

	encrypted_buf = malloc(*bufSize);

	chacha20_encrypt(&ctx, *buf, encrypted_buf, *bufSize);

	free(*buf);
	*buf = encrypted_buf;
}

void mFailure()
{
	printf("[-] Out of memory\n");
	exit(1);
}