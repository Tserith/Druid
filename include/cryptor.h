#pragma once
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "stub.h"

#define STUB_FILE "stub.exe"
#define STUB_FILE_DLL "stub.dll"
#define OUT_PREPEND "druid_"

long readFileRaw(char* file, void** buf);
long pack(void** exe, void** stub, size_t exeSize, size_t stubSize);
void encrypt(void** buf, size_t* bufSize, BYTE* key);
void mFailure();