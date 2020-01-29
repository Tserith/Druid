#pragma once
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "stub.h"

#define STUB_FILE "stub.exe"
#define OUT_PREPEND "packed_"

long readFileRaw(char* file, void** buf);
long pack(void** exe, void** stub, size_t exeSize, size_t stubSize);
void encrypt(void** buf, size_t* bufSize, BYTE* key);
void mFailure();

extern MapFileAndCheckSumA();