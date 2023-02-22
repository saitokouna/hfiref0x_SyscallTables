/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2023
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        20 Feb 2023
*
*  Ntdll/Win32u/Iumdll Syscall dumper
*  Based on gr8 scg project
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 4091) //'typedef ': ignored on left of '' when no variable is declared

#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include "ntos.h"
#include "minirtl\cmdline.h"
#include "minirtl\minirtl.h"

#pragma comment(lib, "version.lib")

#if defined _M_X64
#include "hde/hde64.h"
#elif defined _M_IX86
#include "hde/hde32.h"
#elif
#error Unknown architecture, check build configuration
#endif

typedef enum tagScgDllType {
    ScgNtDll = 0,
    ScgWin32u,
    ScgIumDll,
    ScgUnknown
} ScgDllType;

typedef struct _LANGANDCODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} LANGANDCODEPAGE, * LPTRANSLATE;

/*
* LdrMapInputFile
*
* Purpose:
*
* Create mapped section from input file.
*
*/
PVOID LdrMapInputFile(
    _In_ LPCWSTR lpFileName
)
{
    HANDLE hFile, hMapping;
    PVOID  pvImageBase = NULL;

    hFile = CreateFile(lpFileName,
        GENERIC_READ,
        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {

        hMapping = CreateFileMapping(hFile,
            NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL);

        if (hMapping != NULL) {

            pvImageBase = MapViewOfFile(hMapping,
                FILE_MAP_READ, 0, 0, 0);

            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    return pvImageBase;
}

/*
* GetDllType
*
* Purpose:
*
* Parse dll version and check it against known values to determine dll type.
*
*/
ScgDllType GetDllType(
    _In_ LPCWSTR lpFileName)
{
    DWORD dwSize;
    DWORD dwHandle;
    PVOID vinfo = NULL;
    LPTRANSLATE lpTranslate = NULL;
    LPWSTR lpOriginalFileName;
    WCHAR szKey[100 + 1];

    ScgDllType dllType = ScgUnknown;

    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {

                dwSize = 0;
                if (VerQueryValue(vinfo,
                    L"\\VarFileInfo\\Translation",
                    (LPVOID*)&lpTranslate,
                    (PUINT)&dwSize))
                {
                    RtlFillMemory(&szKey, sizeof(szKey), 0);

                    StringCchPrintf(szKey,
                        RTL_NUMBER_OF(szKey),
                        TEXT("\\StringFileInfo\\%04x%04x\\InternalName"),
                        lpTranslate[0].wLanguage,
                        lpTranslate[0].wCodePage);

                    if (VerQueryValue(vinfo, szKey, (LPVOID*)&lpOriginalFileName, (PUINT)&dwSize)) {

                        if (_strcmpi(lpOriginalFileName, L"IumDll.dll") == 0) {
                            dllType = ScgIumDll;
                        }
                        else if (_strcmpi(lpOriginalFileName, L"Ntdll.dll") == 0) {
                            dllType = ScgNtDll;
                        }
                        else if (_strcmpi(lpOriginalFileName, L"win32u") == 0)
                        {
                            dllType = ScgWin32u;
                        }

                    }
                }
            }
            LocalFree(vinfo);
        }
    }

    return dllType;
}

VOID ProcessExportEntry(
    _In_ ULONG EntryIndex,
    _In_ PVOID ImageBase,
    _In_ PULONG FunctionsTableBase,
    _In_ PUSHORT NameOrdinalTableBase,
    _In_ PCHAR FunctionName,
    _In_ ScgDllType DllType
)
{
    SIZE_T FunctionNameLength;
    DWORD sid;
    PBYTE ptrCode;
    ULONG i, max;

    USHORT targetUShort;

#if defined _M_X64
    hde64s hs;
#elif defined _M_IX86
    hde32s hs;
#endif

    if (DllType == ScgIumDll)
        targetUShort = 'uI';
    else
        targetUShort = 'tN';

    if (*(USHORT*)FunctionName == targetUShort) {

        FunctionNameLength = _strlen_a(FunctionName);
        if (FunctionNameLength <= MAX_PATH) {
            
            sid = (DWORD)-1;
            ptrCode = (PBYTE)RtlOffsetToPointer(ImageBase, FunctionsTableBase[NameOrdinalTableBase[EntryIndex]]);
            i = 0;
#if defined _M_X64
            max = 32;
#elif defined _M_IX86
            max = 16;
#endif

            do {
#if defined _M_X64
                hde64_disasm(RtlOffsetToPointer(ptrCode, i), &hs);
#elif defined _M_IX86
                hde32_disasm(RtlOffsetToPointer(ptrCode, i), &hs);
#endif
                if (hs.flags & F_ERROR) {
                    DbgPrint("scg: disassembly error\r\n");
                    break;
                }
                else {

                    if (hs.len == 5) {
                        if (ptrCode[i] == 0xE9)
                            break;

                        if (ptrCode[i] == 0xB8) {
                            sid = *(ULONG*)(ptrCode + i + 1);
                            break;
                        }
                    }

                }

                i += hs.len;

            } while (i < max);

            if (sid != (DWORD)-1) {
                printf_s("%s\t%lu\n", FunctionName, sid);
            }
            else {
                DbgPrint("scg: syscall index for %s not found\r\n", FunctionName);
            }
        }
        else {
            DbgPrint("scg: Unexpected function name length %zu\r\n", FunctionNameLength);
        }
    }
}

/*
* ParseInputFile
*
* Purpose:
*
* Generate syscall list from given dll.
*
*/
VOID ParseInputFile(
    _In_ LPCWSTR lpFileName)
{
    PIMAGE_FILE_HEADER FileHeader;

    union {
        PIMAGE_OPTIONAL_HEADER32 oh32;
        PIMAGE_OPTIONAL_HEADER64 oh64;
    } oh;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

    PULONG NameTableBase;
    PULONG FunctionsTableBase;
    PUSHORT NameOrdinalTableBase;

    PCHAR pvImageBase;
    ULONG entryIndex;

    ScgDllType dllType = GetDllType(lpFileName);

    if (dllType == ScgUnknown) {
        printf_s("scg: unknown or corrupted dll, must be ntdll/win32u/iumdll\r\n");
        return;
    }

    pvImageBase = LdrMapInputFile(lpFileName);
    if (pvImageBase == NULL) {
        printf_s("scg: cannot load input file, GetLastError %lu\r\n", GetLastError());
        return;
    }

    __try {

        FileHeader = (PIMAGE_FILE_HEADER)RtlOffsetToPointer(pvImageBase,
            ((PIMAGE_DOS_HEADER)pvImageBase)->e_lfanew + sizeof(DWORD));

        switch (FileHeader->Machine) {

        case IMAGE_FILE_MACHINE_I386:

#ifdef _M_X64
            printf_s("scg: 32-bit machine image\r\nscg: use x86-32 version of scg to process this file\r\n");
            __leave;
#else
            oh.oh32 = (PIMAGE_OPTIONAL_HEADER32)RtlOffsetToPointer(FileHeader,
                sizeof(IMAGE_FILE_HEADER));

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pvImageBase,
                oh.oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
#endif

            break;

        case  IMAGE_FILE_MACHINE_AMD64:

#ifdef _M_IX86
            printf_s("scg: 64-bit machine image\r\nscg: use x64 version of scg to process this file\r\n");
            __leave;
#else 
            oh.oh64 = (PIMAGE_OPTIONAL_HEADER64)RtlOffsetToPointer(FileHeader,
                sizeof(IMAGE_FILE_HEADER));

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pvImageBase,
                oh.oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

#endif
            break;

        default:
            printf_s("scg: unexpected image machine type %lx\r\n", FileHeader->Machine);
            break;
        }

        if (ExportDirectory) {

            NameTableBase = (PULONG)RtlOffsetToPointer(pvImageBase, (ULONG)ExportDirectory->AddressOfNames);
            NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(pvImageBase, ExportDirectory->AddressOfNameOrdinals);
            FunctionsTableBase = (PULONG)RtlOffsetToPointer(pvImageBase, ExportDirectory->AddressOfFunctions);

            for (entryIndex = 0; entryIndex < ExportDirectory->NumberOfNames; entryIndex++) {

                ProcessExportEntry(
                    entryIndex,
                    pvImageBase,
                    FunctionsTableBase,
                    NameOrdinalTableBase,
                    RtlOffsetToPointer(pvImageBase, NameTableBase[entryIndex]),
                    dllType);

            }

        }

    }
    __finally {
        UnmapViewOfFile(pvImageBase);
        if (AbnormalTermination()) {
            printf_s("Unexpected exception occurred\r\n");
        }
    }
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
int main()
{
    ULONG paramLength = 0;
    WCHAR szInputFile[MAX_PATH + 1];
    PVOID pvEnable = (PVOID)1;

    HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, &pvEnable, sizeof(pvEnable));

    RtlSecureZeroMemory(szInputFile, sizeof(szInputFile));
    GetCommandLineParam(GetCommandLine(), 1, szInputFile, MAX_PATH, &paramLength);
    if (paramLength > 0) {
        ParseInputFile((LPCWSTR)szInputFile);
    }
    else {
        printf_s("Syscall Generator (NTOS/WIN32K/IUM)\r\nSupports ntdll/win32u/iumdll dlls as targets\r\nUsage: scg filename\r\n");
#ifdef _M_X64
        printf_s("win64 release");
#elif _M_IX86
        printf_s("win32 release");
#elif
        printf_s("unsupported architecture");
        return;
#endif
    }

    return 0;
}
