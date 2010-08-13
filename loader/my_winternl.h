/* From wine1.2-1.1.42/include/winternl.h  */

/*
 * Internal NT APIs and data structures
 *
 * Copyright (C) the Wine project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_WINTERNL_H
#define __WINE_WINTERNL_H

#include <windows.h>


typedef struct _PEB
{
  HMODULE ImageBaseAddress;

  wchar_t *ImagePathName;
  wchar_t *CommandLine;

  /* The exit code after completion of the executed image.  */
  int ExitStatus;
} PEB, *PPEB;


typedef enum _SECTION_INHERIT {
  ViewShare = 1,
  ViewUnmap = 2
} SECTION_INHERIT;


#define NtCurrentProcess() ((HANDLE)-1)

typedef struct _LDR_MODULE
{
#if 0
  LIST_ENTRY          InLoadOrderModuleList;
  LIST_ENTRY          InMemoryOrderModuleList;
  LIST_ENTRY          InInitializationOrderModuleList;
#endif
  void*               BaseAddress;
  void*               EntryPoint;
  ULONG               SizeOfImage;
  wchar_t             FullDllName[MAX_PATH];
  wchar_t             BaseDllName[MAX_PATH];
  ULONG               Flags;
  SHORT               LoadCount;
  SHORT               TlsIndex;
  HANDLE              SectionHandle;
  ULONG               CheckSum;
  ULONG               TimeDateStamp;
  HANDLE              ActivationContext;
} LDR_MODULE, *PLDR_MODULE;

/* those defines are (some of the) regular LDR_MODULE.Flags values */
#define LDR_IMAGE_IS_DLL                0x00000004
#define LDR_LOAD_IN_PROGRESS            0x00001000
#define LDR_UNLOAD_IN_PROGRESS          0x00002000
#define LDR_NO_DLL_CALLS                0x00040000
#define LDR_PROCESS_ATTACHED            0x00080000
#define LDR_MODULE_REBASED              0x00200000

/* these ones is Wine specific */
#define LDR_DONT_RESOLVE_REFS           0x40000000
#define LDR_WINE_INTERNAL               0x80000000

#endif  /* __WINE_WINTERNL_H */
