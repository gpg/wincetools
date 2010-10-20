/* himemce.h - High Memory for Windows CE interfaces
   Copyright (C) 2010 g10 Code GmbH
   Written by Marcus Brinkmann <marcus@g10code.com>

   This file is part of HiMemCE.
 
   HiMemCE is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
   
   HiMemCE is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef HIMEMCE_H
#define HIMEMCE_H

#include <windows.h>

#include "my_winternl.h"
#include "server_protocol.h"


/* Global options.  */

extern int verbose;


/* Debugging output.  FIXME: For now... */
#define TRACE printf

#define ERR printf


/* Support for the wine code.  */
extern struct _PEB _peb;
#define current_peb() (&_peb)

#define OBJECT_ATTRIBUTES void

typedef int off_t;

/* compat.c */
size_t pread(HANDLE handle, char *buffer, size_t len, off_t offset);

int get_prot_flags (int vprot);


/* Exports from the wine code.  */

/* ntdll_error.c */
ULONG MyRtlNtStatusToDosError (NTSTATUS status);

/* ntdll_loader.c */
PIMAGE_NT_HEADERS MyRtlImageNtHeader (HMODULE hModule);
NTSTATUS MyLdrLoadDll (LPCWSTR path_name, DWORD flags,
		       LPCWSTR libname, HMODULE* hModule);
void MyLdrInitializeThunk( void *kernel_start, ULONG_PTR unknown2,
			   ULONG_PTR unknown3, ULONG_PTR unknown4 );
IMAGE_BASE_RELOCATION *MyLdrProcessRelocationBlock (void *page, UINT count,
						    USHORT *relocs,
						    INT_PTR delta);
PVOID MyRtlImageDirectoryEntryToData( HMODULE module, BOOL image,
				      WORD dir, ULONG *size );

/* ntdll_virtual.c */
NTSTATUS MyNtCreateSection (HANDLE *handle, ACCESS_MASK access,
			    const OBJECT_ATTRIBUTES *attr,
			    const LARGE_INTEGER *size, ULONG protect,
			    ULONG sec_flags, HANDLE file);
NTSTATUS MyNtMapViewOfSection (HANDLE handle, HANDLE process,
			       PVOID *addr_ptr, ULONG zero_bits,
			       SIZE_T commit_size,
			       const LARGE_INTEGER *offset_ptr,
			       SIZE_T *size_ptr,
			       SECTION_INHERIT inherit, ULONG alloc_type,
			       ULONG protect);

/* kernel32_module.c */
void MODULE_get_binary_info (HANDLE hfile, struct binary_info *info);
HMODULE MyLoadLibraryExW (LPCWSTR libnameW, HANDLE hfile, DWORD flags);

/* kernel32_process.c */
BOOL MyCreateProcessW (LPCWSTR app_name, LPWSTR cmd_line, int *exit_code);


#endif /* HIMEMCE_H */
