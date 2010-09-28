/* From wine1.2-1.1.42/dlls/kernel32/module.c  */

/*
 * Modules
 *
 * Copyright 1995 Alexandre Julliard
 * Copyright 2010 g10 Code GmbH
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


#include "wine.h"
#include "kernel32_kernel_private.h"


void MODULE_get_binary_info (HANDLE hfile, struct binary_info *info)
{
  union
  {
    IMAGE_DOS_HEADER mz;
  } header;
  
  DWORD len;

  memset( info, 0, sizeof(*info) );
  /* Seek to the start of the file and read the header information. */
  if (SetFilePointer( hfile, 0, NULL, SEEK_SET ) == -1) return;
  if (!ReadFile( hfile, &header, sizeof(header), &len, NULL ) || len != sizeof(header)) return;
  
  if (header.mz.e_magic == IMAGE_DOS_SIGNATURE)
    {
      union
      {
	IMAGE_OS2_HEADER os2;
	IMAGE_NT_HEADERS32 nt;
      } ext_header;
      
      /* We do have a DOS image so we will now try to seek into
       * the file by the amount indicated by the field
       * "Offset to extended header" and read in the
       * "magic" field information at that location.
       * This will tell us if there is more header information
       * to read or not.
       */
      info->type = BINARY_DOS;
      if (SetFilePointer( hfile, header.mz.e_lfanew, NULL, SEEK_SET ) == -1) return;
      if (!ReadFile( hfile, &ext_header, sizeof(ext_header), &len, NULL ) || len < 4) return;
      
      /* Reading the magic field succeeded so
       * we will try to determine what type it is.
       */
      if (!memcmp( &ext_header.nt.Signature, "PE\0\0", 4 ))
        {
	  if (len >= sizeof(ext_header.nt.FileHeader))
            {
	      info->type = BINARY_PE;
	      if (ext_header.nt.FileHeader.Characteristics & IMAGE_FILE_DLL)
		info->flags |= BINARY_FLAG_DLL;
	      if (len < sizeof(ext_header.nt))  /* clear remaining part of header if missing */
		memset( (char *)&ext_header.nt + len, 0, sizeof(ext_header.nt) - len );
	      switch (ext_header.nt.OptionalHeader.Magic)
                {
                case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		  info->res_start = (void *)(ULONG_PTR)ext_header.nt.OptionalHeader.ImageBase;
		  info->res_end = (void *)((ULONG_PTR)ext_header.nt.OptionalHeader.ImageBase +
					   ext_header.nt.OptionalHeader.SizeOfImage);
		  break;
                case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		  info->flags |= BINARY_FLAG_64BIT;
		  break;
                } 

	      info->machine = ext_header.nt.FileHeader.Machine;
           }
        }
    }
}


static HMODULE load_library( LPCWSTR libname, DWORD flags )
{
  NTSTATUS nts;
  HMODULE hModule;

  /* We don't use any special DLL load path.  */

  if (flags & LOAD_LIBRARY_AS_DATAFILE)
    {
      SetLastError(ERROR_INVALID_PARAMETER);
      return NULL;
    }

  nts = MyLdrLoadDll( NULL, flags, libname, &hModule );
  if (nts != STATUS_SUCCESS)
    {
      hModule = 0;
      SetLastError( MyRtlNtStatusToDosError( nts ) );
    }
  return hModule;
}


HMODULE MyLoadLibraryExW(LPCWSTR libnameW, HANDLE hfile, DWORD flags)
{
/* We would like to use the native LoadLibraryEx, but on Windows CE
   that is only implemented for DLLs.  Also, base addresses are
   restricted to the process slot, but we want to load at high
   addresses.  */
  TRACE ("MyLoadLibraryExW (\"%S\", 0x%p, 0x%x)\n", libnameW, hfile, flags);
  if (!libnameW)
    {
      SetLastError(ERROR_INVALID_PARAMETER);
      return 0;
    }
  return load_library( libnameW, flags );
}
