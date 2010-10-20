/* From wine1.2-1.1.42/dlls/kernel32/process.c  */

/*
 * Win32 processes
 *
 * Copyright 1996, 1998 Alexandre Julliard
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

#include <windef.h>
#include "wine.h"
#include "kernel32_kernel_private.h"


typedef int (APIENTRY *ENTRY_POINT) (HINSTANCE hInstance,
				     HINSTANCE hPrevInstance,
				     LPWSTR lpCmdLine, int nCmdShow);

static BOOL start_process( PEB *peb )
{
  IMAGE_NT_HEADERS *nt;
  ENTRY_POINT entry;
  
  nt = MyRtlImageNtHeader( peb->ImageBaseAddress );
  entry = (ENTRY_POINT)((char *)peb->ImageBaseAddress +
			nt->OptionalHeader.AddressOfEntryPoint);
  
  if (!nt->OptionalHeader.AddressOfEntryPoint)
    {
      ERR( "%S doesn't have an entry point, it cannot be executed\n",
	     peb->ImagePathName );
      SetLastError (ERROR_BAD_EXE_FORMAT);
      return FALSE;
    }

  TRACE( "Starting process %S (entryproc=%p)\n",
	 peb->ImagePathName, entry );

  SetLastError( 0 );  /* clear error code */
  peb->ExitStatus = entry (GetModuleHandle (NULL), NULL, peb->CommandLine, 0);

  return 0;
}


static BOOL __wine_kernel_init (HANDLE hFile, LPCWSTR main_exe_name,
				LPWSTR cmd_line, int *exit_code)
{
  PEB *peb = current_peb();

  peb->CommandLine = cmd_line;
  peb->ImageBaseAddress = MyLoadLibraryExW( main_exe_name, 0,
					    DONT_RESOLVE_DLL_REFERENCES );

  if (! peb->ImageBaseAddress)
    {
      ERR ("can not load %S: %i\n", main_exe_name, GetLastError());
      return FALSE;
    }

  /* FIXME: Error checking?  */
  MyLdrInitializeThunk( start_process, 0, 0, 0 );

  *exit_code = peb->ExitStatus;
  return TRUE;
}


static HANDLE open_exe_file (LPCWSTR name, struct binary_info *binary_info)
{
  HANDLE handle;
  
  handle = CreateFileForMappingW( name, GENERIC_READ, FILE_SHARE_READ,
				  NULL, OPEN_EXISTING, 0, 0 );
  if (handle != INVALID_HANDLE_VALUE)
    MODULE_get_binary_info( handle, binary_info );
  
  return handle;
}


BOOL MyCreateProcessW (LPCWSTR app_name, LPWSTR cmd_line,
		       int *exit_code)
{
  BOOL retv = FALSE;
  HANDLE hFile = 0;
  struct binary_info binary_info;
  
  hFile = open_exe_file (app_name, &binary_info);
  if (hFile == INVALID_HANDLE_VALUE)
    {
      ERR ("could not open file %S: %i\n", app_name, GetLastError());
      goto err;
    }
  
  TRACE ("MyCreateProcessW: 0x%p type=0x%x flags=0x%x "
	 "res_start=0x%p res_end=0x%p\n",
	 hFile, binary_info.type, binary_info.flags,
	 binary_info.res_start, binary_info.res_end);

  /* Some sanity checks.  */
  if (binary_info.flags & BINARY_FLAG_DLL)
    {
      ERR ("not starting %S since it is a DLL\n", app_name);
      SetLastError( ERROR_BAD_EXE_FORMAT );
      goto err;
    }

  if (binary_info.flags & BINARY_FLAG_64BIT)
    {
      ERR( "starting 64-bit process %S not supported on this platform\n",
	   app_name);
      SetLastError( ERROR_BAD_EXE_FORMAT );
      return FALSE;
    }

  if (binary_info.type != BINARY_PE)
    {
      ERR ("not starting %S of type %i (expected %i)\n", app_name,
	   binary_info.type, BINARY_PE);
      SetLastError( ERROR_BAD_EXE_FORMAT );
      return FALSE;
    }

  retv = __wine_kernel_init (hFile, app_name, cmd_line, exit_code);

 err:
  if (hFile)
    CloseHandle( hFile );
  
  return retv;
}

