/* compat.c - High Memory for Windows CE
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

#include "himemce.h"

struct _PEB _peb;

size_t
pread (HANDLE handle, char *buffer, size_t len, off_t offset)
{
  DWORD out = -1;
  if (SetFilePointer (handle, offset, NULL, SEEK_SET) == -1)
    return -1;
  if (!ReadFile (handle, buffer, len, &out, NULL))
    return -1;
  return out;
}


int get_prot_flags (int vprot)
{
  int rwx = vprot & (VPROT_READ | VPROT_WRITE | VPROT_WRITECOPY | VPROT_EXEC);
  int res = 0;

  switch(rwx)
    {
    case VPROT_READ:
      res = PAGE_READONLY;
      break;
    case VPROT_READ | VPROT_WRITE:
      res = PAGE_READWRITE;
      break;
    case VPROT_READ | VPROT_WRITECOPY:
      // res = PAGE_WRITECOPY;
      res = PAGE_READWRITE;
      break;
    case VPROT_EXEC:
      res = PAGE_EXECUTE;
      break;
    case VPROT_EXEC | VPROT_READ:
      res = PAGE_EXECUTE_READ;
      break;
    case VPROT_EXEC | VPROT_READ | VPROT_WRITE:
      res = PAGE_EXECUTE_READWRITE;
      break;
    case VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY:
      // res = PAGE_EXECUTE_WRITECOPY;
      res = PAGE_EXECUTE_READWRITE;
      break;
    default:
      res = PAGE_NOACCESS;
    }
  if (vprot & VPROT_GUARD) res |= PAGE_GUARD;
  if (vprot & VPROT_NOCACHE) res |= PAGE_NOCACHE;
  return res;
}
