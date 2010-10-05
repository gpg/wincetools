 /* himemce-pre.c - High Memory for Windows CE (preloader)
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

#include <windows.h>
#include <assert.h>

#include "debug.h"

#include "kernel32_kernel_private.h"
#include "wine.h"
#include "himemce-map-provider.h"


# define page_mask  0xfff
# define page_shift 12
# define page_size  0x1000

#define ROUND_SIZE(size) \
  (((SIZE_T)(size) + page_mask) & ~page_mask)

#define SECTION_IS_LOW(sec) \
      (((sec)->Characteristics & IMAGE_SCN_MEM_WRITE) &&	\
       ! ((sec)->Characteristics & IMAGE_SCN_MEM_SHARED))


/* Find all modules to preload and add them to the map.  */
static int
find_modules (struct himemce_map *map)
{
  /* Five for "*.dll" and one for good luck.  */
  wchar_t dirname[MAX_PATH + 6];
  wchar_t filename[2 * MAX_PATH + 1];
  int res;
  wchar_t *end;
  int idx;
  HANDLE hSearch;
  WIN32_FIND_DATA FileData;
  BOOL bFinished = FALSE;

  res = GetModuleFileName (GetModuleHandle (NULL), dirname, MAX_PATH);
  if (! res)
    {
      ERR ("can not determine module filename: %i\n",
	     GetLastError ());
      return 0;
    }

  idx = wcslen (dirname);
  while (idx > 0 && dirname[idx - 1] != '\\' && dirname[idx - 1] != '/')
    idx--;
  dirname[idx] = '\0';

  wcscpy (filename, dirname);
  wcscpy (&dirname[idx], L"*.dll");
  end = &filename[idx];

  hSearch = FindFirstFile (dirname, &FileData);
  if (hSearch == INVALID_HANDLE_VALUE)
    {
      ERR ("no .dll files found\n");
      return 0;
    }

  while (!bFinished)
    {
      struct himemce_module *mod;
      struct binary_info info;
      HANDLE hnd;

      TRACE ("considering %S: ", FileData.cFileName);

      wcscpy (end, FileData.cFileName);

      if (FileData.cFileName[0] != L'Q')
	{
	  TRACE ("skip non-Qt library for testing\n");
	  goto skipit;
	}

      hnd = CreateFile (filename, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (hnd == INVALID_HANDLE_VALUE)
	{
	  TRACE ("skip (probe failure: %i)\n", GetLastError ());
	  goto skipit;
	}

      MODULE_get_binary_info (hnd, &info);
      CloseHandle (hnd);
      if (info.machine != IMAGE_FILE_MACHINE_THUMB)
	{
	  TRACE ("skip (machine type: %04x)\n", info.machine);
	  goto skipit;
	}

      /* FIXME: Keep a blacklist.  Maybe exclude ARM (not THUMB)
	 binaries automatically (gpgme and friends).  */

      TRACE ("accept [%2i]\n", map->nr_modules);
      mod = map_add_module (map, filename, 0);
      if (! mod)
	return 0;
      
    skipit:
      if (!FindNextFile (hSearch, &FileData))
	{
	  bFinished = TRUE;
	  
	  if (GetLastError () != ERROR_NO_MORE_FILES)
	    {
	      ERR ("unable to find next .dll file\n");
	      return 0;
	    }
	}
    }
  if (!FindClose (hSearch))
    {
      ERR ("unable to close search handle: %i\n", GetLastError ());
      return 0;
    }
  return 1;
}


static SIZE_T
section_size (IMAGE_SECTION_HEADER *sec)
{
  static const SIZE_T sector_align = 0x1ff;
  SIZE_T map_size, file_size, end;
  
  if (!sec->Misc.VirtualSize)
    map_size = ROUND_SIZE( sec->SizeOfRawData );
  else
    map_size = ROUND_SIZE( sec->Misc.VirtualSize );
  
  file_size = (sec->SizeOfRawData + (sec->PointerToRawData & sector_align) + sector_align) & ~sector_align;
  if (file_size > map_size) file_size = map_size;
  end = ROUND_SIZE( file_size );
  if (end > map_size) end = map_size;
  return end;
}


static void *
get_rva_low (char *module, size_t rva)
{
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(module + dos->e_lfanew);
  IMAGE_SECTION_HEADER *sec;
  int sec_cnt;
  int idx;

  sec = (IMAGE_SECTION_HEADER*)((char*)&nt->OptionalHeader+nt->FileHeader.SizeOfOptionalHeader);
  sec_cnt = nt->FileHeader.NumberOfSections;

  for (idx = 0; idx < sec_cnt; idx++)
    {
      if (! sec[idx].PointerToLinenumbers)
	continue;
      if (rva >= sec[idx].VirtualAddress
	  && rva < sec[idx].VirtualAddress + section_size (&sec[idx]))
		break;
    }
  if (idx == sec_cnt)
    return (void *)((char *)module + rva);
  
  return (void *)((char *)sec[idx].PointerToLinenumbers
		  + (rva - sec[idx].VirtualAddress));
}

  
static IMAGE_BASE_RELOCATION *
LowLdrProcessRelocationBlock (void *base, void *page, UINT count,
			      USHORT *relocs)
{
  char *ptr;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_SECTION_HEADER *sec;
  int sec_cnt;
  int idx;

  ptr = base;
  dos = (IMAGE_DOS_HEADER *) ptr;
  nt = (IMAGE_NT_HEADERS *) (ptr + dos->e_lfanew);
  sec = (IMAGE_SECTION_HEADER *) ((char*) &nt->OptionalHeader
				  + nt->FileHeader.SizeOfOptionalHeader);
  sec_cnt = nt->FileHeader.NumberOfSections;
  idx = sec_cnt;

  /* Small optimization: Exclude read-only sections at the start and
     end of the list.  */
  while (sec_cnt > 0 && SECTION_IS_LOW (sec))
    {
      sec++;
      sec_cnt--;
    }
  while (sec_cnt > 0 && SECTION_IS_LOW (&sec[sec_cnt - 1]))
    sec_cnt--;
  
  while (count--)
    {
      USHORT offset = *relocs & 0xfff;
      int type = *relocs >> 12;
      size_t addr;
      size_t old_addr;
      size_t off;

      switch(type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
	  goto nextreloc;
        case IMAGE_REL_BASED_HIGH:
	  addr = HIWORD (*(short *)((char *)page + offset));
	  break;
        case IMAGE_REL_BASED_LOW:
	  addr = LOWORD (*(short *)((char *)page + offset));
	  break;
        case IMAGE_REL_BASED_HIGHLOW:
	  addr = *(int *)((char *)page + offset);
	  break;
        default:
	  TRACE("Unknown/unsupported fixup type %x.\n", type);
	  goto nextreloc;
        }

      if ((void *) addr < base)
	{
	  ERR ("ignoring relocation that points below image");
	  goto nextreloc;
	}
      off = ((char *) addr) - ((char *) base);

      /* Check if ADDR points into a rw segment.  First check the
	 cached index.  */
      if (idx < sec_cnt)
	{
	  if (off >= sec[idx].VirtualAddress
	      && off < sec[idx].VirtualAddress + section_size (&sec[idx]))
	    ; /* Found it.  */
	  else
	    idx = sec_cnt;
	}
      if (idx == sec_cnt)
	{
	  for (idx = 0; idx < sec_cnt; idx++)
	    {
	      if (! sec[idx].PointerToLinenumbers)
		continue;
	      if (off >= sec[idx].VirtualAddress
		  && off < sec[idx].VirtualAddress + section_size (&sec[idx]))
		break;
	    }
	  if (idx == sec_cnt)
	    goto nextreloc;
	}
      old_addr = addr;
      addr = sec[idx].PointerToLinenumbers + (off - sec[idx].VirtualAddress);

#if 0
      TRACE ("rewriting relocation at %p to rw section from %p to %p\n",
	     ((char *)page + offset), old_addr, addr);
#endif

      switch(type)
        {
        case IMAGE_REL_BASED_HIGH:
	  *(short *)((char *)page + offset) = HIWORD(addr);
	  break;
        case IMAGE_REL_BASED_LOW:
	  *(short *)((char *)page + offset) = LOWORD(addr);
	  break;
        case IMAGE_REL_BASED_HIGHLOW:
	  *(int *)((char *)page + offset) = addr;
	  break;
        }
    nextreloc:
      relocs++;
    }
  return (IMAGE_BASE_RELOCATION *)relocs;  /* return address of next block */
}


static void
relocate_rw_sections (struct himemce_map *map, void *base)
{
  char *ptr;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  IMAGE_SECTION_HEADER *sec;
  int i;
  IMAGE_BASE_RELOCATION *rel, *end;
  const IMAGE_DATA_DIRECTORY *relocs;

  TRACE ("adjusting rw sections at %p\n", base);

  ptr = base;
  dos = (IMAGE_DOS_HEADER *) ptr;
  nt = (IMAGE_NT_HEADERS *) (ptr + dos->e_lfanew);
  sec = (IMAGE_SECTION_HEADER *) ((char*) &nt->OptionalHeader
				  + nt->FileHeader.SizeOfOptionalHeader);

  /* Go through all the sections, reserve low memory for the writable
     sections.  */
  for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
      if (SECTION_IS_LOW (sec))
	{
	  SIZE_T map_size;

	  if (! sec->Misc.VirtualSize)
	    map_size = ROUND_SIZE (sec->SizeOfRawData);
	  else
	    map_size = ROUND_SIZE (sec->Misc.VirtualSize);

	  sec->PointerToLinenumbers = (DWORD) map_reserve_low (map, map_size);

	  TRACE ("mapping r/w section %.8s at %p off %x (%lx) flags "
		 "%x to low mem %p\n",
		 sec->Name, ptr + sec->VirtualAddress,
		 sec->PointerToRawData, map_size,
		 sec->Characteristics, sec->PointerToLinenumbers);
	}
      else
	sec->PointerToLinenumbers = 0;
    }

  /* Perform base relocations pointing into low sections.  Before
     that, these relocations point into the high mem address.  */

  relocs = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  rel = (IMAGE_BASE_RELOCATION *)(ptr + relocs->VirtualAddress);
  end = (IMAGE_BASE_RELOCATION *)(ptr + relocs->VirtualAddress + relocs->Size);
  
  while (rel < end - 1 && rel->SizeOfBlock)
    {
      rel = LowLdrProcessRelocationBlock
	(base, ptr + rel->VirtualAddress,
	 (rel->SizeOfBlock - sizeof (*rel)) / sizeof (USHORT),
	 (USHORT *)(rel + 1));
    }
}


/* convert PE image VirtualAddress to Real Address */
static void *
get_rva (HMODULE module, DWORD va)
{
  return (void *) ((char *) module + va);
}


/* convert from straight ASCII to Unicode without depending on the
   current codepage */
static void
ascii_to_unicode (WCHAR *dst, const char *src, size_t len)
{
  while (len--)
    *dst++ = (unsigned char) *src++;
}


#define allocate_stub(x,y) ((void *)0xdeadbeef)


static FARPROC
find_ordinal_export (void *module, const IMAGE_EXPORT_DIRECTORY *exports,
		     DWORD exp_size, DWORD ordinal)
{
  FARPROC proc;
  const DWORD *functions = get_rva (module, exports->AddressOfFunctions);
  
  if (ordinal >= exports->NumberOfFunctions)
    {
      TRACE(" ordinal %d out of range!\n", ordinal + exports->Base );
      return NULL;
    }
  if (!functions[ordinal]) return NULL;
  
#if 0
  /* if the address falls into the export dir, it's a forward */
  if (((const char *)proc >= (const char *)exports) && 
      ((const char *)proc < (const char *)exports + exp_size))
    return find_forwarded_export( module, (const char *)proc, load_path );
#endif

  proc = get_rva_low (module, functions[ordinal]);
  return proc;
}


static FARPROC
find_named_export (void *module, const IMAGE_EXPORT_DIRECTORY *exports,
		   DWORD exp_size, const char *name, int hint)
{
  const WORD *ordinals = get_rva (module, exports->AddressOfNameOrdinals);
  const DWORD *names = get_rva (module, exports->AddressOfNames);
  int min = 0, max = exports->NumberOfNames - 1;

  /* first check the hint */
  if (hint >= 0 && hint <= max)
    {
      char *ename = get_rva( module, names[hint] );
      if (!strcmp( ename, name ))
	return find_ordinal_export( module, exports, exp_size, ordinals[hint]);
    }

  /* then do a binary search */
  while (min <= max)
    {
      int res, pos = (min + max) / 2;
      char *ename = get_rva( module, names[pos] );
      if (!(res = strcmp( ename, name )))
	return find_ordinal_export( module, exports, exp_size, ordinals[pos]);
      if (res > 0) max = pos - 1;
      else min = pos + 1;
    }
  return NULL;
}


/*************************************************************************
 *              import_dll
 *
 * Import the dll specified by the given import descriptor.
 * The loader_section must be locked while calling this function.
 */
static void *
import_dll (struct himemce_map *map, HMODULE module,
	    const IMAGE_IMPORT_DESCRIPTOR *descr)
{
  int status = 0;
  const char *name = get_rva (module, descr->Name);
  DWORD len = strlen(name);
  const IMAGE_THUNK_DATA *import_list;
  IMAGE_THUNK_DATA *thunk_list;
  void *imp_base = 0;
  HMODULE imp_mod = 0;
  const IMAGE_EXPORT_DIRECTORY *exports;
  DWORD exp_size;
  WCHAR buffer[32];
  int i;

  thunk_list = get_rva (module, (DWORD)descr->FirstThunk);
  if (descr->OriginalFirstThunk)
    import_list = get_rva (module, (DWORD)descr->OriginalFirstThunk);
  else
    import_list = thunk_list;

  while (len && name[len-1] == ' ') len--;  /* remove trailing spaces */

  /* First check for the modules in the map.  */
  for (i = 0; i < map->nr_modules; i++)
    {
      if (! strncmp (name, map->module[i].name, len))
	break;
    }
  if (i < map->nr_modules)
    {
      imp_base = map->module[i].base;
      TRACE("Loading library %s internal\n", name);
    }
  else if (len * sizeof(WCHAR) < sizeof(buffer))
    {
      ascii_to_unicode( buffer, name, len );
      buffer[len] = 0;
      imp_mod = LoadLibrary (buffer);
      if (imp_mod == INVALID_HANDLE_VALUE)
	status = GetLastError ();
    }
  else
    {
      WCHAR *ptr = malloc ((len + 1) * sizeof(WCHAR) );
      if (!ptr) return NULL;
      ascii_to_unicode( ptr, name, len );
      ptr[len] = 0;
      imp_mod = LoadLibrary (ptr);
      if (imp_mod == INVALID_HANDLE_VALUE)
	status = GetLastError ();
      free (ptr);
    }
  if (status)
    {
      if (status == ERROR_DLL_NOT_FOUND)
	TRACE("Library %s not found\n", name);
      else
	TRACE("Loading library %s failed (error %x).\n",  name, status);
      return NULL;
    }

  if (imp_base)
    {
      exports = MyRtlImageDirectoryEntryToData (imp_base, TRUE,
						IMAGE_DIRECTORY_ENTRY_EXPORT,
						&exp_size);
      if (!exports)
	{
	  /* set all imported function to deadbeef */
	  while (import_list->u1.Ordinal)
	    {
	      if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
		{
		  int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);
		  TRACE ("No implementation for %s.%d", name, ordinal);
		  thunk_list->u1.Function
		    = (PDWORD) allocate_stub (name, IntToPtr (ordinal));
		}
	      else
		{
		  IMAGE_IMPORT_BY_NAME *pe_name
		    = get_rva (module, (DWORD) import_list->u1.AddressOfData);
		  TRACE ("No implementation for %s.%s", name, pe_name->Name);
		  thunk_list->u1.Function
		    = (PDWORD) allocate_stub (name, (const char*) pe_name->Name);
		}
	      import_list++;
	      thunk_list++;
	    }
	  goto done;
	}
    }
  
  while (import_list->u1.Ordinal)
    {
      if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
        {
	  int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);

	  if (imp_base)
	    thunk_list->u1.Function = (PDWORD)(ULONG_PTR)
	      find_ordinal_export (imp_base, exports, exp_size,
				   ordinal - exports->Base);
	  else
	    thunk_list->u1.Function = (PDWORD)(ULONG_PTR)
	      GetProcAddress (imp_mod, (void *) (ordinal & 0xffff));
	  if (!thunk_list->u1.Function)
            {
	      thunk_list->u1.Function = (PDWORD) allocate_stub( name, IntToPtr(ordinal) );
	      TRACE("No implementation for %s.%d imported, setting to %p\n",
		    name, ordinal,
		    (void *)thunk_list->u1.Function );
            }
	  TRACE("--- Ordinal %s.%d = %p\n", name, ordinal, (void *)thunk_list->u1.Function );
        }
      else  /* import by name */
        {
	  IMAGE_IMPORT_BY_NAME *pe_name;
	  pe_name = get_rva( module, (DWORD)import_list->u1.AddressOfData );
	  if (imp_base)
	    thunk_list->u1.Function = (PDWORD)(ULONG_PTR)
	      find_named_export (imp_base, exports, exp_size,
				 (const char*)pe_name->Name, pe_name->Hint);
	  else
	    thunk_list->u1.Function = (PDWORD)(ULONG_PTR)
	      GetProcAddressA (imp_mod, (const char*)pe_name->Name);
	  if (!thunk_list->u1.Function)
            {
	      thunk_list->u1.Function
		= (PDWORD) allocate_stub (name, (const char*)pe_name->Name);
	      TRACE ("No implementation for %s.%s imported, setting to %p\n",
		     name, pe_name->Name, (void *)thunk_list->u1.Function);
            }
	  TRACE("--- %s %s.%d = %p\n",
		pe_name->Name, name, pe_name->Hint,
		(void *)thunk_list->u1.Function);
        }
      import_list++;
      thunk_list++;
    }

 done:
  return (void*)1;
}


static void
fixup_imports (struct himemce_map *map, void *base)
{
  int i, nb_imports;
  const IMAGE_IMPORT_DESCRIPTOR *imports;
  DWORD size;

  imports = MyRtlImageDirectoryEntryToData (base, TRUE,
					    IMAGE_DIRECTORY_ENTRY_IMPORT,
					    &size);
  if (!imports)
    return;

  nb_imports = 0;
  while (imports[nb_imports].Name && imports[nb_imports].FirstThunk)
    nb_imports++;
  if (!nb_imports)
    return;

  for (i = 0; i < nb_imports; i++)
    {
      if (! import_dll (map, base, &imports[i]))
	{
	  SetLastError (ERROR_DLL_NOT_FOUND);
	  break;
	}
    }
}


int
main (int argc, char *argv[])
{
  struct himemce_map *map;
  int result = 0;
  int i;

  TRACE ("creating map file...\n");

  map = map_create ();
  if (! map)
    return 1;

  TRACE ("finding modules...\n");

  result = find_modules (map);
  if (! result)
    exit (1);

  TRACE ("loading modules...\n");

  /* For each module: load it high without resolving references.  */
  for (i = 0; i < map->nr_modules; i++)
    {
      struct himemce_module *mod = &map->module[i];
      void *base = MyLoadLibraryExW (mod->filename, 0,
				     DONT_RESOLVE_DLL_REFERENCES);

      if (! base)
	{
	  ERR ("could not load %S: %i\n", mod->filename, GetLastError());
	  exit (1);
	}
      mod->base = base;
    }

  TRACE ("relocationg writable sections...\n");

  for (i = 0; i < map->nr_modules; i++)
    {
      struct himemce_module *mod = &map->module[i];

      /* Allocate low mem for read-write sections and adjust
	 relocations pointing into them.  */
      relocate_rw_sections (map, mod->base);
    }

  /* Export entries are handled at time of import on the other side,
     when we check for low memory mapped sections and adjust the
     imported address accordingly.  */

  TRACE ("resolve module dependencies...\n");

  for (i = 0; i < map->nr_modules; i++)
    {
      struct himemce_module *mod = &map->module[i];

      /* Fixup imports (this loads all dependencies as well!).  */
      fixup_imports (map, mod->base);
    }

  TRACE ("sleeping...");

  while (1)
    Sleep (3600 * 1000);

  return 0;
}
