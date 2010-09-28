/* From wine1.2-1.1.42/dlls/ntdll/loader.c  */

/*
 * Loader functions
 *
 * Copyright 1995, 2003 Alexandre Julliard
 * Copyright 2002 Dmitry Timoshkov for CodeWeavers
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



#include <assert.h>

#include "wine.h"

PIMAGE_NT_HEADERS MyRtlImageNtHeader(HMODULE hModule)
{
    IMAGE_NT_HEADERS *ret;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;

    ret = NULL;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE)
    {
        ret = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
        if (ret->Signature != IMAGE_NT_SIGNATURE) ret = NULL;
    }
    return ret;
}


/* internal representation of 32bit modules. per process. */
typedef struct _wine_modref
{
    LDR_MODULE            ldr;
    int                   nDeps;
    struct _wine_modref **deps;
} WINE_MODREF;

/* FIXME: cmp with himemce-map.h */
#define MAX_MODREFS 64
WINE_MODREF *modrefs[MAX_MODREFS];
int nr_modrefs;


static WINE_MODREF *current_modref;


/* convert from straight ASCII to Unicode without depending on the current codepage */
static void ascii_to_unicode( WCHAR *dst, const char *src, size_t len )
{
  while (len--) *dst++ = (unsigned char)*src++;
}


/***********************************************************************
 *           RtlImageDirectoryEntryToData   (NTDLL.@)
 */
PVOID MyRtlImageDirectoryEntryToData( HMODULE module, BOOL image, WORD dir, ULONG *size )
{
  const IMAGE_NT_HEADERS *nt;
  DWORD addr;

  if ((ULONG_PTR)module & 1)  /* mapped as data file */
    {
      module = (HMODULE)((ULONG_PTR)module & ~1);
      image = FALSE;
    }
  if (!(nt = MyRtlImageNtHeader( module ))) return NULL;
  if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
      const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;

      if (dir >= nt64->OptionalHeader.NumberOfRvaAndSizes) return NULL;
      if (!(addr = nt64->OptionalHeader.DataDirectory[dir].VirtualAddress)) return NULL;
      *size = nt64->OptionalHeader.DataDirectory[dir].Size;
      if (image || addr < nt64->OptionalHeader.SizeOfHeaders) return (char *)module + addr;
    }
  else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
      const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)nt;

      if (dir >= nt32->OptionalHeader.NumberOfRvaAndSizes) return NULL;
      if (!(addr = nt32->OptionalHeader.DataDirectory[dir].VirtualAddress)) return NULL;
      *size = nt32->OptionalHeader.DataDirectory[dir].Size;
      if (image || addr < nt32->OptionalHeader.SizeOfHeaders) return (char *)module + addr;
    }
  else return NULL;

#if 0
  /* not mapped as image, need to find the section containing the virtual address */
  return RtlImageRvaToVa( nt, module, addr, NULL );
#else
  return NULL;
#endif
}


/* convert PE image VirtualAddress to Real Address */
static void *get_rva( HMODULE module, DWORD va )
{
  return (void *)((char *)module + va);
}


#define allocate_stub(x,y) (0xdeadbeef)

/*************************************************************************
 *              import_dll
 *
 * Import the dll specified by the given import descriptor.
 * The loader_section must be locked while calling this function.
 */
static WINE_MODREF *import_dll( HMODULE module, const IMAGE_IMPORT_DESCRIPTOR *descr, LPCWSTR load_path )
{
  NTSTATUS status = STATUS_SUCCESS;
  //  WINE_MODREF *wmImp;
  HMODULE imp_mod;
  //  const IMAGE_EXPORT_DIRECTORY *exports;
  //  DWORD exp_size;
  const IMAGE_THUNK_DATA *import_list;
  IMAGE_THUNK_DATA *thunk_list;
  WCHAR buffer[32];
  const char *name = get_rva( module, descr->Name );
  DWORD len = strlen(name);
#if 0
  PVOID protect_base;
  SIZE_T protect_size = 0;
  DWORD protect_old;
#endif

  thunk_list = get_rva( module, (DWORD)descr->FirstThunk );
  if (descr->OriginalFirstThunk)
    import_list = get_rva( module, (DWORD)descr->OriginalFirstThunk );
  else
    import_list = thunk_list;

  while (len && name[len-1] == ' ') len--;  /* remove trailing spaces */

  if (len * sizeof(WCHAR) < sizeof(buffer))
    {
      ascii_to_unicode( buffer, name, len );
      buffer[len] = 0;
      //      status = load_dll( load_path, buffer, 0, &wmImp );
      imp_mod = LoadLibrary (buffer);
      if (imp_mod == INVALID_HANDLE_VALUE)
	status = GetLastError ();
    }
  else  /* need to allocate a larger buffer */
    {
      WCHAR *ptr = malloc ((len + 1) * sizeof(WCHAR) );
      if (!ptr) return NULL;
      ascii_to_unicode( ptr, name, len );
      ptr[len] = 0;
      // status = load_dll( load_path, ptr, 0, &wmImp );
      imp_mod = LoadLibrary (ptr);
      if (imp_mod == INVALID_HANDLE_VALUE)
	status = GetLastError ();
      free (ptr);
    }
  if (status)
    {
      if (status == STATUS_DLL_NOT_FOUND)
	TRACE("Library %s (which is needed by %s) not found\n",
	    name, current_modref->ldr.FullDllName);
      else
	TRACE("Loading library %s (which is needed by %s) failed (error %x).\n",
	    name, current_modref->ldr.FullDllName, status);
      return NULL;
    }

#if 0
  /* unprotect the import address table since it can be located in
   * readonly section */
  while (import_list[protect_size].u1.Ordinal) protect_size++;
  protect_base = thunk_list;
  protect_size *= sizeof(*thunk_list);
  NtProtectVirtualMemory( NtCurrentProcess(), &protect_base,
			  &protect_size, PAGE_WRITECOPY, &protect_old );
#endif

#if 0
  imp_mod = wmImp->ldr.BaseAddress;
  exports = RtlImageDirectoryEntryToData( imp_mod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size );

  if (!exports)
    {
      /* set all imported function to deadbeef */
      while (import_list->u1.Ordinal)
        {
	  if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
            {
	      int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);
	      WARN("No implementation for %s.%d", name, ordinal );
	      thunk_list->u1.Function = allocate_stub( name, IntToPtr(ordinal) );
            }
	  else
            {
	      IMAGE_IMPORT_BY_NAME *pe_name = get_rva( module, (DWORD)import_list->u1.AddressOfData );
	      WARN("No implementation for %s.%s", name, pe_name->Name );
	      thunk_list->u1.Function = allocate_stub( name, (const char*)pe_name->Name );
            }
	  WARN(" imported from %s, allocating stub %p\n",
	       current_modref->ldr.FullDllName,
	       (void *)thunk_list->u1.Function );
	  import_list++;
	  thunk_list++;
        }
      goto done;
    }
#endif

  while (import_list->u1.Ordinal)
    {
      if (IMAGE_SNAP_BY_ORDINAL(import_list->u1.Ordinal))
        {
	  int ordinal = IMAGE_ORDINAL(import_list->u1.Ordinal);

	  //	  thunk_list->u1.Function = (ULONG_PTR)find_ordinal_export( imp_mod, exports, exp_size,
	  //                                                                ordinal - exports->Base, load_path );
	  thunk_list->u1.Function = (PDWORD)(ULONG_PTR)GetProcAddress (imp_mod, (void *) (ordinal & 0xffff));
	  if (!thunk_list->u1.Function)
            {
	      thunk_list->u1.Function = (PDWORD) allocate_stub( name, IntToPtr(ordinal) );
	      TRACE("No implementation for %s.%d imported from %s, setting to %p\n",
		    name, ordinal, current_modref->ldr.FullDllName,
		    (void *)thunk_list->u1.Function );
            }
	  TRACE("--- Ordinal %s.%d = %p\n", name, ordinal, (void *)thunk_list->u1.Function );
        }
      else  /* import by name */
        {
	  IMAGE_IMPORT_BY_NAME *pe_name;
	  pe_name = get_rva( module, (DWORD)import_list->u1.AddressOfData );
	  //	  thunk_list->u1.Function = (ULONG_PTR)find_named_export( imp_mod, exports, exp_size,
	  //								  (const char*)pe_name->Name,
	  //								  pe_name->Hint, load_path );
	  thunk_list->u1.Function = (PDWORD)(ULONG_PTR)GetProcAddressA (imp_mod, (const char*)pe_name->Name);
	  if (!thunk_list->u1.Function)
            {
	      thunk_list->u1.Function = (PDWORD) allocate_stub( name, (const char*)pe_name->Name );
	      TRACE("No implementation for %s.%s imported from %s, setting to %p\n",
		    name, pe_name->Name, current_modref->ldr.FullDllName,
		    (void *)thunk_list->u1.Function );
            }
	  TRACE("--- %s %s.%d = %p\n",
		pe_name->Name, name, pe_name->Hint, (void *)thunk_list->u1.Function);
        }
      import_list++;
      thunk_list++;
    }
  // done:
#if 0
  /* restore old protection of the import address table */
  NtProtectVirtualMemory( NtCurrentProcess(), &protect_base, &protect_size, protect_old, NULL );
  return wmImp;
#endif
  return (void*)1;
}



/****************************************************************
 *       fixup_imports
 *
 * Fixup all imports of a given module.
 * The loader_section must be locked while calling this function.
 */
static NTSTATUS fixup_imports( WINE_MODREF *wm, LPCWSTR load_path )
{
  int i, nb_imports;
  const IMAGE_IMPORT_DESCRIPTOR *imports;
  WINE_MODREF *prev;
  DWORD size;
  NTSTATUS status;
  //  ULONG_PTR cookie;

  if (!(wm->ldr.Flags & LDR_DONT_RESOLVE_REFS)) return STATUS_SUCCESS;  /* already done */
  wm->ldr.Flags &= ~LDR_DONT_RESOLVE_REFS;
  
  if (!(imports = MyRtlImageDirectoryEntryToData( wm->ldr.BaseAddress, TRUE,
						  IMAGE_DIRECTORY_ENTRY_IMPORT, &size )))
    return STATUS_SUCCESS;
  
  nb_imports = 0;
  while (imports[nb_imports].Name && imports[nb_imports].FirstThunk) nb_imports++;
  
  if (!nb_imports) return STATUS_SUCCESS;  /* no imports */
  
#if 0
  if (!create_module_activation_context( &wm->ldr ))
    RtlActivateActivationContext( 0, wm->ldr.ActivationContext, &cookie );
#endif
  
#if 0
  /* Allocate module dependency list */
  wm->nDeps = nb_imports;
  wm->deps  = RtlAllocateHeap( GetProcessHeap(), 0, nb_imports*sizeof(WINE_MODREF *) );
#endif

  /* load the imported modules. They are automatically
   * added to the modref list of the process.
   */
  prev = current_modref;
  current_modref = wm;
  status = STATUS_SUCCESS;
  for (i = 0; i < nb_imports; i++)
    {
      //      if (!(wm->deps[i] = import_dll( wm->ldr.BaseAddress, &imports[i], load_path )))
      if (! import_dll( wm->ldr.BaseAddress, &imports[i], load_path ))
	status = STATUS_DLL_NOT_FOUND;
    }
  current_modref = prev;
  //  if (wm->ldr.ActivationContext) RtlDeactivateActivationContext( 0, cookie );
  return status;
}


static BOOL is_dll_native_subsystem( HMODULE module, const IMAGE_NT_HEADERS *nt, LPCWSTR filename )
{
	return FALSE;
}


/*************************************************************************
 *              get_modref
 *
 * Looks for the referenced HMODULE in the current process
 * The loader_section must be locked while calling this function.
 */
static WINE_MODREF *get_modref( HMODULE hmod )
{
  int i;
  for (i = 0; i < nr_modrefs; i++)
    if (modrefs[i]->ldr.BaseAddress == hmod)
      return modrefs[i];
  return NULL;
}



static WINE_MODREF *alloc_module( HMODULE hModule, LPCWSTR filename )
{
    WINE_MODREF *wm;
    const WCHAR *p;
    const IMAGE_NT_HEADERS *nt = MyRtlImageNtHeader(hModule);
#if 0
    PLIST_ENTRY entry, mark;
#endif

    if (!(wm = malloc (sizeof(*wm)))) return NULL;

    wm->nDeps    = 0;
    wm->deps     = NULL;

    wm->ldr.BaseAddress   = hModule;
    wm->ldr.EntryPoint    = NULL;
    wm->ldr.SizeOfImage   = nt->OptionalHeader.SizeOfImage;
    wm->ldr.Flags         = LDR_DONT_RESOLVE_REFS;
    wm->ldr.LoadCount     = 1;
    wm->ldr.TlsIndex      = -1;
    wm->ldr.SectionHandle = NULL;
    wm->ldr.CheckSum      = 0;
    wm->ldr.TimeDateStamp = 0;
    wm->ldr.ActivationContext = 0;

    wcscpy (wm->ldr.FullDllName, filename);
    if ((p = wcsrchr( wm->ldr.FullDllName, L'\\' ))) p++;
    else p = wm->ldr.FullDllName;
    wcscpy (wm->ldr.BaseDllName, p );

    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) && !is_dll_native_subsystem( hModule, nt, p ))
    {
        wm->ldr.Flags |= LDR_IMAGE_IS_DLL;
        if (nt->OptionalHeader.AddressOfEntryPoint)
            wm->ldr.EntryPoint = (char *)hModule + nt->OptionalHeader.AddressOfEntryPoint;
    }

#if 0
    InsertTailList(&NtCurrentTeb()->Peb->LdrData->InLoadOrderModuleList,
                   &wm->ldr.InLoadOrderModuleList);

    /* insert module in MemoryList, sorted in increasing base addresses */
    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    for (entry = mark->Flink; entry != mark; entry = entry->Flink)
    {
        if (CONTAINING_RECORD(entry, LDR_MODULE, InMemoryOrderModuleList)->BaseAddress > wm->ldr.BaseAddress)
            break;
    }
    entry->Blink->Flink = &wm->ldr.InMemoryOrderModuleList;
    wm->ldr.InMemoryOrderModuleList.Blink = entry->Blink;
    wm->ldr.InMemoryOrderModuleList.Flink = entry;
    entry->Blink = &wm->ldr.InMemoryOrderModuleList;

    /* wait until init is called for inserting into this list */
    wm->ldr.InInitializationOrderModuleList.Flink = NULL;
    wm->ldr.InInitializationOrderModuleList.Blink = NULL;
#endif

    modrefs[nr_modrefs++] = wm;

    return wm;
}


static NTSTATUS load_native_dll( LPCWSTR load_path, LPCWSTR name, HANDLE file,
                                 DWORD flags, WINE_MODREF** pwm )
{
  void *module;
  HANDLE mapping;
  LARGE_INTEGER size;
  SIZE_T len = 0;
  WINE_MODREF *wm;
  NTSTATUS status;

  TRACE("Trying native dll %S\n", name);
  
  size.QuadPart = 0;
  status = MyNtCreateSection( &mapping, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
			      NULL, &size, PAGE_READONLY, SEC_IMAGE, file );
  if (status != STATUS_SUCCESS) return status;
  
  module = NULL;
  status = MyNtMapViewOfSection( mapping, NtCurrentProcess(),
				 &module, 0, 0, &size, &len, ViewShare, 0, PAGE_READONLY );
  CloseHandle( mapping );
  if (status < 0) return status;
  
  /* create the MODREF */
  
  if (!(wm = alloc_module( module, name ))) return STATUS_NO_MEMORY;
  
  /* fixup imports */
  
  if (!(flags & DONT_RESOLVE_DLL_REFERENCES))
    {
#if 1
      return (STATUS_NOT_IMPLEMENTED);
#else
      if ((status = fixup_imports( wm, load_path )) != STATUS_SUCCESS)
        {
#if 0
	  /* the module has only be inserted in the load & memory order lists */
	  RemoveEntryList(&wm->ldr.InLoadOrderModuleList);
	  RemoveEntryList(&wm->ldr.InMemoryOrderModuleList);
	  
	  /* FIXME: there are several more dangling references
	   * left. Including dlls loaded by this dll before the
	   * failed one. Unrolling is rather difficult with the
	   * current structure and we can leave them lying
	   * around with no problems, so we don't care.
	   * As these might reference our wm, we don't free it.
	   */
#endif
	  return status;
        }
#endif
    }
  
  TRACE( "Loaded %S at %p: native\n", wm->ldr.FullDllName, module );
  
  wm->ldr.LoadCount = 1;
  *pwm = wm;
  return STATUS_SUCCESS;
}


static NTSTATUS find_dll_file( const WCHAR *load_path, const WCHAR *libname,
                               WCHAR *filename, ULONG *size, WINE_MODREF **pwm, HANDLE *handle )
{
  HMODULE hnd = GetModuleHandle (NULL);
  int len;
  
  assert (handle);
  assert (*size == MAX_PATH);
  
  if (libname[0] == L'/' || libname[0] == L'\\')
    {
      wcscpy (filename, libname);
    }
  else
    {
      len = GetModuleFileName (hnd, filename, MAX_PATH);
      filename[len++] = L'\\';
      wcscpy (&filename[len], libname);
    }
  TRACE( "opening %S\n", filename);
  
  if (handle)
    {
      *handle = CreateFile( filename, GENERIC_READ, FILE_SHARE_READ, NULL,
			    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
      TRACE ("find_dll_file: 0x%p (0x%x)\n", *handle, GetFileSize (*handle, NULL));
    }
  return STATUS_SUCCESS;
}


static NTSTATUS load_dll( LPCWSTR load_path, LPCWSTR libname, DWORD flags, WINE_MODREF** pwm )
{
    WCHAR filename[MAX_PATH];
    ULONG size;
    HANDLE handle = 0;
    NTSTATUS nts;

    TRACE( "looking for %S in %S\n", libname, load_path ? load_path : L"default path" );

    *pwm = NULL;
    size = MAX_PATH;
    find_dll_file( load_path, libname, filename, &size, pwm, &handle );
    
    if (!handle)
      nts = STATUS_DLL_NOT_FOUND;
    else
      nts = load_native_dll( load_path, filename, handle, flags, pwm );
    
    if (nts == STATUS_SUCCESS)
      {
        /* Initialize DLL just loaded */
        TRACE("Loaded module %S at %p\n", filename, (*pwm)->ldr.BaseAddress);
        if (handle)
	  CloseHandle( handle );
        return nts;
      }
    
    TRACE("Failed to load module %S; status=%x\n", libname, nts);
    if (handle)
      CloseHandle( handle );
    return nts;
}


NTSTATUS MyLdrLoadDll(LPCWSTR path_name, DWORD flags,
		      LPCWSTR libname, HMODULE* hModule)
{
  WINE_MODREF *wm;
  NTSTATUS nts;

  /* Support for dll path removed.  */
  nts = load_dll( path_name, libname, flags, &wm );

  /* For now.  */
  assert (wm->ldr.Flags & LDR_DONT_RESOLVE_REFS);
#if 0
  if (nts == STATUS_SUCCESS && !(wm->ldr.Flags & LDR_DONT_RESOLVE_REFS))
    {
      nts = process_attach( wm, NULL );
      if (nts != STATUS_SUCCESS)
        {
	  LdrUnloadDll(wm->ldr.BaseAddress);
	  wm = NULL;
        }
    }
#endif
  *hModule = (wm) ? wm->ldr.BaseAddress : NULL;

  return nts;
}



/***********************************************************************
 *           LdrProcessRelocationBlock  (NTDLL.@)
 *
 * Apply relocations to a given page of a mapped PE image.
 */
IMAGE_BASE_RELOCATION * MyLdrProcessRelocationBlock( void *page, UINT count,
						     USHORT *relocs, INT_PTR delta )
{
  while (count--)
    {
      USHORT offset = *relocs & 0xfff;
      int type = *relocs >> 12;
      switch(type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
	  break;
#if 1
        case IMAGE_REL_BASED_HIGH:
	  *(short *)((char *)page + offset) += HIWORD(delta);
	  break;
        case IMAGE_REL_BASED_LOW:
	  *(short *)((char *)page + offset) += LOWORD(delta);
	  break;
        case IMAGE_REL_BASED_HIGHLOW:
	  *(int *)((char *)page + offset) += delta;
	  break;
#else
        case IMAGE_REL_BASED_DIR64:
	  *(INT_PTR *)((char *)page + offset) += delta;
	  break;
#endif
        default:
	  TRACE("Unknown/unsupported fixup type %x.\n", type);
	  return NULL;
        }
      relocs++;
    }
  return (IMAGE_BASE_RELOCATION *)relocs;  /* return address of next block */
}


void MyLdrInitializeThunk( void *kernel_start, ULONG_PTR unknown2,
			   ULONG_PTR unknown3, ULONG_PTR unknown4 )
{
  static const WCHAR globalflagW[] = {'G','l','o','b','a','l','F','l','a','g',0};
  NTSTATUS status;
  WINE_MODREF *wm;
  LPCWSTR load_path = NULL;
  PEB *peb = current_peb();
  IMAGE_NT_HEADERS *nt = MyRtlImageNtHeader( peb->ImageBaseAddress );
  void (*_kernel_start) (void *ptr) = kernel_start;

#if 0
  if (main_exe_file) NtClose( main_exe_file );  /* at this point the main module is created */
#endif

  /* allocate the modref for the main exe (if not already done) */
  wm = get_modref( peb->ImageBaseAddress );
  assert( wm );
  if (wm->ldr.Flags & LDR_IMAGE_IS_DLL)
    {
      TRACE("%S is a dll, not an executable\n", wm->ldr.FullDllName );
      exit(1);
    }

  //  peb->ProcessParameters->ImagePathName = wm->ldr.FullDllName;
  //  version_init( wm->ldr.FullDllName );

  //  LdrQueryImageFileExecutionOptions( &peb->ProcessParameters->ImagePathName, globalflagW,
  //				     REG_DWORD, &peb->NtGlobalFlag, sizeof(peb->NtGlobalFlag), NULL );

  /* the main exe needs to be the first in the load order list */
  //  RemoveEntryList( &wm->ldr.InLoadOrderModuleList );
  //  InsertHeadList( &peb->LdrData->InLoadOrderModuleList, &wm->ldr.InLoadOrderModuleList );

  //  if ((status = virtual_alloc_thread_stack( NtCurrentTeb(), 0, 0 )) != STATUS_SUCCESS) goto error;
  //  if ((status = server_init_process_done()) != STATUS_SUCCESS) goto error;

  //  actctx_init();
  //  load_path = NtCurrentTeb()->Peb->ProcessParameters->DllPath.Buffer;
  if ((status = fixup_imports( wm, load_path )) != STATUS_SUCCESS) goto error;
  //  if ((status = alloc_process_tls()) != STATUS_SUCCESS) goto error;
  //  if ((status = alloc_thread_tls()) != STATUS_SUCCESS) goto error;
  //  heap_set_debug_flags( GetProcessHeap() );

#if 0
  /* FIXME: This may be interesting at some point.  */
  status = wine_call_on_stack( attach_process_dlls, wm, NtCurrentTeb()->Tib.StackBase );
  if (status != STATUS_SUCCESS) goto error;
#endif

  //  virtual_release_address_space( nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE );
  //  virtual_clear_thread_stack();
  //  wine_switch_to_stack( start_process, kernel_start, NtCurrentTeb()->Tib.StackBase );
  // stack( start_process, kernel_start, NtCurrentTeb()->Tib.StackBase );
  _kernel_start (peb);

 error:
  TRACE( "Main exe initialization for %S failed, status %x\n",
	 wm->ldr.FullDllName, status);
	 //	 peb->ProcessParameters->ImagePathName, status );
  //  NtTerminateProcess( GetCurrentProcess(), status );
  exit (1);
}
