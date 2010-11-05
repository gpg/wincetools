/* From wine1.2-1.1.42/dlls/ntdll/virtual.c  */

/*
 * Win32 virtual memory functions
 *
 * Copyright 1997, 2002 Alexandre Julliard
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


#include <windows.h>
#include <assert.h>

#include "himemce.h"

/* File view */
typedef struct file_view
{
    void         *base;        /* Base address */
    size_t        size;        /* Size in bytes */
    HANDLE        mapping;     /* Handle to the file mapping */
    unsigned int  protect;     /* Protection for all pages at allocation time */
} FILE_VIEW;


# define page_mask  0xfff
# define page_shift 12
# define page_size  0x1000


#define ROUND_SIZE(addr,size) \
  (((SIZE_T)(size) + ((UINT_PTR)(addr) & page_mask) + page_mask) & ~page_mask)


static size_t get_mask( ULONG zero_bits )
{
  if (!zero_bits) return 0xffff;  /* allocations are aligned to 64K by default */
  if (zero_bits < page_shift) zero_bits = page_shift;
  return (1 << zero_bits) - 1;
}


static NTSTATUS get_vprot_flags( DWORD protect, unsigned int *vprot )
{
  switch(protect & 0xff)
    {
    case PAGE_READONLY:
      *vprot = VPROT_READ;
      break;
    case PAGE_READWRITE:
      *vprot = VPROT_READ | VPROT_WRITE;
      break;
    case PAGE_WRITECOPY:
      *vprot = VPROT_READ | VPROT_WRITECOPY;
      break;
    case PAGE_EXECUTE:
      *vprot = VPROT_EXEC;
      break;
    case PAGE_EXECUTE_READ:
      *vprot = VPROT_EXEC | VPROT_READ;
      break;
    case PAGE_EXECUTE_READWRITE:
      *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITE;
      break;
    case PAGE_EXECUTE_WRITECOPY:
      *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
      break;
    case PAGE_NOACCESS:
      *vprot = 0;
      break;
    default:
      return STATUS_INVALID_PARAMETER;
    }
  if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
  if (protect & PAGE_NOCACHE) *vprot |= VPROT_NOCACHE;
  return STATUS_SUCCESS;
}


static void delete_view( struct file_view *view ) /* [in] View */
{
  VirtualFree (view->base, view->size, MEM_RELEASE);
  // if (view->mapping) NtClose( view->mapping );
  free (view);
}


static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size, size_t mask,
                          int top_down, unsigned int vprot )
{
  int prot = get_prot_flags (vprot);
  struct file_view *view;
  void *ptr;
  void *new_ptr;

  view = malloc (sizeof (struct file_view));
  if (!view)
    return STATUS_NO_MEMORY;
  
  // FIXME: Only with NOACCESS does Windows CE prefer the high mem area
  // even for smaller areas.
  ptr = VirtualAlloc(base, size, MEM_RESERVE, PAGE_NOACCESS /*prot*/);
  if (!ptr)
    {
      free (view);
      return GetLastError();
    }
  /* We have to zero map the whole thing.  */
  new_ptr = VirtualAlloc (ptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (new_ptr != ptr)
    {
      free (view);
      return GetLastError();
    }
  view->base = ptr;
  view->size = size;
  view->protect = vprot;
  view->mapping = 0;
  *view_ret = view;
  return STATUS_SUCCESS;
}


static NTSTATUS map_file_into_view( struct file_view *view, HANDLE fhandle, size_t start, size_t size,
                                    off_t offset, unsigned int vprot, BOOL removable )
{
  void *ptr;
  int prot = get_prot_flags (vprot);
  BOOL shared_write = (vprot & VPROT_WRITE) != 0;

  assert( start < view->size );
  assert( start + size <= view->size );

#if 0
  /* only try mmap if media is not removable (or if we require write access) */
  if (!removable || shared_write)
    {
      int flags = MAP_FIXED | (shared_write ? MAP_SHARED : MAP_PRIVATE);

      if (mmap( (char *)view->base + start, size, prot, flags, fd, offset ) != (void *)-1)
	goto done;

      /* mmap() failed; if this is because the file offset is not    */
      /* page-aligned (EINVAL), or because the underlying filesystem */
      /* does not support mmap() (ENOEXEC,ENODEV), we do it by hand. */
      if ((errno != ENOEXEC) && (errno != EINVAL) && (errno != ENODEV)) return FILE_GetNtStatus();
      if (shared_write)  /* we cannot fake shared write mappings */
        {
	  if (errno == EINVAL) return STATUS_INVALID_PARAMETER;
	  ERR( "shared writable mmap not supported, broken filesystem?\n" );
	  return STATUS_NOT_SUPPORTED;
        }
    }
#endif

#if 0
  /* Already done by map_view.  */
  /* Reserve the memory with an anonymous mmap */
  ptr = VirtualAlloc ((char *)view->base + start, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (ptr == (void *)-1) return GetLastError();
#else
  ptr = (char *)view->base + start;
#endif

  /* Now read in the file */
  pread( fhandle, ptr, size, offset );
  //  if (prot != (PROT_READ|PROT_WRITE)) mprotect( ptr, size, prot );  /* Set the right protection */
  //done:
  //  memset( view->prot + (start >> page_shift), vprot, ROUND_SIZE(start,size) >> page_shift );
  return STATUS_SUCCESS;
}


static NTSTATUS map_image (HANDLE hmapping, HANDLE hfile, HANDLE hmap, char *base, SIZE_T total_size, SIZE_T mask,
			   SIZE_T header_size, int shared_fd, HANDLE dup_mapping, PVOID *addr_ptr)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    IMAGE_DATA_DIRECTORY *imports;
    NTSTATUS status = STATUS_CONFLICTING_ADDRESSES;
    int i;
    off_t pos;
    DWORD fsize;
    struct file_view *view = NULL;
    char *ptr, *header_end;
    INT_PTR delta = 0;


    /* zero-map the whole range */

    if (base >= (char *)0x110000)  /* make sure the DOS area remains free */
      status = map_view( &view, base, total_size, mask, FALSE,
			 VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY | VPROT_IMAGE );

    if (status != STATUS_SUCCESS)
      status = map_view( &view, NULL, total_size, mask, FALSE,
			 VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY | VPROT_IMAGE );

    if (status != STATUS_SUCCESS) goto error;

    ptr = view->base;
    TRACE( "mapped PE file at %p-%p\n", ptr, ptr + total_size );

    /* map the header */
    
    fsize = GetFileSize (hfile, NULL);
    if (fsize == INVALID_FILE_SIZE)
      {
	status = GetLastError();
	goto error;
      }
    status = STATUS_INVALID_IMAGE_FORMAT;  /* generic error */
    header_size = min( header_size, fsize );
    if (map_file_into_view( view, hfile, 0, header_size, 0, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                            !dup_mapping ) != STATUS_SUCCESS) goto error;
    dos = (IMAGE_DOS_HEADER *)ptr;
    nt = (IMAGE_NT_HEADERS *)(ptr + dos->e_lfanew);
    header_end = ptr + ROUND_SIZE( 0, header_size );
    memset( ptr + header_size, 0, header_end - (ptr + header_size) );
    if ((char *)(nt + 1) > header_end) goto error;
    sec = (IMAGE_SECTION_HEADER*)((char*)&nt->OptionalHeader+nt->FileHeader.SizeOfOptionalHeader);
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > header_end) goto error;

    imports = nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    if (!imports->Size || !imports->VirtualAddress) imports = NULL;

    /* check the architecture */

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM
	&& nt->FileHeader.Machine != IMAGE_FILE_MACHINE_THUMB)
	{
 	  TRACE("Trying to load PE image for unsupported architecture (");
	  switch (nt->FileHeader.Machine)
	    {
	    case IMAGE_FILE_MACHINE_UNKNOWN: TRACE("Unknown"); break;
	    case IMAGE_FILE_MACHINE_I386:    TRACE("I386"); break;
	    case IMAGE_FILE_MACHINE_R3000:   TRACE("R3000"); break;
	    case IMAGE_FILE_MACHINE_R4000:   TRACE("R4000"); break;
	    case IMAGE_FILE_MACHINE_R10000:  TRACE("R10000"); break;
	    case IMAGE_FILE_MACHINE_ALPHA:   TRACE("Alpha"); break;
	    case IMAGE_FILE_MACHINE_POWERPC: TRACE("PowerPC"); break;
	    case IMAGE_FILE_MACHINE_IA64:    TRACE("IA-64"); break;
	    case IMAGE_FILE_MACHINE_ALPHA64: TRACE("Alpha-64"); break;
	    case IMAGE_FILE_MACHINE_ARM:     TRACE("ARM"); break;
	    default: TRACE("Unknown-%04x", nt->FileHeader.Machine); break;
	    }
	  TRACE(")\n");
	  goto error;
	}
    
    /* check for non page-aligned binary */

    if (nt->OptionalHeader.SectionAlignment <= page_mask)
      {
        /* unaligned sections, this happens for native subsystem binaries */
        /* in that case Windows simply maps in the whole file */

        if (map_file_into_view( view, hfile, 0, total_size, 0, VPROT_COMMITTED | VPROT_READ,
                                !dup_mapping ) != STATUS_SUCCESS) goto error;

        /* check that all sections are loaded at the right offset */
        if (nt->OptionalHeader.FileAlignment != nt->OptionalHeader.SectionAlignment) goto error;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
	  {
            if (sec[i].VirtualAddress != sec[i].PointerToRawData)
	      goto error;  /* Windows refuses to load in that case too */
	  }
#if 0
        /* set the image protections */
        VIRTUAL_SetProt( view, ptr, total_size,
                         VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
#endif

#if 0
        /* no relocations are performed on non page-aligned binaries */
        goto done;
#else
	goto reloc;
#endif
      }


    /* map all the sections */

    for (i = pos = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
      {
        static const SIZE_T sector_align = 0x1ff;
        SIZE_T map_size, file_start, file_size, end;

        if (!sec->Misc.VirtualSize)
	  map_size = ROUND_SIZE( 0, sec->SizeOfRawData );
        else
	  map_size = ROUND_SIZE( 0, sec->Misc.VirtualSize );

        /* file positions are rounded to sector boundaries regardless of OptionalHeader.FileAlignment */
        file_start = sec->PointerToRawData & ~sector_align;
        file_size = (sec->SizeOfRawData + (sec->PointerToRawData & sector_align) + sector_align) & ~sector_align;
        if (file_size > map_size) file_size = map_size;

        /* a few sanity checks */
        end = sec->VirtualAddress + ROUND_SIZE( sec->VirtualAddress, map_size );
        if (sec->VirtualAddress > total_size || end > total_size || end < sec->VirtualAddress)
	  {
            ERR ( "Section %.8s too large (%x+%lx/%lx)\n",
		  sec->Name, sec->VirtualAddress, map_size, total_size );
            goto error;
	  }

        if ((sec->Characteristics & IMAGE_SCN_MEM_SHARED) &&
            (sec->Characteristics & IMAGE_SCN_MEM_WRITE))
	  {
            TRACE( "mapping shared section %.8s at %p off %x (%x) size %lx (%lx) flags %x\n",
		   sec->Name, ptr + sec->VirtualAddress,
		   sec->PointerToRawData, (int)pos, file_size, map_size,
		   sec->Characteristics );
            if (map_file_into_view( view, hfile, sec->VirtualAddress, map_size, pos,
                                    VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                                    FALSE ) != STATUS_SUCCESS)
	      {
                ERR ( "Could not map shared section %.8s\n", sec->Name );
                goto error;
	      }

            /* check if the import directory falls inside this section */
            if (imports && imports->VirtualAddress >= sec->VirtualAddress &&
                imports->VirtualAddress < sec->VirtualAddress + map_size)
	      {
                UINT_PTR base = imports->VirtualAddress & ~page_mask;
                UINT_PTR end = base + ROUND_SIZE( imports->VirtualAddress, imports->Size );
                if (end > sec->VirtualAddress + map_size) end = sec->VirtualAddress + map_size;
                if (end > base)
		  map_file_into_view( view, hfile, base, end - base,
				      pos + (base - sec->VirtualAddress),
				      VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
				      FALSE );
	      }
            pos += map_size;
            continue;
	  }

        TRACE( "mapping section %.8s at %p off %x size %x virt %x flags %x\n",
	     sec->Name, ptr + sec->VirtualAddress,
	     sec->PointerToRawData, sec->SizeOfRawData,
	     sec->Misc.VirtualSize, sec->Characteristics );
	
        if (!sec->PointerToRawData || !file_size) continue;

        /* Note: if the section is not aligned properly map_file_into_view will magically
         *       fall back to read(), so we don't need to check anything here.
         */
        end = file_start + file_size;
        if (sec->PointerToRawData >= fsize ||
            end > ((fsize + sector_align) & ~sector_align) ||
            end < file_start ||
            map_file_into_view( view, hfile, sec->VirtualAddress, file_size, file_start,
                                VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                !dup_mapping ) != STATUS_SUCCESS)
	  {
            ERR( "Could not map section %.8s, file probably truncated\n", sec->Name );
            goto error;
	  }

        if (file_size & page_mask)
	  {
            end = ROUND_SIZE( 0, file_size );
            if (end > map_size) end = map_size;
            TRACE("clearing %p - %p\n",
		  ptr + sec->VirtualAddress + file_size,
		  ptr + sec->VirtualAddress + end );
            memset( ptr + sec->VirtualAddress + file_size, 0, end - file_size );
	  }
      }

 reloc:
    /* perform base relocation, if necessary */

    if (ptr != base)
      // &&
      //        ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) ||
      //	 !NtCurrentTeb()->Peb->ImageBaseAddress) )
      {
        IMAGE_BASE_RELOCATION *rel, *end;
        const IMAGE_DATA_DIRECTORY *relocs;

        if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	  {
            TRACE( "Need to relocate module from %p to %p, but there are no relocation records\n",
		   base, ptr );
            status = STATUS_CONFLICTING_ADDRESSES;
            goto error;
	  }

        TRACE( "relocating from %p-%p to %p-%p\n",
	       base, base + total_size, ptr, ptr + total_size );

        relocs = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        rel = (IMAGE_BASE_RELOCATION *)(ptr + relocs->VirtualAddress);
        end = (IMAGE_BASE_RELOCATION *)(ptr + relocs->VirtualAddress + relocs->Size);
        delta = ptr - base;

        while (rel < end - 1 && rel->SizeOfBlock)
	  {
            if (rel->VirtualAddress >= total_size)
	      {
                TRACE( "invalid address %p in relocation %p\n", ptr + rel->VirtualAddress, rel );
                status = STATUS_ACCESS_VIOLATION;
                goto error;
	      }
            rel = MyLdrProcessRelocationBlock( ptr + rel->VirtualAddress,
					       (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT),
					       (USHORT *)(rel + 1), delta );
            if (!rel) goto error;
	  }
      }
#if 0
    /* set the image protections */
    VIRTUAL_SetProt( view, ptr, ROUND_SIZE( 0, header_size ), VPROT_COMMITTED | VPROT_READ );

    sec = (IMAGE_SECTION_HEADER*)((char *)&nt->OptionalHeader+nt->FileHeader.SizeOfOptionalHeader);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
      {
        SIZE_T size;
        BYTE vprot = VPROT_COMMITTED;

        if (sec->Misc.VirtualSize)
	  size = ROUND_SIZE( sec->VirtualAddress, sec->Misc.VirtualSize );
        else
	  size = ROUND_SIZE( sec->VirtualAddress, sec->SizeOfRawData );

        if (sec->Characteristics & IMAGE_SCN_MEM_READ)    vprot |= VPROT_READ;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   vprot |= VPROT_READ|VPROT_WRITECOPY;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) vprot |= VPROT_EXEC;

        /* Dumb game crack lets the AOEP point into a data section. Adjust. */
        if ((nt->OptionalHeader.AddressOfEntryPoint >= sec->VirtualAddress) &&
            (nt->OptionalHeader.AddressOfEntryPoint < sec->VirtualAddress + size))
	  vprot |= VPROT_EXEC;

        VIRTUAL_SetProt( view, ptr + sec->VirtualAddress, size, vprot );
      }
#endif

    // done:
    *addr_ptr = ptr;
#ifdef VALGRIND_LOAD_PDB_DEBUGINFO
    VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, delta);
#endif
    if (ptr != base) return STATUS_IMAGE_NOT_AT_BASE;
    return STATUS_SUCCESS;

 error:
    if (view) delete_view( view );
    return status;
}


NTSTATUS MyNtCreateSection (HANDLE *handle, ACCESS_MASK access,
			    /* const OBJECT_ATTRIBUTES *attr */ void *attr,
			    const LARGE_INTEGER *size, ULONG protect,
			    ULONG sec_flags, HANDLE file)
{
    NTSTATUS ret;
    unsigned int vprot;
    
    if ((ret = get_vprot_flags( protect, &vprot ))) return ret;

    assert (attr == NULL);

    if (!(sec_flags & SEC_RESERVE)) vprot |= VPROT_COMMITTED;
    if (sec_flags & SEC_NOCACHE) vprot |= VPROT_NOCACHE;
    if (sec_flags & SEC_IMAGE) vprot |= VPROT_IMAGE;

    ret = SERVER_create_mapping (access, attr, file, size ? size->QuadPart : 0,
				 vprot, handle);

    return ret;
}


NTSTATUS MyNtMapViewOfSection (HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG zero_bits,
			       SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
			       SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect)
{
  NTSTATUS res;
  mem_size_t full_size;
  ACCESS_MASK access;
  SIZE_T size, mask = get_mask( zero_bits );
  unsigned int map_vprot;
  //  unsigned int vprot;
  void *base;
  //  struct file_view *view;
  DWORD header_size;
  HANDLE fhandle;
  HANDLE mhandle;
  LARGE_INTEGER offset;

  offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

  TRACE("handle=%p process=%p addr=%p off=%x%08x size=%lx access=%x\n",
	handle, process, *addr_ptr, offset.u.HighPart, offset.u.LowPart, *size_ptr, protect );

  /* Check parameters */

  if ((offset.u.LowPart & mask) || (*addr_ptr && ((UINT_PTR)*addr_ptr & mask)))
    return STATUS_INVALID_PARAMETER;

  switch(protect)
    {
    case PAGE_NOACCESS:
      access = 0;
      break;
    case PAGE_READWRITE:
    case PAGE_EXECUTE_READWRITE:
      access = SECTION_MAP_WRITE;
      break;
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
      access = SECTION_MAP_READ;
      break;
    default:
      return STATUS_INVALID_PARAMETER;
    }

  res = SERVER_get_mapping_info (handle, access, &map_vprot, &base, &full_size, &header_size, &fhandle, &mhandle);
  if (res) return res;

  if (map_vprot & VPROT_IMAGE)
    {
      size = full_size;
      if (size != full_size)  /* truncated */
        {
	  TRACE( "Modules larger than 4Gb not supported\n");
	  res = STATUS_INVALID_PARAMETER;
	  goto done;
        }
      res = map_image( handle, fhandle, mhandle, base, size, mask, header_size,
		       -1, INVALID_HANDLE_VALUE, addr_ptr );
      if (res >= 0) *size_ptr = size;
      return res;
    }

  assert (!"Not supported");
#if 0
  res = STATUS_INVALID_PARAMETER;
  if (offset.QuadPart >= full_size) goto done;
  if (*size_ptr)
    {
      if (*size_ptr > full_size - offset.QuadPart) goto done;
      size = ROUND_SIZE( offset.u.LowPart, *size_ptr );
      if (size < *size_ptr) goto done;  /* wrap-around */
    }
  else
    {
      size = full_size - offset.QuadPart;
      if (size != full_size - offset.QuadPart)  /* truncated */
        {
	  ERR( "Files larger than 4Gb (%s) not supported on this platform\n",
		wine_dbgstr_longlong(full_size) );
	  goto done;
        }
    }

  /* Reserve a properly aligned area */

  server_enter_uninterrupted_section( &csVirtual, &sigset );

  get_vprot_flags( protect, &vprot );
  vprot |= (map_vprot & VPROT_COMMITTED);
  res = map_view( &view, *addr_ptr, size, mask, FALSE, vprot );
  if (res)
    {
      server_leave_uninterrupted_section( &csVirtual, &sigset );
      goto done;
    }

  /* Map the file */

  TRACE("handle=%p size=%lx offset=%x%08x\n",
	handle, size, offset.u.HighPart, offset.u.LowPart );

  res = map_file_into_view( view, unix_handle, 0, size, offset.QuadPart, vprot, !dup_mapping );
  if (res == STATUS_SUCCESS)
    {
      *addr_ptr = view->base;
      *size_ptr = size;
      view->mapping = dup_mapping;
      dup_mapping = 0;  /* don't close it */
    }
  else
    {
      ERR( "map_file_into_view %p %lx %x%08x failed\n",
	   view->base, size, offset.u.HighPart, offset.u.LowPart );
      delete_view( view );
    }
  
  server_leave_uninterrupted_section( &csVirtual, &sigset );
#endif

 done:
  return res;

  //  *addr_ptr = MapViewOfFile (handle, 
  //			     protect == PAGE_READONLY ? FILE_MAP_READ : FILE_MAP_WRITE,
  //			     offset_ptr ? offset_ptr->HighPart : 0,
  //			     offset_ptr ? offset_ptr->LowPart : 0,
  //			     size_ptr ? size_ptr->LowPart : 0);
  //  if (*addr_ptr == NULL)
  //    return GetLastError ();
  //
  //  return STATUS_SUCCESS;
}
