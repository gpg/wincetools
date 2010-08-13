/* From wine1.2-1.1.42/server/mapping.c  */

/*
 * Server-side file mapping management
 *
 * Copyright (C) 1999 Alexandre Julliard
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

#include "himemce.h"
#include <assert.h>

/* These are always the same.  */
# define page_mask  0xfff
# define page_shift 12
# define init_page_size() do { /* nothing */ } while(0)

#define set_error(x) SetLastError(x)

#define ROUND_SIZE(size)  (((size) + page_mask) & ~page_mask)



struct mapping
{
  void           *obj;
  mem_size_t      size;            /* mapping size */
  int             protect;         /* protection flags */
  HANDLE         *fhnd;             /* handle for file */
  HANDLE         *hnd;             /* handle for mapped file */
  int             header_size;     /* size of headers (for PE image mapping) */
  void           *base;            /* default base addr (for PE image mapping) */
};



/* retrieve the mapping parameters for an executable (PE) image */
static int get_image_params( struct mapping *mapping, HANDLE unix_fd )
{
  IMAGE_DOS_HEADER dos;
  IMAGE_SECTION_HEADER *sec = NULL;
  struct
  {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union
    {
      IMAGE_OPTIONAL_HEADER32 hdr32;
      IMAGE_OPTIONAL_HEADER64 hdr64;
    } opt;
  } nt;
  off_t pos;
  int size;

    /* load the headers */

    if (pread( unix_fd, (char *) &dos, sizeof(dos), 0 ) != sizeof(dos)) goto error;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) goto error;
    pos = dos.e_lfanew;

    size = pread( unix_fd, (char *) &nt, sizeof(nt), pos );
    if (size < sizeof(nt.Signature) + sizeof(nt.FileHeader)) goto error;
    /* zero out Optional header in the case it's not present or partial */
    if (size < sizeof(nt)) memset( (char *)&nt + size, 0, sizeof(nt) - size );
    if (nt.Signature != IMAGE_NT_SIGNATURE) goto error;

    switch (nt.opt.hdr32.Magic)
      {
      case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        mapping->size        = ROUND_SIZE( nt.opt.hdr32.SizeOfImage );
        mapping->base        = (void *) nt.opt.hdr32.ImageBase;
        mapping->header_size = nt.opt.hdr32.SizeOfHeaders;
        break;
      case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        mapping->size        = ROUND_SIZE( nt.opt.hdr64.SizeOfImage );
        mapping->base        = (void *) nt.opt.hdr64.ImageBase;
        mapping->header_size = nt.opt.hdr64.SizeOfHeaders;
        break;
      default:
        goto error;
      }

    /* load the section headers */

    pos += sizeof(nt.Signature) + sizeof(nt.FileHeader) + nt.FileHeader.SizeOfOptionalHeader;
    size = sizeof(*sec) * nt.FileHeader.NumberOfSections;
    if (pos + size > mapping->size) goto error;
    if (pos + size > mapping->header_size) mapping->header_size = pos + size;
    if (!(sec = malloc( size ))) goto error;
    if (pread( unix_fd, (void *) sec, size, pos ) != size) goto error;

    // if (!build_shared_mapping( mapping, unix_fd, sec, nt.FileHeader.NumberOfSections )) goto error;

    // if (mapping->shared_file) list_add_head( &shared_list, &mapping->shared_entry );

    mapping->protect = VPROT_IMAGE;
    free( sec );
    return 1;

 error:
    free( sec );
    set_error( STATUS_INVALID_FILE_FOR_SECTION );
    return 0;
}


void *create_mapping(/* struct directory *root */ void *root,
		     /* const struct unicode_str *name */ void *name,
		     unsigned int attr, mem_size_t size, int protect,
		     HANDLE handle, /* const struct security_descriptor *sd */ void *sd)
{
  struct mapping *mapping;
#if 0
  struct file *file;
  struct fd *fd;
#endif
  int access = 0;
#if 0
  int unix_fd;
#endif

  if (!page_mask) init_page_size();

  if (!(mapping = malloc (sizeof (struct mapping))))
    return NULL;

  mapping->obj         = NULL;
  mapping->header_size = 0;
  mapping->base        = 0;
  mapping->fhnd         = handle;
  mapping->hnd         = 0;

  if (protect & VPROT_READ) access |= FILE_READ_DATA;
  if (protect & VPROT_WRITE) access |= FILE_WRITE_DATA;

  if (handle)
    {
      // unsigned int mapping_access = FILE_MAPPING_ACCESS;

      if (!(protect & VPROT_COMMITTED))
        {
	  SetLastError( STATUS_INVALID_PARAMETER );
	  goto error;
        }
    
      mapping->hnd = CreateFileMapping (handle, NULL, get_prot_flags (protect),
					0, size, NULL);
      if (mapping->hnd == INVALID_HANDLE_VALUE)
	goto error;

#if 0
      /* file sharing rules for mappings are different so we use magic the access rights */
      if (protect & VPROT_IMAGE) mapping_access |= FILE_MAPPING_IMAGE;
      else if (protect & VPROT_WRITE) mapping_access |= FILE_MAPPING_WRITE;
#endif

      if (protect & VPROT_IMAGE)
        {
	  if (!get_image_params( mapping, handle )) goto error;
	  return &mapping->obj;
        }
#if 0
      if (fstat( unix_fd, &st ) == -1)
        {
	  file_set_error();
	  goto error;
        }
      if (!size)
        {
	  if (!(size = st.st_size))
            {
	      set_error( STATUS_MAPPED_FILE_SIZE_ZERO );
	      goto error;
            }
        }
      else if (st.st_size < size && !grow_file( unix_fd, size )) goto error;
#endif
    }
  else  /* Anonymous mapping (no associated file) */
    {
#if 0
      if (!size || (protect & VPROT_IMAGE))
        {
	  set_error( STATUS_INVALID_PARAMETER );
	  goto error;
        }
      if (!(protect & VPROT_COMMITTED))
        {
	  if (!(mapping->committed = mem_alloc( offsetof(struct ranges, ranges[8]) ))) goto error;
	  mapping->committed->count = 0;
	  mapping->committed->max   = 8;
        }
      if ((unix_fd = create_temp_file( size )) == -1) goto error;
      if (!(mapping->fd = create_anonymous_fd( &mapping_fd_ops, unix_fd, &mapping->obj,
					       FILE_SYNCHRONOUS_IO_NONALERT ))) goto error;
#endif
      assert (!"Not implemented.");
    }
  mapping->size    = (size + page_mask) & ~((mem_size_t)page_mask);
  mapping->protect = protect;
  return &mapping->obj;
  
 error:
  free( mapping );
  return NULL;
}


/* create a file mapping */
NTSTATUS SERVER_create_mapping (ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
				HANDLE file_handle, long long size, unsigned int protect, HANDLE *handle)
{
  void *obj;
  
  *handle = 0;

  obj = create_mapping( NULL, NULL, 0, (mem_size_t) size, protect, file_handle, NULL );
  if (! obj)
    return GetLastError ();

  *handle = (HANDLE)obj;

  return STATUS_SUCCESS;
}


NTSTATUS SERVER_get_mapping_info (HANDLE _mapping, ACCESS_MASK access, unsigned int *protect,
				  void **base, mem_size_t *size, int *header_size, HANDLE *fhandle,
				  HANDLE *handle)
{
  struct mapping *mapping = (struct mapping *) _mapping;

  /* Ignore access.  */

  *size        = mapping->size;
  *protect     = mapping->protect;
  *fhandle     = mapping->fhnd;
  *handle     = mapping->hnd;
  *header_size = mapping->header_size;
  *base        = mapping->base;

  return STATUS_SUCCESS;
}

