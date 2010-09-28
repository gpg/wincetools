/* himemce-map.h - High Memory for Windows CE
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

#ifndef HIMEMCE_MAP_H
#define HIMEMCE_MAP_H 1

#include <stddef.h>

/* The preloader makes its information available at a shared memory
   object of this name and size.  */
#define HIMEMCE_MAP_NAME L"himemcemap"
#define HIMEMCE_MAP_SIZE (128 * 1024)
#define HIMEMCE_MAP_MAGIC 0x400b1337

/* The default base address.  Users should take the actual value from
   the LOW_START member of struct himemce_map.  */
#define _HIMEMCE_MAP_LOW_BASE ((void *) (2 * 1024 * 1024))

/* Maximum number of DLLs that can be mapped.  */
#define HIMEMCE_MAP_MAX_MODULES 64


/* Each module provides this.  */
struct himemce_module
{
  wchar_t *filename;

  /* Points into filename.  */
  wchar_t *dllname;

  /* Export DLL name (same as DLLNAME, but in ASCII).  */
  char *name;

  /* The base address of the module image.  */
  void *base;

  /* The low (in-process) address of read-write sections is available
     in the PointerToLinenumbers in the section header, which is
     recycled for that purpose.  */
};


struct himemce_map
{
  /* Must be HIMEMCE_MAP_MAGIC.  */
  unsigned int magic;

  /* Actual size of the map.  */
  unsigned int size;

  /* The low addresses of sections are within this range, which must
     be reserved by the program that wants to use mapped modules as
     soon as possible.  */
  void *low_start;
  int low_size;

  /* Number of mapped modules.  */
  int nr_modules;

  struct himemce_module module[HIMEMCE_MAP_MAX_MODULES];
};


/* Open the map data (which must exist).  */
struct himemce_map *himemce_map_open (void);

/* Release the map data.  */
void himemce_map_close (struct himemce_map *map);

/* Find the DLL with the name DLLNAME in the map.  */
struct himemce_module *himemce_map_find_dll (struct himemce_map *map,
					     char *name);

#endif /* HIMEMCE_MAP_H */
