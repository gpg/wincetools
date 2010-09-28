/* himemce-map-provider.c - High Memory for Windows CE
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

#include "debug.h"
#include "himemce-map-provider.h"

#define ALIGN(x,a) ((x + ((a) - 1)) & ~(a - 1))

struct himemce_map *
map_create (void)
{
  HANDLE *hnd;
  struct himemce_map *map;

  hnd = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
			   HIMEMCE_MAP_SIZE, HIMEMCE_MAP_NAME);
  if (! hnd)
    {
      ERR ("creating himemce map file failed: %i\n", GetLastError ());
      return NULL;
    }
  map = MapViewOfFile (hnd, FILE_MAP_READ, 0, 0, 0);
  CloseHandle (hnd);
  if (! map)
    {
      ERR ("mapping himemce map file failed: %i\n", GetLastError ());
      return NULL;
    }

  if (map->magic == HIMEMCE_MAP_MAGIC)
    {
      /* Already running.  */
      ERR ("himemce map already present\n");
      UnmapViewOfFile (map);
      return NULL;
    }

  /* Set the defaults.  */
  map->magic = HIMEMCE_MAP_MAGIC;
  map->size = sizeof (struct himemce_map);
  map->low_start = _HIMEMCE_MAP_LOW_BASE;
  return map;
}


void *
map_alloc (struct himemce_map *map, int size)
{
  void *ptr = ((char *) map) + map->size;

  /* Word-align.  */
  map->size += ALIGN (size, 4);
  if (size >= HIMEMCE_MAP_SIZE)
    {
      ERR ("out of map memory allocating %i bytes\n", size);
      return NULL;
    }
  return ptr;
}


void *
map_reserve_low (struct himemce_map *map, int size)
{
  void *ptr = ((char *) map->low_start) + map->low_size;

  /* Alignment for module sections.  */
  map->low_size += ALIGN (size, 1024);
  return ptr;
}


struct himemce_module *
map_add_module (struct himemce_map *map, wchar_t *filename, void *base)
{
  struct himemce_module *mod;
  int len;
  int idx;

  if (map->nr_modules == HIMEMCE_MAP_MAX_MODULES)
    {
      ERR ("too many modules\n");
      return NULL;
    }

  mod = &map->module[map->nr_modules];

  len = wcslen (filename);
  mod->filename = map_alloc (map, (len + 1) * sizeof (wchar_t));
  if (! mod->filename)
    return NULL;
  wcscpy (mod->filename, filename);
  idx = len;
  while (idx > 0 && mod->filename[idx - 1] != '\\'
	 && mod->filename[idx - 1] != '/')
    idx--;
  mod->dllname = &mod->filename[idx];
  mod->base = base;

  len = WideCharToMultiByte (CP_UTF8, 0, mod->dllname, -1, NULL, 0, NULL, NULL);
  if (len == 0)
    {
      ERR ("conversion failure: %i\n", GetLastError ());
      return NULL;
    }
  mod->name = map_alloc (map, len);
  if (! mod->name)
    return NULL;

  if (WideCharToMultiByte (CP_UTF8, 0, mod->dllname, -1, mod->name, len,
			   NULL, NULL) != len)
    {
      ERR ("conversion inconsistency: %i\n", GetLastError ());
      return NULL;
    }

  map->nr_modules++;
  return mod;
}


