/* himemce-map.c - High Memory for Windows CE
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

#include "himemce-map.h"

/* Open the map data (which must exist).  */
struct himemce_map *
himemce_map_open (void)
{
  HANDLE *hnd;
  struct himemce_map *map;

  hnd = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
			   HIMEMCE_MAP_SIZE, HIMEMCE_MAP_NAME);
  if (! hnd)
    return NULL;
  map = MapViewOfFile (hnd, FILE_MAP_READ, 0, 0, 0);
  CloseHandle (hnd);
  if (! map)
    return NULL;
  if (map->magic != HIMEMCE_MAP_MAGIC)
    return NULL;

  return map;
}


/* Release the map data.  */
void
himemce_map_close (struct himemce_map *map)
{
  UnmapViewOfFile (map);
}


/* Find the DLL with the name DLLNAME in the map.  */
struct himemce_module *
himemce_map_find_dll (struct himemce_map *map, char *name)
{
  int i;

  for (i = 0; i < map->nr_modules; map++)
    if (! strcmp (map->module[i].name, name))
      break;

  if (i < map->nr_modules)
    return &map->module[i];

  return NULL;
}
