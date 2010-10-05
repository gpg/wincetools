/* himemce-tool.c - High Memory for Windows CE
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
#include <stdio.h>

#include "himemce-map.h"

int
main (int argc, char *argv[])
{
  struct himemce_map *map;
  int i;

  /* Open the map data (which must exist).  */
  map = himemce_map_open ();
  if (! map)
    {
      fprintf (stderr, "could not open himem map: %i\n", GetLastError ());
      exit (1);
    }

  printf ("Found map at %p (size 0x%x)\n", map, map->size);
  printf ("Low memory reserve at %p (size 0x%x)\n",
	  map->low_start, map->low_size);
  printf ("Listing %i modules:\n", map->nr_modules);
  for (i = 0; i < map->nr_modules; i++)
    {
      struct himemce_module *mod = &map->module[i];
      printf ("module[%2i] = %s %p\n", i, mod->name, mod->base);
      /* TODO: Loop through sections, show some more info.  */
    }

  himemce_map_close (map);
  return 0;
}
