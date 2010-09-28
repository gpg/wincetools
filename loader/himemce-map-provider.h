/* himemce-map-provider.h - High Memory for Windows CE
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

#ifndef HIMEMCE_MAP_PROVIDER_H
#define HIMEMCE_MAP_PROVIDER_H 1

#include "himemce-map.h"


struct himemce_map *map_create (void);

void *map_alloc (struct himemce_map *map, int size);

void *map_reserve_low (struct himemce_map *map, int size);

struct himemce_module *map_add_module (struct himemce_map *map,
				       wchar_t *filename, void *base);


#endif /* HIMEMCE_MAP_PROVIDER_H */
