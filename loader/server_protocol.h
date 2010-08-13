/* -*- C -*-
 *
 * Wine server protocol definition
 *
 * Copyright (C) 2001 Alexandre Julliard
 * Copyright 2010 g10 Code GmbH
 *
 * This file is used by tools/make_requests to build the
 * protocol structures in include/wine/server_protocol.h
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


#ifndef PROTOCOL_SERVER_H
#define PROTOCOL_SERVER_H 1

typedef int mem_size_t; // Normally 64 bit, but good enough.


/* per-page protection flags */
#define VPROT_READ       0x01
#define VPROT_WRITE      0x02
#define VPROT_EXEC       0x04
#define VPROT_WRITECOPY  0x08
#define VPROT_GUARD      0x10
#define VPROT_NOCACHE    0x20
#define VPROT_COMMITTED  0x40
#define VPROT_WRITEWATCH 0x80
/* per-mapping protection flags */
#define VPROT_IMAGE      0x0100  /* mapping for an exe image */
#define VPROT_SYSTEM     0x0200  /* system view (underlying mmap not under our control) */
#define VPROT_VALLOC     0x0400  /* allocated by VirtualAlloc */
#define VPROT_NOEXEC     0x0800  /* don't force exec permission */


/* Server mapping.  */
NTSTATUS SERVER_create_mapping (ACCESS_MASK access, /* const OBJECT_ATTRIBUTES *attr */ void *attr,
				HANDLE file_handle, long long size, unsigned int protect, HANDLE *handle);
NTSTATUS SERVER_get_mapping_info (HANDLE _mapping, ACCESS_MASK access, unsigned int *protect,
				  void **base, mem_size_t *size, int *header_size, HANDLE *fhandle,
				  HANDLE *handle);

#endif
