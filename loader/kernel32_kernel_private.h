/* From wine1.2-1.1.42/dlls/kernel32/kernel_private.h  */

/*
 * Kernel32 undocumented and private functions definition
 *
 * Copyright 2003 Eric Pouech
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

#ifndef __WINE_KERNEL_PRIVATE_H
#define __WINE_KERNEL_PRIVATE_H


enum binary_type
{
    BINARY_UNKNOWN = 0,
    BINARY_PE,
    BINARY_WIN16,
    BINARY_OS216,
    BINARY_DOS,
    BINARY_UNIX_EXE,
    BINARY_UNIX_LIB
};

#define BINARY_FLAG_DLL   0x01
#define BINARY_FLAG_64BIT 0x02

struct binary_info
{
    enum binary_type type;
    DWORD            flags;
    void            *res_start;
    void            *res_end;
};

/* module.c */
extern void MODULE_get_binary_info( HANDLE hfile, struct binary_info *info );

#endif
