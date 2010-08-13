/* himemce-real.cpp - High Memory for Windows CE Test program
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


#include <stdio.h>

#define KB(x) ((x) * 1024)
#define MB(x) (KB(x) * 1024)

/* Test read-only data section.  */
const char teststr_ro[] = { 'R', 'e', 'a', 'd', '-',
			    'o', 'n', 'l', 'y', '.' };

/* Make program wastefully large and test read/write data section.  */
char teststr_rw[MB(4)] = { 'R', 'e', 'a', 'd', '-',
			   'w', 'r', 'i', 't', 'e', '.', '\0' };

/* FIXME: TODO: Add BSS test.  */
// char teststr_bs[512];


/* Test static constructors/destructors.  */
class Foo
{
public:
  Foo()
  {
    printf ("CONSTRUCTED FOO\n");
  }
  ~Foo()
  {
    printf ("DECONSTRUCTED FOO\n");
  }
};

Foo foo;


int
main (int argc, char *argv[])
{
  int i;

  printf ("TEST: argc = %i\n", argc);
  for (i = 0; i < argc; i++)
    printf ("TEST: argv[%i] = %s\n", i, argv[i]);

  printf ("TEST: RO: %s\n", teststr_ro);
  printf ("TEST: RW: %s\n", teststr_rw);
  // printf ("TEST: BS: %s\n", teststr_bs);
  return 0;
}
