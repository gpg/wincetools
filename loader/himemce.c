/* himemce.c - High Memory for Windows CE
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
#include <winuser.h>
#include <assert.h>

#include "himemce.h"

/* True if debug output should be given.  */
int verbose = 1;


/* Get the filename of the image file to load.  Normally, this is the
   current exe name, with "-real.exe" instead of any existing
   ending.  */
wchar_t *
get_app_name (void)
{
  /* Nine for "-real.exe" and one for good luck.  */
  static wchar_t filename[MAX_PATH + 10];
  int res;
  wchar_t *end;

  res = GetModuleFileName (GetModuleHandle (NULL), filename, MAX_PATH);
  if (! res)
    {
      ERR ("can not determine module filename: %i\n",
	     GetLastError ());
      exit (1);
    }
  
  end = wcsrchr (filename, L'.');
  if (! end)
    end = filename + wcslen (filename);
  
  wcscpy (end, L"-real.exe");
  return filename;
}

int
main (int argc, char *argv[])
{
  WCHAR *app_name;
  WCHAR *cmdline;

  BOOL ret;
  int result = 0;

  SetCursor( LoadCursor( NULL, IDC_WAIT ) );
  app_name = get_app_name ();
  cmdline = GetCommandLine ();

  TRACE ("starting %S %S\n", app_name, cmdline);

  /* Note that this does not spawn a new process, but just calls into
     the startup function of the app eventually, and returns with its
     exit code.  */
#if USE_LOADER
  ret = MyCreateProcessW (app_name, cmdline, &result);
#else
  ret = CreateProcess (app_name, cmdline, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, NULL, NULL);
#endif
  if (! ret)
    {
      ERR ("starting %S failed: %i\n", app_name, GetLastError());
      return 1;
    }

  return result;
}
