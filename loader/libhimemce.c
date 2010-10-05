#include <windows.h>

static void dllmain_cb (DWORD reason, LPVOID reserved);


/* This library is necessary, because if DLLs are loaded high, they
   need to be notified of new threads, and we can't do that without
   a DLL that receives these notifications from the system.  */

BOOL
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  if (fdwReason != DLL_THREAD_ATTACH && fdwReason != DLL_THREAD_DETACH)
    return TRUE;

  if (dllmain_cb)
    (*dllmain_cb) (fdwReason, lpvReserved);
}


void
himemce_set_dllmain_cb (void (*cb) (DWORD, LPVOID))
{
  dllmain_cb = cb;
}
