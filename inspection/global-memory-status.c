#include <stdio.h>
#include <windows.h>

int
main (int argc, char* argv[])
{
  MEMORYSTATUS ms;
  memset (&ms, '\0', sizeof (ms));
  ms.dwLength = sizeof (ms);

  GlobalMemoryStatus (&ms);
  printf ("Overall memory load (0-100): %i\n",
	  ms.dwMemoryLoad);
  printf ("Physical memory available/total: 0x%08x/0x%08x (%i)\n",
	  ms.dwAvailPhys, ms.dwTotalPhys);
  printf ("Pagefile memory available/total: 0x%08x/0x%08x (%i)\n",
	  ms.dwAvailPageFile, ms.dwTotalPageFile);
  printf ("Virtual  memory available/total: 0x%08x/0x%08x (%i)\n",
	  ms.dwAvailVirtual, ms.dwTotalVirtual);

  /* Give ssh time to flush buffers.  */
  fflush (stdout);
  Sleep (300);
  return 0;
}
