#include <stdio.h>
#include <windows.h>

char const*
get_proc_arch (WORD proc_arch)
{
  switch (proc_arch)
    {
    case PROCESSOR_ARCHITECTURE_INTEL:
      return "INTEL";

    case PROCESSOR_ARCHITECTURE_MIPS:
      return "MIPS";

    case PROCESSOR_ARCHITECTURE_ALPHA:
      return "ALPHA";

    case PROCESSOR_ARCHITECTURE_PPC:
      return "PPC";

    case PROCESSOR_ARCHITECTURE_SHX:
      return "SHX";

    case PROCESSOR_ARCHITECTURE_ARM:
      return "ARM";

    case PROCESSOR_ARCHITECTURE_IA64:
      return "IA64";

    case PROCESSOR_ARCHITECTURE_ALPHA64:
      return "ALPHA64";

    case PROCESSOR_ARCHITECTURE_MSIL:
      return "MSIL";

    case PROCESSOR_ARCHITECTURE_AMD64:
      return "AMD64";

    case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
      return "WIN64";

    case PROCESSOR_ARCHITECTURE_UNKNOWN:
      return "UNKNOWN";

    default:
      return "(unknown)";
    }
};


int
main (int argc, char* argv[])
{
  SYSTEM_INFO si;
  memset (&si, '\0', sizeof (si));

  GetSystemInfo (&si);
  printf ("Processor Architecture/Type/Level/Revision: %s/%i/%i/%i\n",
	  get_proc_arch (si.wProcessorArchitecture),
	  si.dwProcessorType, (int) si.wProcessorLevel, (int)si.wProcessorRevision);
  printf ("Page Size: %i\n", si.dwPageSize);
  printf ("Application Virtual Address Space: %p - %p\n",
	  si.lpMinimumApplicationAddress,
	  si.lpMaximumApplicationAddress);
  printf ("Allocation Granularity: %i\n",
	  si.dwAllocationGranularity);

  /* Give ssh time to flush buffers.  */
  fflush (stdout);
  Sleep (300);
  return 0;
}
