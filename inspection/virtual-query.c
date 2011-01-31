#include <stdio.h>
#include <windows.h>

FILE *fp;

void
dump_mbi_header ()
{
  fprintf (fp, "alc-base   alc-prot address    size       state    protect  type     \n");
} 


void
dump_protect_flags (DWORD flags)
{
  DWORD pr = flags & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
		      | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY
		      | PAGE_READWRITE | PAGE_WRITECOPY);
  DWORD pw = flags & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
		      | PAGE_READWRITE | PAGE_WRITECOPY);
  DWORD pc = flags & (PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY);
  DWORD px = flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ
		      | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
  
  fprintf (fp, "%c%c%c %c%c%c  ",
	  pr ? 'r' : '-', pc ? 'c' : (pw ? 'w' : '-'), px ? 'x' : '-',
	  (flags & PAGE_GUARD) ? 'g' : '-',
	  (flags & PAGE_NOCACHE) ? 'n' : '-',
#ifdef PAGE_PHYSICAL
	  (flags & PAGE_PHYSICAL) ? 'p' : 
#endif
	  '-');
}


void
dump_state (DWORD state)
{
  switch (state)
    {
    case MEM_COMMIT:
      fprintf (fp, "commit   ");
      return;
    case MEM_FREE:
      fprintf (fp, "free     ");
      return;
    case MEM_RESERVE:
      fprintf (fp, "reserve  ");
      return;
    default:
      fprintf (fp, "unknown  ");
    }
}


void
dump_type (DWORD mtype)
{
  switch (mtype)
    {
    case MEM_IMAGE:
      fprintf (fp, "image    ");
      return;
    case MEM_MAPPED:
      fprintf (fp, "mapped   ");
      return;
    case MEM_PRIVATE:
      fprintf (fp, "private  ");
      return;
    default:
      fprintf (fp, "unknown  ");
    }
}


void
dump_mbi (PMEMORY_BASIC_INFORMATION mbi)
{
  fprintf (fp, "0x%08x ", mbi->AllocationBase);
  dump_protect_flags (mbi->AllocationProtect);
  fprintf (fp, "0x%08x ", mbi->BaseAddress);
  fprintf (fp, "0x%08x ", mbi->RegionSize);
  dump_state (mbi->State);
  dump_protect_flags (mbi->Protect);
  dump_type (mbi->Type);
  fprintf (fp, "\n");
}

#include <tlhelp32.h>
#include <windows.h>
#define MAX_PROCESSES 32

DWORD GetMaxProcessNameLength( PROCESSENTRY32 lppe[MAX_PROCESSES], DWORD ProcessCount )
{
  DWORD index ;
  DWORD MaxLength = 0;
  DWORD CurrentLength;
  for( index = 0; index < ProcessCount; index++ )
    {
      CurrentLength = wcslen( lppe[ index ].szExeFile );
      if( MaxLength <  CurrentLength )
	MaxLength = CurrentLength;
    }
  return MaxLength;
}

#define TH32CS_SNAPNOHEAPS 0x40000000

DWORD GetRunningProcesses( PROCESSENTRY32 *pProcess )
{
  HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS|TH32CS_SNAPNOHEAPS, 0);
  DWORD index = 0;
  if(hSnapShot == (HANDLE)-1)
    {
#if 1
      fprintf (fp, "GetRunningProcesses: Failed CreateToolhelp32Snapshot Error: %d\n",
	       GetLastError());
#endif
      return 0;
    }

  memset(pProcess,0,sizeof(PROCESSENTRY32));
  index = 0;
  pProcess->dwSize = sizeof(PROCESSENTRY32);
  if(Process32First(hSnapShot, pProcess))
    {
      while(TRUE)
	{
	  index += 1;
	  if( index < MAX_PROCESSES )
	    {
	      memcpy( pProcess + 1, pProcess, sizeof(PROCESSENTRY32));
	      pProcess++;
	      if(!Process32Next(hSnapShot, pProcess))
		{
		  break;
		}
	    }
	  else
	    {
	      index = MAX_PROCESSES;
	      break;
	    }
	}
    }
  CloseToolhelp32Snapshot (hSnapShot);
  return index ;
}

int
main (int argc, char* argv[])
{
  MEMORY_BASIC_INFORMATION mbi;
  SYSTEM_INFO si;
  void *addr;
  int skipping = 0;

  fp = fopen ("\\Speicherkarte\\vmemory.txt", "w");
  {
    PROCESSENTRY32 *CurrentProcess;
    PROCESSENTRY32 Process[ MAX_PROCESSES ];
    DWORD ProcessCount;
    DWORD index ;
    DWORD MaxProcessNameLength;
    // Get the list of running processes
    ProcessCount = GetRunningProcesses( Process );
    // Get the length of the longest process name so that we can format
    // the output to be pretty
    MaxProcessNameLength = GetMaxProcessNameLength( Process, ProcessCount );
    // Output a header to describe each column
    fprintf (fp, "%-*s %8s %13s %9s %9s %10s\n",
	    MaxProcessNameLength, "Process", "PID", "Base Priority", "# Threads", "Base Addr", "Access Key");

    // Output information for each running process
    for( index = 0; index < ProcessCount; index++ )
      {
	CurrentProcess = &(Process[ index ] );
	fprintf (fp, "%-*S %8X %13d %9d %9X %10X\n", 
		 MaxProcessNameLength, CurrentProcess->szExeFile,
		 CurrentProcess->th32ProcessID,
		 CurrentProcess->pcPriClassBase,
		 CurrentProcess->cntThreads,
		 CurrentProcess->th32MemoryBase,
		 CurrentProcess->th32AccessKey
		 );
      }
  }
  
  memset (&si, '\0', sizeof (si));
  GetSystemInfo (&si);
  dump_mbi_header ();

  addr = 0;
  do
    {
      DWORD res;
      void *new_addr;

      memset (&mbi, '\0', sizeof (mbi));
      res = VirtualQuery (addr, &mbi, sizeof (mbi));
      if (res == 0)
	{
	  if (!skipping)
	    fprintf (fp, "Skipping over %p...\n", addr);
	  skipping = 1;
	  new_addr = (void*)(((unsigned int)addr) + si.dwPageSize);
 	  if (new_addr < addr)
	    break;
          addr = new_addr; 
         continue;
        }
      if (res != sizeof (mbi))
	{
	  fprintf (fp, "Unexpected return size: %i (expected %i)\n",
		  res, sizeof (mbi));
	}
      skipping = 0;
      dump_mbi (&mbi);
      /* Check for overflow.  */
      new_addr = (void*)(((unsigned int)addr) + mbi.RegionSize);
      if (new_addr < addr)
	break;
      addr = new_addr;
    }
  while (1);

  /* Give ssh time to flush buffers.  */
  fflush (fp);
  fclose (fp);
  Sleep (300);
  return 0;
}
