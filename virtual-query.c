#include <stdio.h>
#include <windows.h>

void
dump_mbi_header ()
{
  printf ("alc-base   alc-prot address    size       state    protect  type     \n");
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
  
  printf ("%c%c%c %c%c%c  ",
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
      printf ("commit   ");
      return;
    case MEM_FREE:
      printf ("free     ");
      return;
    case MEM_RESERVE:
      printf ("reserve  ");
      return;
    default:
      printf ("unknown  ");
    }
}


void
dump_type (DWORD mtype)
{
  switch (mtype)
    {
    case MEM_IMAGE:
      printf ("image    ");
      return;
    case MEM_MAPPED:
      printf ("mapped   ");
      return;
    case MEM_PRIVATE:
      printf ("private  ");
      return;
    default:
      printf ("unknown  ");
    }
}


void
dump_mbi (PMEMORY_BASIC_INFORMATION mbi)
{
  printf ("0x%08x ", mbi->AllocationBase);
  dump_protect_flags (mbi->AllocationProtect);
  printf ("0x%08x ", mbi->BaseAddress);
  printf ("0x%08x ", mbi->RegionSize);
  dump_state (mbi->State);
  dump_protect_flags (mbi->Protect);
  dump_type (mbi->Type);
  printf ("\n");
}


int
main (int argc, char* argv[])
{
  MEMORY_BASIC_INFORMATION mbi;
  SYSTEM_INFO si;
  void *addr;
  
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
          printf ("Skipping over %p\n", addr);
	  new_addr = addr + si.dwPageSize;
 	  if (new_addr < addr)
	    break;
          addr = new_addr; 
         continue;
        }
      if (res != sizeof (mbi))
	{
	  printf ("Unexpected return size: %i (expected %i)\n",
		  res, sizeof (mbi));
	}
      dump_mbi (&mbi);
      /* Check for overflow.  */
      new_addr = addr + mbi.RegionSize;
      if (new_addr < addr)
	break;
      addr = new_addr;
    }
  while (1);

  /* Give ssh time to flush buffers.  */
  fflush (stdout);
  Sleep (300);
  return 0;
}
