#include <stdio.h>
#include <windows.h>
#include <ctype.h>

void
dump_mbi_header ()
{
  printf ("alc-base   alc-prot address    size       state    protect  type     \n");
} 


int
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
  return pr;
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
dump_region (unsigned char *base, unsigned int size)
{
  int i;
  int in_nulls = 0;
 
  /* Base and size are page-aligned.  */
  while (size != 0)
    {
      for (i = 0; i < 16; i++)
	if (base[i])
	  break;
      if (i == 16)
	{
	  /* Only zeroes.  */
	  if (! in_nulls)
	    {
	      printf ("*\n");
	      in_nulls = 1;
	    }
	  goto next;
	}
      in_nulls = 0;
      printf ("0x%08x:", base);
      for (i = 0; i < 16; i++)
	{
	  if (i == 8)
	    printf (" ");
	  printf (" %02x", base[i]);
	}
      printf ("  ");
      for (i = 0; i < 16; i++)
	{
	  if (i == 8)
	    printf (" ");
	  printf ("%c", isprint(base[i]) ? base[i] : '.');
	}
      printf ("\n");
    next:
      base += 16;
      size -= 16;
    }
}


void
dump_mbi (PMEMORY_BASIC_INFORMATION mbi)
{
  int pr;
  printf ("0x%08x ", mbi->AllocationBase);
  dump_protect_flags (mbi->AllocationProtect);
  printf ("0x%08x ", mbi->BaseAddress);
  printf ("0x%08x ", mbi->RegionSize);
  dump_state (mbi->State);
  pr = dump_protect_flags (mbi->Protect);
  dump_type (mbi->Type);
  printf ("\n");
  if (pr)
    dump_region (mbi->BaseAddress, mbi->RegionSize);
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
