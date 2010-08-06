#include <windows.h>

int
main (int argc, char *argv[])
{
  int asize = 1024*1024*1024;
  int total_high = 0;
  int total_low = 0;

  printf ("Trying size 0x%08x\n", asize);

  while (asize >= 4096)
    {
      void *ptr;

      ptr = VirtualAlloc (NULL, asize, MEM_RESERVE, PAGE_NOACCESS);
      if (ptr != NULL)
	{
	  printf ("Allocated region of size 0x%08x at 0x%p\n", asize, ptr);
	  if (ptr >= (void*)0x40000000)
	    total_high += asize;
	  else
	    total_low += asize;
	}
      else
	{
	  asize /= 2;
	  printf ("Trying size 0x%08x\n", asize);
	}
    }
  printf ("Total High: 0x%08x\n", total_high);
  printf ("Total Low:  0x%08x\n", total_low);
  Sleep (300);
 
  return 0;
}
