#include <stdio.h>
#include <windows.h>

int some_data;
char *str = "test";
int some_more_data = 10;

int
main (int argc, char* argv[])
{
  int a = argc;
  void *p = malloc (128);

  printf ("Code:  %p\n", &main);
  printf ("RO D:  %p\n", str);
  printf ("RW D:  %p\n", &some_more_data);
  printf ("BSS:   %p\n", &some_data);  
  printf ("Stack: %p\n", &a);
  printf ("Heap:  %p\n", p);
  printf ("DLL:   %p\n", GetProcAddress(GetModuleHandle(TEXT("coredll.dll")), 
	TEXT("Sleep")));

  /* Give ssh time to flush buffers.  */
  fflush (stdout);
  Sleep (300);
  return 0;
}
