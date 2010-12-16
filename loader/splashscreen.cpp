#include <windows.h>
#include <aygshell.h>
#include "himemce.h"

// Global Bitmap variable
HBITMAP hbm;

const wchar_t *szTitle = L"Kontact Mobile";		// title bar text
const wchar_t *szWindowClass = L"SplashScreen";	// main window class name

//Prototype of the main function from the loader
int main (int argc, char *argv[]);

//This functions rotates the screen by 270 degrees
BOOL RotateTo270Degrees()
{
	DEVMODE DevMode;
	memset(&DevMode, 0, sizeof (DevMode));
	DevMode.dmSize               = sizeof (DevMode);
	DevMode.dmFields             = DM_DISPLAYORIENTATION;
	DevMode.dmDisplayOrientation = DMDO_270;
	if (DISP_CHANGE_SUCCESSFUL != ChangeDisplaySettingsEx(NULL, &DevMode, NULL, 0, NULL)){
	  //error cannot change to 270 degrees
	  printf("failed to rotate!\n");
	  return false;
	}
   return true;
}

// Load Splashscreen from resource dll
BOOL onCreate(
   HWND hwnd)
{
  // Load Splashscreen dll
  HINSTANCE hinst = LoadLibrary(L"splashscreen.dll");

	if (!hinst) {
		printf("failed to load splashscreen dll!\n");
		return false;
	}
  hbm = LoadBitmap(hinst,MAKEINTRESOURCE(101));
  
  return true;
}

// Clean up
void onDestroy(
  HWND hwnd)
{
  DeleteObject(hbm);
  
  PostQuitMessage(0);
}

void onPaint(
  HWND hwnd)
{
  PAINTSTRUCT ps;
  HDC hdc = BeginPaint(hwnd,&ps);
  
  HDC hdcMem = CreateCompatibleDC(NULL);
  SelectObject(hdcMem, hbm);

  BITMAP bm;
  GetObject(hbm,sizeof(bm),&bm);
  
  BitBlt(hdc,0,0,bm.bmWidth,bm.bmHeight,hdcMem,0,0,SRCCOPY);

  DeleteDC(hdcMem);
  
  EndPaint(hwnd,&ps);
}  


LRESULT CALLBACK windowProc(
  HWND hwnd,
  UINT uMsg,
  WPARAM wParam,
  LPARAM lParam)
{
  switch(uMsg)
  {
  case WM_CREATE:
    onCreate(hwnd);
    break;
  case WM_DESTROY:
    onDestroy(hwnd);
    break;
  case WM_PAINT:
	  onPaint(hwnd);
	  break;
  case WM_SETTINGCHANGE:
    RotateTo270Degrees();
    break;
  }
  return DefWindowProc(hwnd,uMsg,wParam,lParam);
}  

/* Restore a Window of a process based on the filename
 * of this process. With some special Case handling for
 * Kontact-Mobile
 * Returns false if the window can not be found */
bool
restore_existing_window( const wchar_t * filename )
{
    HWND windowID = NULL;
    wchar_t * basename;
    wchar_t * p;
    wchar_t c;

    if (! filename ) {
        TRACE("check_window_exists called with NULL");
        return false;
    }
    c = L'\\';
    basename = wcsrchr(filename, c) + 1;
    if (! basename) {
        TRACE("Basename not found\n");
        return false;
    }
    TRACE("BASENAME of %S \n is : %S \n", filename, basename);

    c = L'-';

    p = wcsrchr(filename, c);
    if (! p ) {
        TRACE("File extension -real.exe could not be found\n");
        return false;
    }
    *p = L'\0';

    TRACE("Searching for Window: %S \n", basename);
    windowID = FindWindow( NULL, basename);
    if (windowID)
    {
        wchar_t classname[255];
        //Find the general top level Window and bring to front
        SetForegroundWindow((HWND)(((ULONG)windowID) | 0x01 ));
        // Check for subwindows that should be laid on top of that
        if ( ! GetClassName(windowID, classname, 255) ) {
            TRACE("No class name found for window\n");
            return true;
        }
        TRACE("Classname for window is: %S", classname);
        windowID =  FindWindow(classname, L"Neue E-Mail");
        if (windowID) {
            TRACE ("Subwindow Neue E-Mail found\n");
            SetForegroundWindow((HWND)(((ULONG)windowID) | 0x01 ));
        }
        if (windowID = FindWindow(classname, L"New E-Mail")) {
            TRACE ("Subwindow New E-Mail found\n");
            SetForegroundWindow((HWND)(((ULONG)windowID) | 0x01 ));
        }
        return true;
    }

    return false;
}

void registerClass(
  HINSTANCE hInstance)
{
  WNDCLASS wc = {
    CS_NOCLOSE,
    windowProc,
    0,0,
    hInstance,
    NULL,
    NULL,
    (HBRUSH) GetStockObject(WHITE_BRUSH),
    NULL,
    szWindowClass
  };
  RegisterClass(&wc);
}

int WINAPI WinMain(
  HINSTANCE hInstance,
  HINSTANCE hInstPrev,
  LPTSTR lpszCmdLine,
  int nCmdShow)
{
    HWND hwnd;
    RotateTo270Degrees();
    WCHAR *app_name;

    app_name = get_app_name ();

    if (restore_existing_window(app_name)) {
        return 0;
    }

    // If the splashscreen window is already loaded just show it
	hwnd = FindWindow(szWindowClass, szTitle);	
  if (hwnd) { 
    ::ShowWindow( hwnd, SW_SHOW );
    SetForegroundWindow( hwnd );
    SHFullScreen(hwnd, SHFS_HIDETASKBAR | SHFS_HIDESTARTICON | SHFS_HIDESIPBUTTON);
	} else {
	  registerClass(hInstance);
	  
	  hwnd = CreateWindow(szWindowClass, szTitle, WS_VISIBLE,
			0, 0, 0, 0, NULL, NULL, hInstance, NULL);
      
    SHFullScreen(hwnd, SHFS_HIDETASKBAR | SHFS_HIDESTARTICON | SHFS_HIDESIPBUTTON);

    RECT rc;
    // Next resize the main window to the size of the screen.
    SetRect(&rc, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    MoveWindow(hwnd, rc.left, rc.top, rc.right-rc.left, rc.bottom-rc.top, TRUE);

    SetForegroundWindow(hwnd);

	  ShowWindow(hwnd,nCmdShow);
	  UpdateWindow(hwnd);
	}
  
  //Call the loaders main function
  return main(0,NULL);
}
