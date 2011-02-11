#include <windows.h>
#include <aygshell.h>
#include "himemce.h"

const wchar_t *szTitle = L"Kontact Touch";		// title bar text
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

bool endswith(const wchar_t *source, const wchar_t *endstr) {
    size_t sourceLen;
    size_t endstrLen;
    wchar_t *startEnd;
    sourceLen = wcslen(source);
    endstrLen = wcslen(endstr);
    if (sourceLen < endstrLen) {
        return false;
    }
    startEnd = (wchar_t *)(source + (sourceLen - endstrLen));
    if (wcscmp(startEnd, endstr) == 0) {
        return true;
    }
    return false;
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

#ifdef USE_LOADER
    c = L'-';
#else
    c = L'.';
#endif

    p = wcsrchr(filename, c);
    if (! p ) {
        TRACE("File extension .exe could not be found\n");
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

    // Show splashscreen
	hwnd = FindWindow(szWindowClass, szTitle);	
  if (hwnd) { 
    ::ShowWindow( hwnd, SW_SHOW );
    SetForegroundWindow( hwnd );
    SHFullScreen(hwnd, SHFS_HIDETASKBAR | SHFS_HIDESTARTICON | SHFS_HIDESIPBUTTON);
	}
  
  //Call the loaders main function
  return main(0,NULL);
}
