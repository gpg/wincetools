#include <windows.h>
#include <aygshell.h>

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

  // If the splashscreen window is already loaded just show it
	hwnd = FindWindow(szWindowClass, szTitle);	
  if (hwnd) {
        SetForegroundWindow((HWND)((ULONG) hwnd | 0x00000001));
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