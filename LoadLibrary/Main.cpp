#include "stdafx.h"
#include "MyLoadDll.h"

typedef void(WINAPI *pfnTestProc)();

CMyLoadDll	g_LoadDll;

int main()
{
	
	//程序首次加载Dll

	const int	iBufferSize = 10240 * 10240;
	int			iBufferLength = 0;

	char*		szBufferData = new char[iBufferSize];
	if (szBufferData == NULL)
	{
		return 0 ;
	}


#ifdef _WIN64
	HANDLE hDll = CreateFile(L..//Debug//x64Testdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
#else
	HANDLE hDll = CreateFile(L"..//Debug//Testdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	//HANDLE hDll = CreateFile(L"..//Debug//360InIShell.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
#endif

	if (hDll)
	{
		if (hDll == INVALID_HANDLE_VALUE)
		{
			printf("打开文件错误：%d\n", GetLastError());
		}
		DWORD dwFileSize = 0;
		DWORD dwRealFileSize = 0;
		dwFileSize = GetFileSize(hDll, NULL);
		if (dwFileSize <= 0)
		{
			printf("获得文件大小失败!\n");
			return -1;
		}
		ReadFile(hDll,szBufferData,dwFileSize,&dwRealFileSize,NULL);

		int b = GetLastError();
		
		if (FALSE == g_LoadDll.MyLoadLibrary(szBufferData, dwRealFileSize))
		{
			delete szBufferData;
			szBufferData = NULL;
			MessageBoxW(NULL,L"加载Dll失败",L"Hello",0);
			return 0;
		}
		pfnTestProc TestProc =  (pfnTestProc)g_LoadDll.MyGetProcAddress("TestProc");
		//pfnTestProc TestProc =  (pfnTestProc)g_LoadDll.MyGetProcAddress("Start");
		if (TestProc)
		{
			TestProc();
		}
		else
		{
			delete szBufferData;
			szBufferData = NULL;
			MessageBoxW(NULL,L"动态库加载失败！",L"Hello",0);
			return 0;
		}
	}
	return 0;
}