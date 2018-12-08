// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
#ifdef _WIN64
#pragma comment(linker,"/INCLUDE:_tls_used")
#else
#pragma comment(linker,"/INCLUDE:__tls_used")
#endif // _WIN64


void NTAPI MY_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved);
void NTAPI MY_TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved);


extern "C" __declspec(dllexport) void TestProc()
{
	MessageBox(NULL, L"Test Proc!",L"Hello", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			MessageBox(NULL, L"Load!", L"Hello", MB_OK);
			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		{
			MessageBox(NULL, L"UnLoad!", L"Hello", MB_OK);
			break;
		}
		break;
	}
	return TRUE;
}

//TLS�ص���������
void NTAPI MY_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		MessageBox(NULL, L"TLSTest!", L"Hello", MB_OK);
	}
}
void NTAPI MY_TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		MessageBox(NULL, L"TLSTest--1!", L"Hello", MB_OK);
	}
}

/*
    ע��TLS����
    .CRT$XLX������
    CRT��ʾʹ��C Runtime ����
    X��ʾ��ʾ�����
    L��ʾTLS Callback section
    XҲ���Ի���B~Y����һ���ַ�
*/

extern "C"
#ifdef _WIN64
#pragma const_seg(".CRT$XLX")
const
#else
#pragma data_seg(".CRT$XLX")
#endif
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { MY_TLS_CALLBACK,MY_TLS_CALLBACK1,0 };
#pragma data_seg()
#pragma const_seg()