#pragma once
#include "Windows.h"
typedef BOOL (__stdcall * ProcDllMain)(HINSTANCE, DWORD, LPVOID);
#define GET_HEADER_DICTIONARY(Module, Index)  &(Module)->NtHeaders->OptionalHeader.DataDirectory[Index];

class CMyLoadDll
{
public:
	CMyLoadDll(void);
	~CMyLoadDll(void);
	BOOL IsLoaded();
	BOOL CheckPEFileValidity(const char*	szBufferData, UINT32 iBufferLength);
	UINT32	GetAlignedSize(UINT32	OriginalDataLength, UINT32 Alignment);
	UINT32	CalcTotalImageSize();
	VOID CopyFileDatas(PVOID	DestData, PVOID	 SourData);
	VOID FixBaseRelocTable(PVOID MemoryAddress);
	BOOL FixImportAddressTable(PVOID MemoryAddress);
	BOOL MyLoadLibrary(const char* szBufferData, UINT32 iBufferLength);
	FARPROC MyGetProcAddress(LPCSTR szFunctionName);
	BOOL CMyLoadDll::ExecuteTLS(PVOID MemoryAddress);
	PIMAGE_DOS_HEADER		m_DosHeader;
	PIMAGE_NT_HEADERS		m_NtHeader;
	PIMAGE_SECTION_HEADER	m_SectionHeader;
	ProcDllMain				m_DllMain;
	BOOL					m_bIsLoaded;
	PVOID					m_ImageBase;
};

