#include "stdafx.h"
#include "MyLoadDll.h"
#include "Windows.h"

CMyLoadDll::CMyLoadDll(void)
{
	m_bIsLoaded = FALSE;
	m_ImageBase = NULL;
	m_DosHeader = NULL;
	m_NtHeader  = NULL;
	m_SectionHeader = NULL;
	m_DllMain = NULL;
}


CMyLoadDll::~CMyLoadDll(void)
{
	if(m_bIsLoaded)
	{	
		//�ѹ���׼��ж��dll
		m_DllMain((HINSTANCE)m_ImageBase, DLL_PROCESS_DETACH, 0);
		VirtualFree(m_ImageBase, 0, MEM_RELEASE);
	}
}

BOOL CMyLoadDll::IsLoaded()
{
	return m_bIsLoaded;
}

BOOL CMyLoadDll::CheckPEFileValidity(const char*	szBufferData, UINT32 iBufferLength)
{
	// ��鳤��
	if (iBufferLength < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	//���dosͷ�ı�� MZ
	m_DosHeader = (PIMAGE_DOS_HEADER)szBufferData;
	if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)	// 0x5A4D : MZ
	{
		return FALSE;
	}

	// ��鳤��					Dosͷ��С      +     Ntͷ��С
	if (iBufferLength < (m_DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
	{
		return FALSE;
	}

	// ���peͷ�ĺϷ���
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)szBufferData + m_DosHeader->e_lfanew);		// ȡ��peͷ
	if (m_NtHeader->Signature != IMAGE_NT_SIGNATURE)	// 0x00004550 : PE00
	{
		return FALSE;
	}
	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)		//0x2000  : DLL
	{
		return FALSE;
	}
	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)	//0x0002 : ָ���ļ���������
	{
		return FALSE;
	}
	// ��֤ÿ���ڱ�Ŀռ�
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PUINT8)m_NtHeader + sizeof(IMAGE_NT_HEADERS));	// ȡ�ýڱ��α�
	for (UINT32	i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		//				�ļ���ƫ��				+    �ļ��д�С
		if ((m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData) > (UINT32)iBufferLength)
		{
			return FALSE;
		}
	}
	return TRUE;
}


UINT32	CMyLoadDll::CalcTotalImageSize()
{
	UINT32	Size = 0;
	if (m_NtHeader == NULL)
	{
		return 0;
	}

	UINT32	MemoryAlignment = m_NtHeader->OptionalHeader.SectionAlignment;		// �ζ����ֽ���

	// ��������ͷ�Ĵ�С  ����dos, stub, peͷ �� �ڱ�Ĵ�С
	Size = GetAlignedSize(m_NtHeader->OptionalHeader.SizeOfHeaders, MemoryAlignment);

	// �������нڵĴ�С
	for (UINT32 i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		// �õ��ýڵĴ�С
		UINT32	TrueCodeSize = m_SectionHeader[i].Misc.VirtualSize;		// �ڵ���ʵ��С
		UINT32	FileAlignmentCodeSize = m_SectionHeader[i].SizeOfRawData;	// �ļ������Ĵ�С
		UINT32	MaxSize = (FileAlignmentCodeSize > TrueCodeSize) ? (FileAlignmentCodeSize) : (TrueCodeSize);
		UINT32	SectionSize = GetAlignedSize(m_SectionHeader[i].VirtualAddress + MaxSize, MemoryAlignment);
		if (Size < SectionSize)		// �ҵĲ���---> ������������û���ݣ���SectionSize��С����䣬if��䲻��
		{
			Size = SectionSize;
		}
	}
	return Size;
}

// �������߽�						����ԭ�ȵĳ���				�����
UINT32	CMyLoadDll::GetAlignedSize(UINT32	OriginalDataLength, UINT32 Alignment)
{
	return (OriginalDataLength + Alignment - 1) / Alignment * Alignment;
}

// ��������
VOID CMyLoadDll::CopyFileDatas(PVOID	DestData, PVOID	 SourData)
{
	// ������Ҫ���Ƶ�PEͷ + �α��ֽ���
	UINT32	HeaderSize = m_NtHeader->OptionalHeader.SizeOfHeaders;
	// ����ͷ����Ϣ
	memcpy(DestData, SourData, HeaderSize);
	// ����ÿ����
	for (UINT32 i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		if (m_SectionHeader[i].VirtualAddress == 0 || m_SectionHeader[i].SizeOfRawData == 0)	// �ڿ�����û������
		{
			continue;
		}
		// ��λ�ýڿ����ڴ��е�λ��
		PVOID	SectionMemoryAddress = (PVOID)((PUINT8)DestData + m_SectionHeader[i].VirtualAddress);
		// ���ƽڿ����ݵ������ڴ�
		memcpy(SectionMemoryAddress, (PVOID)((PUINT8)SourData + m_SectionHeader[i].PointerToRawData), m_SectionHeader[i].SizeOfRawData);
	}

	// ����ָ�룬ָ���·�����ڴ�
	// �µ�Dosͷ
	m_DosHeader = (PIMAGE_DOS_HEADER)DestData;
	// �µ�PEͷ
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)DestData + m_DosHeader->e_lfanew);
	// �µĽڱ�
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PUINT8)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
	// ��ʵûɶ�任���ǣ�ǰ����Щͷ�Ķ��뻹�ǲ��䣬����Ǻ���Ľڿ�
}

// �����ض����
VOID CMyLoadDll::FixBaseRelocTable(PVOID MemoryAddress)
{
	// ���������ض��������Ϊ����������Ԥ���IMAGEBASE �� 0x40������ʵ���ϵĳ���װ�ڵ�ַ����0x40������ 0x50�Ļ���ԭ���ض��������ĵ�12λ�����ŵ�ƫ��ȫҪҪ���� 0x50-0x40

	PIMAGE_BASE_RELOCATION	BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)MemoryAddress + m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock != 0)
	{
		PUINT16	RelocationData = (PUINT16)((PUINT8)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		// ������Ҫ�������ض���λ�����Ŀ
		UINT32	NumberOfRelocations = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (UINT32	i = 0; i < NumberOfRelocations; i ++)
		{
			// ÿ��WORD�����������
			// ��4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ
			// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ��
			if ((UINT32)(RelocationData[i] & 0x0000F000) == 0x0000A000)
			{
				// 64λdll�ض�λ��IMAGE_REL_BASED_DIR64
				// ����IA-64�Ŀ�ִ���ļ����ض�λһ����IMAGE_REL_BASED_DIR64���͵�
#ifdef _WIN64
				PUINT64	Address = (PUINT64)((PUINT8)MemoryAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x00000FFF));
				UINT64	Delta	= (UINT64)MemoryAddress - m_NtHeader->OptionalHeader.ImageBase;
				*Address += Delta;
#endif
			}
			else if ((UINT32)(RelocationData[i] & 0x0000F000) == 0x00003000)
			{
				// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
				// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�
#ifndef _WIN64
				PUINT32	Address = (PUINT32)((PUINT8)MemoryAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x00000FFF));
				UINT32	Delta	= (UINT32)MemoryAddress - m_NtHeader->OptionalHeader.ImageBase;
				*Address += Delta;
#endif
			}
		}
		// ת����һ���ض����
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((PUINT8)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
}

// ������ַ�����
BOOL CMyLoadDll::FixImportAddressTable(PVOID MemoryAddress)
{
	UINT64	ImportTableRVA = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (0 == ImportTableRVA)
	{
		return TRUE;	// �޵����
	}

	PIMAGE_IMPORT_DESCRIPTOR	ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)MemoryAddress + ImportTableRVA);
	while (ImageImportDescriptor->Characteristics != 0)  //0˵�������һ��Ԫ��
	{
		PIMAGE_THUNK_DATA	FirstThunkData = (PIMAGE_THUNK_DATA)((PUINT8)MemoryAddress + ImageImportDescriptor->FirstThunk); //ָ��iat��rva
		PIMAGE_THUNK_DATA	OriginalThunkData = (PIMAGE_THUNK_DATA)((PUINT8)MemoryAddress + ImageImportDescriptor->OriginalFirstThunk);

		// ��ȡ����ģ������
		char	szModuleName[MAX_PATH] = {0};
		PUINT8	ModuleName = (PUINT8)((PUINT8)MemoryAddress + ImageImportDescriptor->Name);
		UINT32	i = 0;
		for (i = 0; i < MAX_PATH; i ++)
		{
			if (ModuleName[i] == 0)
			{
				break;
			}
			szModuleName[i] = ModuleName[i];
		}
		if (i >= MAX_PATH)
		{
			return FALSE;
		}
		else
		{
			szModuleName[i] = 0;
		}
		HMODULE	hModule = GetModuleHandleA(szModuleName);
		if (NULL == hModule)
		{
			return FALSE;
		}
		i = 0;
		while (TRUE)
		{
			if (OriginalThunkData[i].u1.Function == 0)  //˵�������һ��
			{
				break;
			}

			FARPROC	FunctionAddress = NULL;

			if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)	// ����ŵ��� ���λΪ 1 
			{
				FunctionAddress = ::GetProcAddress(hModule, (LPSTR)(OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG));		// ��ȥ���λ��Ϊ���
			}
			else		// �����ֵ���
			{
				// ��ú�������
				PIMAGE_IMPORT_BY_NAME	ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)MemoryAddress + (OriginalThunkData[i].u1.AddressOfData));
				FunctionAddress = ::GetProcAddress(hModule, (LPSTR)ImageImportByName->Name);
			}
			if (NULL != FunctionAddress)
			{
#ifdef _WIN64
				FirstThunkData[i].u1.Function = (UINT64)FunctionAddress;
#else
				FirstThunkData[i].u1.Function = (UINT32)FunctionAddress;
#endif
			}
			else
			{
				return FALSE;
			}
			i ++;
		}
		// �ƶ�����һ������ģ��
		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)ImageImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return TRUE;
}

BOOL CMyLoadDll::MyLoadLibrary(const char* szBufferData, UINT32 BufferLength)
{

	//���������Ч�ԣ�����ʼ��
	if (FALSE == CheckPEFileValidity(szBufferData, BufferLength))
	{
		return FALSE;
	}

	// ��������ļ��ؿռ�
	UINT32	ImageSize = CalcTotalImageSize();  //���ֵ��sizeofimageһ��

	// ���������ڴ�												������ҳ�����
	char*	MemoryAddress = (char*)VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == MemoryAddress)
	{
		return FALSE;
	}
	else
	{
		CopyFileDatas(MemoryAddress, (PVOID)szBufferData);

		// �޸��ض����
		if (m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			FixBaseRelocTable(MemoryAddress);
		}

		// ���������(��ַ����IAT)
		if (FALSE == FixImportAddressTable(MemoryAddress))
		{
			VirtualFree(MemoryAddress, 0, MEM_RELEASE);		// �ж�������ҳ��Ĺ���
		}

		if (!ExecuteTLS(MemoryAddress))
		{
			return FALSE;
		}

		// �޸�ҳ������
		UINT32	OldProtect;

		VirtualProtect(MemoryAddress, BufferLength, PAGE_EXECUTE_READWRITE, (PDWORD)&OldProtect);
	}

	// ��������ַ
#ifdef _WIN64
	m_NtHeader->OptionalHeader.ImageBase = (UINT64)MemoryAddress;
#else
	m_NtHeader->OptionalHeader.ImageBase = (UINT32)MemoryAddress;
#endif

	// ������Ҫ����dll����ں���������ʼ������(����Ҫ)
	m_DllMain = (ProcDllMain)((PUINT8)MemoryAddress + m_NtHeader->OptionalHeader.AddressOfEntryPoint);

	BOOL bInitResult = m_DllMain((HINSTANCE)MemoryAddress, DLL_PROCESS_ATTACH, 0);
	if (FALSE == bInitResult)
	{
		m_DllMain((HINSTANCE)MemoryAddress, DLL_PROCESS_DETACH, 0);
		VirtualFree(MemoryAddress, 0, MEM_RELEASE);
		m_DllMain = NULL;
		return FALSE;
	}

	m_bIsLoaded = TRUE;
	m_ImageBase	= MemoryAddress;

	return TRUE;
}

FARPROC CMyLoadDll::MyGetProcAddress(LPCSTR szFunctionName)
{

	if (m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
		m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
	{
		return NULL;
	}
	if (FALSE == m_bIsLoaded)
	{
		return NULL;
	}

	UINT32	ExportTableRVA = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	UINT32	ExportTableSize = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PIMAGE_EXPORT_DIRECTORY	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)m_ImageBase + ExportTableRVA);
	UINT32	Base = ImageExportDirectory->Base;
	UINT32	NumberOfFunctions = ImageExportDirectory->NumberOfFunctions;
	UINT32	NumberOfNames = ImageExportDirectory->NumberOfNames;
	PUINT32	AddressOfFunctions = (PUINT32)((PUINT8)m_ImageBase + ImageExportDirectory->AddressOfFunctions);
	PUINT16	AddressOfNameOrdinals = (PUINT16)((PUINT8)m_ImageBase + ImageExportDirectory->AddressOfNameOrdinals);		// �ر�ע�������� 16λ-- 2�ֽڣ���Ϊ���ֻ��2�ֽ�
	PUINT32	AddressOfNames = (PUINT32)((PUINT8)m_ImageBase + ImageExportDirectory->AddressOfNames);

	int iOrdinal = -1;
	if (((UINT32)szFunctionName & 0xFFFF0000) == 0)		// ��ŵ���
	{
		iOrdinal = (UINT32)szFunctionName & ~0xFFFF0000 - Base;
	}
	else		// ���Ƶ���
	{
		int iFound = -1;
		for (UINT32 i = 0; i < NumberOfNames; i ++)
		{
			char*	szName = (char*)(AddressOfNames[i] + (PUINT8)m_ImageBase);
			if (strcmp(szName, szFunctionName) == 0)		// ��������Ա�
			{
				iFound = i;
				break;
			}
		}
		if (iFound >= 0)
		{
			iOrdinal = (int)(AddressOfNameOrdinals[iFound]);	// ͨ�����Ƶ������ҵ�������ڶ�Ӧ��������ŵ��������ҵ��ں����������е����
		}
	}

	if (iOrdinal < 0 || iOrdinal >= NumberOfFunctions)
	{
		return NULL;
	}
	else
	{
		UINT32	FunctionOffset = AddressOfFunctions[iOrdinal];
		if (FunctionOffset > ExportTableRVA && FunctionOffset < (ExportTableRVA + ExportTableSize))
		{
			return NULL;
		}
		else
		{
			return (FARPROC)(FunctionOffset + (PUINT8)m_ImageBase);
		}
	}

}



//ִ��TLS�ص�����
BOOL CMyLoadDll::ExecuteTLS(PVOID MemoryAddress)
{
	PIMAGE_TLS_CALLBACK* CallBack;
	PIMAGE_TLS_DIRECTORY TLSDirectory;
	UINT64 DirectoryRVA = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	if (DirectoryRVA == 0)
	{
		return TRUE;
	}

	TLSDirectory = (PIMAGE_TLS_DIRECTORY)((PUINT8)MemoryAddress + DirectoryRVA);
	CallBack = (PIMAGE_TLS_CALLBACK *)TLSDirectory->AddressOfCallBacks;
	if (CallBack)
	{
		while (*CallBack)
		{
			//�����̿�ʼʱִ��
			(*CallBack)((LPVOID)MemoryAddress, DLL_PROCESS_ATTACH, NULL);
			CallBack++;
		}
	}
	return TRUE;
}