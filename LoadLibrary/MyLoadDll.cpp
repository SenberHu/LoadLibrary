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
		//脱钩，准备卸载dll
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
	// 检查长度
	if (iBufferLength < sizeof(IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	//检查dos头的标记 MZ
	m_DosHeader = (PIMAGE_DOS_HEADER)szBufferData;
	if (m_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)	// 0x5A4D : MZ
	{
		return FALSE;
	}

	// 检查长度					Dos头大小      +     Nt头大小
	if (iBufferLength < (m_DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
	{
		return FALSE;
	}

	// 检查pe头的合法性
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)szBufferData + m_DosHeader->e_lfanew);		// 取得pe头
	if (m_NtHeader->Signature != IMAGE_NT_SIGNATURE)	// 0x00004550 : PE00
	{
		return FALSE;
	}
	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)		//0x2000  : DLL
	{
		return FALSE;
	}
	if ((m_NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)	//0x0002 : 指出文件可以运行
	{
		return FALSE;
	}
	// 验证每个节表的空间
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PUINT8)m_NtHeader + sizeof(IMAGE_NT_HEADERS));	// 取得节表（段表）
	for (UINT32	i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		//				文件中偏移				+    文件中大小
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

	UINT32	MemoryAlignment = m_NtHeader->OptionalHeader.SectionAlignment;		// 段对齐字节数

	// 计算所有头的大小  包括dos, stub, pe头 和 节表的大小
	Size = GetAlignedSize(m_NtHeader->OptionalHeader.SizeOfHeaders, MemoryAlignment);

	// 计算所有节的大小
	for (UINT32 i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		// 得到该节的大小
		UINT32	TrueCodeSize = m_SectionHeader[i].Misc.VirtualSize;		// 节的真实大小
		UINT32	FileAlignmentCodeSize = m_SectionHeader[i].SizeOfRawData;	// 文件对其后的大小
		UINT32	MaxSize = (FileAlignmentCodeSize > TrueCodeSize) ? (FileAlignmentCodeSize) : (TrueCodeSize);
		UINT32	SectionSize = GetAlignedSize(m_SectionHeader[i].VirtualAddress + MaxSize, MemoryAlignment);
		if (Size < SectionSize)		// 我的猜想---> 如果这个节里面没数据，则SectionSize大小不会变，if语句不进
		{
			Size = SectionSize;
		}
	}
	return Size;
}

// 计算对齐边界						数据原先的长度				对齐度
UINT32	CMyLoadDll::GetAlignedSize(UINT32	OriginalDataLength, UINT32 Alignment)
{
	return (OriginalDataLength + Alignment - 1) / Alignment * Alignment;
}

// 拷贝数据
VOID CMyLoadDll::CopyFileDatas(PVOID	DestData, PVOID	 SourData)
{
	// 计算需要复制的PE头 + 段表字节数
	UINT32	HeaderSize = m_NtHeader->OptionalHeader.SizeOfHeaders;
	// 拷贝头的信息
	memcpy(DestData, SourData, HeaderSize);
	// 复制每个节
	for (UINT32 i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i ++)
	{
		if (m_SectionHeader[i].VirtualAddress == 0 || m_SectionHeader[i].SizeOfRawData == 0)	// 节块里面没有数据
		{
			continue;
		}
		// 定位该节块在内存中的位置
		PVOID	SectionMemoryAddress = (PVOID)((PUINT8)DestData + m_SectionHeader[i].VirtualAddress);
		// 复制节块数据到虚拟内存
		memcpy(SectionMemoryAddress, (PVOID)((PUINT8)SourData + m_SectionHeader[i].PointerToRawData), m_SectionHeader[i].SizeOfRawData);
	}

	// 修正指针，指向新分配的内存
	// 新的Dos头
	m_DosHeader = (PIMAGE_DOS_HEADER)DestData;
	// 新的PE头
	m_NtHeader = (PIMAGE_NT_HEADERS)((PUINT8)DestData + m_DosHeader->e_lfanew);
	// 新的节表
	m_SectionHeader = (PIMAGE_SECTION_HEADER)((PUINT8)m_NtHeader + sizeof(IMAGE_NT_HEADERS));
	// 其实没啥变换就是，前面这些头的对齐还是不变，变得是后面的节块
}

// 修正重定向表
VOID CMyLoadDll::FixBaseRelocTable(PVOID MemoryAddress)
{
	// 这里修正重定向表是因为：假设我们预想的IMAGEBASE 是 0x40，但是实际上的程序装在地址不是0x40，而是 0x50的话，原先重定向块里面的低12位里面存放的偏移全要要加上 0x50-0x40

	PIMAGE_BASE_RELOCATION	BaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)MemoryAddress + m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (BaseRelocation->VirtualAddress + BaseRelocation->SizeOfBlock != 0)
	{
		PUINT16	RelocationData = (PUINT16)((PUINT8)BaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
		// 计算需要修正的重定向位项的数目
		UINT32	NumberOfRelocations = (BaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (UINT32	i = 0; i < NumberOfRelocations; i ++)
		{
			// 每个WORD由两部分组成
			// 高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值
			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置
			if ((UINT32)(RelocationData[i] & 0x0000F000) == 0x0000A000)
			{
				// 64位dll重定位，IMAGE_REL_BASED_DIR64
				// 对于IA-64的可执行文件，重定位一般是IMAGE_REL_BASED_DIR64类型的
#ifdef _WIN64
				PUINT64	Address = (PUINT64)((PUINT8)MemoryAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x00000FFF));
				UINT64	Delta	= (UINT64)MemoryAddress - m_NtHeader->OptionalHeader.ImageBase;
				*Address += Delta;
#endif
			}
			else if ((UINT32)(RelocationData[i] & 0x0000F000) == 0x00003000)
			{
				// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
				// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
#ifndef _WIN64
				PUINT32	Address = (PUINT32)((PUINT8)MemoryAddress + BaseRelocation->VirtualAddress + (RelocationData[i] & 0x00000FFF));
				UINT32	Delta	= (UINT32)MemoryAddress - m_NtHeader->OptionalHeader.ImageBase;
				*Address += Delta;
#endif
			}
		}
		// 转到下一张重定向表
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((PUINT8)BaseRelocation + BaseRelocation->SizeOfBlock);
	}
}

// 修正地址导入表
BOOL CMyLoadDll::FixImportAddressTable(PVOID MemoryAddress)
{
	UINT64	ImportTableRVA = m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (0 == ImportTableRVA)
	{
		return TRUE;	// 无导入表
	}

	PIMAGE_IMPORT_DESCRIPTOR	ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)MemoryAddress + ImportTableRVA);
	while (ImageImportDescriptor->Characteristics != 0)  //0说明是最后一个元素
	{
		PIMAGE_THUNK_DATA	FirstThunkData = (PIMAGE_THUNK_DATA)((PUINT8)MemoryAddress + ImageImportDescriptor->FirstThunk); //指向iat的rva
		PIMAGE_THUNK_DATA	OriginalThunkData = (PIMAGE_THUNK_DATA)((PUINT8)MemoryAddress + ImageImportDescriptor->OriginalFirstThunk);

		// 获取导入模块名称
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
			if (OriginalThunkData[i].u1.Function == 0)  //说明是最后一个
			{
				break;
			}

			FARPROC	FunctionAddress = NULL;

			if (OriginalThunkData[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)	// 按序号导出 最高位为 1 
			{
				FunctionAddress = ::GetProcAddress(hModule, (LPSTR)(OriginalThunkData[i].u1.Ordinal & ~IMAGE_ORDINAL_FLAG));		// 除去最高位即为序号
			}
			else		// 按名字导出
			{
				// 获得函数名称
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
		// 移动到下一个导入模块
		ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)ImageImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}
	return TRUE;
}

BOOL CMyLoadDll::MyLoadLibrary(const char* szBufferData, UINT32 BufferLength)
{

	//检查数据有效性，并初始化
	if (FALSE == CheckPEFileValidity(szBufferData, BufferLength))
	{
		return FALSE;
	}

	// 计算所需的加载空间
	UINT32	ImageSize = CalcTotalImageSize();  //这个值和sizeofimage一样

	// 分配虚拟内存												与物理页面关联
	char*	MemoryAddress = (char*)VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == MemoryAddress)
	{
		return FALSE;
	}
	else
	{
		CopyFileDatas(MemoryAddress, (PVOID)szBufferData);

		// 修复重定向表
		if (m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& m_NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			FixBaseRelocTable(MemoryAddress);
		}

		// 修正导入表(地址导入IAT)
		if (FALSE == FixImportAddressTable(MemoryAddress))
		{
			VirtualFree(MemoryAddress, 0, MEM_RELEASE);		// 切断与物理页面的关联
		}

		if (!ExecuteTLS(MemoryAddress))
		{
			return FALSE;
		}

		// 修改页面属性
		UINT32	OldProtect;

		VirtualProtect(MemoryAddress, BufferLength, PAGE_EXECUTE_READWRITE, (PDWORD)&OldProtect);
	}

	// 修正基地址
#ifdef _WIN64
	m_NtHeader->OptionalHeader.ImageBase = (UINT64)MemoryAddress;
#else
	m_NtHeader->OptionalHeader.ImageBase = (UINT32)MemoryAddress;
#endif

	// 接下来要调用dll的入口函数，做初始化工作(必须要)
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
	PUINT16	AddressOfNameOrdinals = (PUINT16)((PUINT8)m_ImageBase + ImageExportDirectory->AddressOfNameOrdinals);		// 特别注意这里是 16位-- 2字节，因为序号只有2字节
	PUINT32	AddressOfNames = (PUINT32)((PUINT8)m_ImageBase + ImageExportDirectory->AddressOfNames);

	int iOrdinal = -1;
	if (((UINT32)szFunctionName & 0xFFFF0000) == 0)		// 序号导出
	{
		iOrdinal = (UINT32)szFunctionName & ~0xFFFF0000 - Base;
	}
	else		// 名称导出
	{
		int iFound = -1;
		for (UINT32 i = 0; i < NumberOfNames; i ++)
		{
			char*	szName = (char*)(AddressOfNames[i] + (PUINT8)m_ImageBase);
			if (strcmp(szName, szFunctionName) == 0)		// 逐个搜索对比
			{
				iFound = i;
				break;
			}
		}
		if (iFound >= 0)
		{
			iOrdinal = (int)(AddressOfNameOrdinals[iFound]);	// 通过名称导出表找到的序号在对应的名称序号导出表里找到在函数导出表中的序号
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



//执行TLS回调函数
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
			//当进程开始时执行
			(*CallBack)((LPVOID)MemoryAddress, DLL_PROCESS_ATTACH, NULL);
			CallBack++;
		}
	}
	return TRUE;
}