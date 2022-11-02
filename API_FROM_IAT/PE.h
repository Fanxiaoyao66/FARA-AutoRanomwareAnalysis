#pragma once
#include<Windows.h>

//32位和64位NT头格式有稍许不一样
//ULONG RvaToOffest32(IMAGE_NT_HEADERS32* pNTHeader, ULONG Rva);
//ULONG RvaToOffest(IMAGE_NT_HEADERS* pNTHeader, ULONG Rva);

PIMAGE_DOS_HEADER FindDosHeader(LPCWCHAR FilePath)
{
	HANDLE hFile;
	HANDLE hFileMap;
	PIMAGE_DOS_HEADER pDosHeader;


	hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == NULL)
	{
		printf("Open file failed! [error code:%u]\n", GetLastError());
		system("pause");
		return 0;
	}

	hFileMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMap == NULL)
	{
		printf("Mapping failed! [error code:%u]\n", GetLastError());
		system("pause");
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (pDosHeader == NULL)
	{
		printf("File map failed! [error code:%u]\n", GetLastError());
		system("pause");
		return 0;
	}
	CloseHandle(hFile);
	CloseHandle(hFileMap);
	return pDosHeader;
}

//32位
ULONG RvaToRaw32(PIMAGE_NT_HEADERS32 pNtHeader, ULONG Rva)
{

	//Section header
	IMAGE_SECTION_HEADER* pSectionHeader;
	ULONG Num, i;

	//获取节表项数目
	Num = pNtHeader->FileHeader.NumberOfSections;

	//获取节表头地址
	pSectionHeader = (PIMAGE_SECTION_HEADER)((byte*)pNtHeader + 0x4 + 0x14 + pNtHeader->FileHeader.SizeOfOptionalHeader);

	for (i = 0; i < Num; i++)
	{
		if (pSectionHeader->VirtualAddress <= Rva && Rva < (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData))
		{
			return Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData; //返回RAW
		}
		pSectionHeader++;
	}
};

//64位
ULONG RvaToRaw64(PIMAGE_NT_HEADERS pNtHeader, ULONG Rva)
{

	//Section header
	IMAGE_SECTION_HEADER* pSectionHeader;
	ULONG Num, i;

	//获取节表项数目
	Num = pNtHeader->FileHeader.NumberOfSections;

	//获取节表头地址
	pSectionHeader = (PIMAGE_SECTION_HEADER)((byte*)pNtHeader + 0x4 + 0x14 + pNtHeader->FileHeader.SizeOfOptionalHeader);

	for (i = 0; i < Num; i++)
	{
		if (pSectionHeader->VirtualAddress <= Rva && Rva < (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData))
		{
			return Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData; //返回RAW
		}
		pSectionHeader++;
	}

};

