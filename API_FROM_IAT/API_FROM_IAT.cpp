#include<Windows.h>
#include<stdio.h>
#include<tchar.h>
#include<PE.h>
#include<shellapi.h>

int main(int argc, TCHAR** arv)
{
	if (argc < 2)
	{
		printf("请至少输入一个参数！");
		system("pause");
		return 0;
	}

	int num;
	PIMAGE_DOS_HEADER pRanDosHeader;
	PIMAGE_NT_HEADERS pRanNtHeader;
	PIMAGE_NT_HEADERS32 pRanNtHeader32;
	HANDLE hNewFile;
	PUCHAR pDllStr;
	PCHAR pApiStr;
	DWORD FileBytes;
	wchar_t* FileName;
	TCHAR* pFileType = L"txt";

	//读取Unicode参数
	LPCWCHAR* ArgList = (LPCWCHAR*)CommandLineToArgvW(GetCommandLineW(),&num);
	if (ArgList[1] == 0)
	{
		printf("Please input file path!");
		system("pause");
		return 0;
	}

	//定位到文件基址
	pRanDosHeader = FindDosHeader(ArgList[1]);
	if (pRanDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("%ls 不是一个PE文件！", ArgList[1]);
		system("pause");
		return 0;
	}

	//写入文件 的绝对路径，如果直接在ArgList[1]更改会报堆损坏异常
	FileName = (wchar_t*)malloc(1000);
	_tcscpy_s(FileName, _MAX_PATH, ArgList[1]);
	wchar_t* p = wcsrchr(FileName, '.');
	_tcscpy_s((wchar_t*)p + 1,_MAX_PATH,pFileType);

	//定位到NT头
	pRanNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pRanDosHeader + pRanDosHeader->e_lfanew);
	
	//判断文件位数
	if (pRanNtHeader->OptionalHeader.Magic == 0x10B) //32位
	{
		pRanNtHeader32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pRanDosHeader + pRanDosHeader->e_lfanew);

		//定位到ImportTable
		ULONG RvaImportTable = pRanNtHeader32->OptionalHeader.DataDirectory[1].VirtualAddress;

		//定位到IID
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw32(pRanNtHeader32, RvaImportTable) + (PUCHAR)pRanDosHeader);

		//新建文件夹存入数据
		hNewFile = CreateFileW(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
		if (hNewFile == 0)
		{
			printf("Create File failed！[error code:%u]", GetLastError());
			system("pause");
			return 0;
		}

		for (; pImportDescriptor->OriginalFirstThunk; pImportDescriptor++)
		{
			pDllStr = RvaToRaw32(pRanNtHeader32, pImportDescriptor->Name) + (PUCHAR)pRanDosHeader;
			printf("Dll name:%s\n", pDllStr);
			printf("-------------\n");

			//写入数据
			WriteFile(hNewFile, pDllStr, strlen((char*)pDllStr), &FileBytes, NULL);
			WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);

			//定位到IAT
			PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(RvaToRaw32(pRanNtHeader32, pImportDescriptor->OriginalFirstThunk) + (PUCHAR)pRanDosHeader);

			//输出每一个Api名
			while (pINT->u1.AddressOfData)
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToRaw32(pRanNtHeader32, pINT->u1.AddressOfData) + (PUCHAR)pRanDosHeader);
				pApiStr = pIBN->Name;
				printf("Api name:%s\n", pApiStr);

				//写入Api
				WriteFile(hNewFile, pApiStr, strlen((char*)pApiStr), &FileBytes, NULL);
				WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);

				pINT++;
			}
			printf("---------------------------------------------------------------\n");
			WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);
		}
		
		LocalFree(ArgList);
		free(FileName);
		CloseHandle(hNewFile);
		return 0;
	}

	if (pRanNtHeader->OptionalHeader.Magic == 0x20B) //64位
	{
		//pRanNtHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)pRanDosHeader + pRanDosHeader->e_lfanew);

		//定位到ImportTable
		ULONG RvaImportTable = pRanNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;

		//定位到IID
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw64(pRanNtHeader, RvaImportTable) + (PUCHAR)pRanDosHeader);

		//新建文件夹存入数据
		hNewFile = CreateFileW(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
		if (hNewFile == 0)
		{
			printf("Create File failed！[error code:%u]", GetLastError());
			system("pause");
			return 0;
		}

		for (; pImportDescriptor->OriginalFirstThunk; pImportDescriptor++)
		{
			pDllStr = RvaToRaw64(pRanNtHeader, pImportDescriptor->Name) + (PUCHAR)pRanDosHeader;
			printf("Dll name:%s\n", pDllStr);
			printf("-------------\n");

			//写入数据
			WriteFile(hNewFile, pDllStr, strlen((char*)pDllStr), &FileBytes, NULL);
			WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);

			//定位到IAT
			PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(RvaToRaw64(pRanNtHeader, pImportDescriptor->OriginalFirstThunk) + (PUCHAR)pRanDosHeader);

			//输出每一个Api名
			while (pINT->u1.AddressOfData)
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToRaw64(pRanNtHeader, pINT->u1.AddressOfData) + (PUCHAR)pRanDosHeader);
				pApiStr = pIBN->Name;
				printf("Api name:%s\n", pApiStr);

				//写入Api
				WriteFile(hNewFile, pApiStr, strlen((char*)pApiStr), &FileBytes, NULL);
				WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);

				pINT++;
			}
			printf("---------------------------------------------------------------\n");
			WriteFile(hNewFile, "\n", 1, &FileBytes, NULL);
		}

		LocalFree(ArgList);
		free(FileName);
		CloseHandle(hNewFile);
		return 0;
	}

	LocalFree(ArgList);
	free(FileName);
	return 0;
}



/* int main() {

	TCHAR file[] = L"C:\\Users\\F4nx1a0y40\\Desktop\\notepad.exe";

	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS32 pImageNtHeader;
	PIMAGE_FILE_HEADER pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader;
	HANDLE hFile = 0;
	HANDLE hMapObject;
	PUCHAR uFileMap;

	hFile = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == NULL)
	{
		printf("Open file failed! %u\n", GetLastError());
		system("pause");
		return 0;
	}

	hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapObject == NULL)
	{
		printf("Mapping failed! %u\n", GetLastError());
		system("pause");
		return 0;
	}

	uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (uFileMap == NULL)
	{
		printf("File map failed! %u\n", GetLastError());
		system("pause");
		return 0;
	}

	//定位到PE基址
	pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;

	//判断MZ头
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("This file is not PE!");
		system("pause");
		return 0;
	}
	
	//定位到NT头
	pImageNtHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)pImageDosHeader + pImageDosHeader->e_lfanew);
	printf("%lx\n", pImageNtHeader->Signature);
	ULONG Rva_pImportTable = pImageNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
	
	//定位到导入表起始位置
	PIMAGE_IMPORT_DESCRIPTOR pIID= (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw32(pImageNtHeader, Rva_pImportTable) + uFileMap);

	//遍历导入表
	for (; pIID->OriginalFirstThunk; pIID++)
	{
		//打印Dll name
		printf("Dll Name:%s\n", (RvaToRaw32(pImageNtHeader, pIID->Name) + uFileMap));

		PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(RvaToRaw32(pImageNtHeader, pIID->OriginalFirstThunk) + uFileMap);
		while (pINT->u1.AddressOfData)
		{
			PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(RvaToRaw32(pImageNtHeader, pINT->u1.AddressOfData) + uFileMap);
			printf("Dll num: %d Dll name: %s\n", pIBN->Hint, pIBN->Name);
			pINT++;
		}

		printf("---------------------------------------------------------------\n");
	}
}*/