// DemoExe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <process.h>
#include <windows.h>

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

int _tmain(int argc, _TCHAR* argv[])
{
	printf("Exe loaded! Printing argc and argv\n\n");

	printf("Argc: %d\n", argc);
	printf("ArgvAddress: %d\n", argv);
	
	for (int i = 0; i < argc; i++)
	{
		wprintf(L"Argv: %s\n", argv[i]);
	}

	printf("DosHeaderMagic: %d\n", __ImageBase.e_magic); 
	printf("__ImageBase: %d\n", &__ImageBase);

	DWORD old = 0;
	VirtualProtect(&__ImageBase, 2, PAGE_EXECUTE_READWRITE, &old);
	__ImageBase.e_magic = 0;
	printf("Updated DosHeaderMagic: %d\n", __ImageBase.e_magic); 
	//wprintf(L"GetCommandLine: %s\n", GetCommandLine());

	return 0;
}








