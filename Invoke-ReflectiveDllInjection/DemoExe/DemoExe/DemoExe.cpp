// DemoExe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <process.h>
#include <windows.h>
#include <iostream>

using namespace std;

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

	//printf("gca: %d\n", GetCommandLineA);
	//printf("gcw: %d\n", GetCommandLineW);
	//printf("gc:  %d\n", GetCommandLine);
	//printf("getcommandlinea: %s\n", GetCommandLineA());
	//wprintf(L"getcommandline: %ls \n", GetCommandLine());

	return 0;
}








