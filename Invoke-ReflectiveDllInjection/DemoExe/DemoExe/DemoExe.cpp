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

	exit(-1);

	return 0;
}








