// DemoExe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	printf("Exe loaded! Printing argc and argv\n\n");

	printf("Argc: %d\n", argc);
	printf("ArgvAddress: %d\n", argv);
	
	for (int i = 0; i < argc; i++)
	{
		wprintf(L"Argv: %s\n", argv[i]);
	}

	wprintf(L"GetCommandLine: %s\n", GetCommandLine());

	return 0;
}








