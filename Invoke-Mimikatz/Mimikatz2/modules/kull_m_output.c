#include "kull_m_output.h"

FILE * logfile = NULL;

size_t outputStringSize = 0;	//In bytes
size_t outputStringPosition = 0; //In characters
wchar_t* outputString = NULL;


void kprintf(PCWCHAR format, ...)
{
	va_list args;
	size_t strSize = 10000;
	int tempOutputLength = 0;
	wchar_t* tempOutput = NULL;

	va_start(args, format);
	tempOutput = (wchar_t*)malloc(strSize);
	tempOutputLength = vswprintf_s(tempOutput, strSize / sizeof(wchar_t), format, args);
	va_end(args);

	if (tempOutputLength > 0)
	{
		//Even if this overflows, the wcsncpy_s call should be protected against an overflow
		size_t neededSize = sizeof(wchar_t) + (outputStringPosition * sizeof(wchar_t)) + (tempOutputLength * sizeof(wchar_t)); //todo, need to do overflow check

		//If the current output string isn't big enough to fit the new data, expand it.
		if (outputStringSize < neededSize)
		{
			size_t newSize = outputStringSize * 2; //Double the size of the buffer. Overflowing this variable isn't a concern, you would run out of memory first.

			void* newMem = realloc(outputString, newSize);
			if (newMem == NULL)
			{
								//todo: error, couldn't realloc
				free(tempOutput);
				tempOutput = NULL;
				return;
			}
			
			outputString = (wchar_t*)newMem;
			outputStringSize = newSize;
			newMem = NULL;
		}

		//Copy the tempOutput in to the main outputString
		wcsncpy_s(outputString + outputStringPosition, (outputStringSize / sizeof(wchar_t)) - outputStringPosition, tempOutput, _TRUNCATE);
		outputStringPosition += tempOutputLength;
	}

	free(tempOutput);
	tempOutput = NULL;
}

void kprintf_inputline(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	if(logfile)
		vfwprintf(logfile, format, args);
	va_end(args);
	fflush(logfile);
}

BOOL kull_m_output_file(PCWCHAR file)
{
	BOOL status = FALSE;
	FILE * newlog = NULL;

	if(file)
		newlog = _wfopen(file, L"a");
	
	if(newlog || !file)
	{
		if(logfile)
			fclose(logfile);
		logfile = newlog;
	}
	return (!file || (file && logfile));
}