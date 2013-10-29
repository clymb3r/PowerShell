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
    SE_PRIVILEGE_ENABLED = 2
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
}

$Win32Constants = New-Object PSObject -Property $Constants

###############################

###############################
#Win32Structures
###############################
#Define all the structures/enums that will be used
#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html

#try { $TOKEN_PRIVILEGES = [TOKEN_PRIVILEGES] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
#{
    $Domain = [AppDomain]::CurrentDomain
    $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
    $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    #Struct LUID
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
    $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
    $LUID = $TypeBuilder.CreateType()

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
    
    
#}
###############################


###############################
#Win32Functions
###############################
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

$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
$OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
$OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

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
###############################


Function Enable-SeSecurityPrivilege
{	
	[IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
	if ($ThreadHandle -eq [IntPtr]::Zero)
	{
		Throw "Unable to get the handle to the current thread"
	}
		
	[IntPtr]$ThreadToken = [IntPtr]::Zero
	[Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	if ($Result -eq $false)
	{
		if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
		{
			$Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			if ($Result -eq $false)
			{
				Throw (New-Object ComponentModel.Win32Exception)
			}
				
			$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			if ($Result -eq $false)
			{
				Throw (New-Object ComponentModel.Win32Exception)
			}
		}
		else
		{
			Throw ([ComponentModel.Win32Exception] $ErrorCode)
		}
	}
	
    $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
    $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
    $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)

	$Result = $LookupPrivilegeValue.Invoke($null, "SeSecurityPrivilege", [Ref] $LuidObject)

	if ($Result -eq $false)
	{
		Throw (New-Object ComponentModel.Win32Exception)
	}

    [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
    $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
    $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
    #$LuidAndAttributes = New-Object $LUID_AND_ATTRIBUTES
    $LuidAndAttributes.Luid = $LuidObject
    $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

    [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)

    $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
	$TokenPrivileges.PrivilegeCount = 1
	$TokenPrivileges.Privileges = $LuidAndAttributes

    $Global:TokenPriv = $TokenPrivileges

	$Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	if ($Result -eq $false)
	{
        Throw (New-Object ComponentModel.Win32Exception)
	}
}

function Get-SecurityInfo
{
    Param(
        [IntPtr]$hObject
        )

    [IntPtr]$ppSidOwner = [IntPtr]::Zero
    [IntPtr]$ppsidGroup = [IntPtr]::Zero
    [IntPtr]$ppDacl = [IntPtr]::Zero
    [IntPtr]$ppSacl = [IntPtr]::Zero
    [IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero #todo: free using localfree
    #todo: 0x7 is window station, change for other types
    $retVal = $GetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, [Ref]$ppSidOwner, [Ref]$ppSidGroup, [Ref]$ppDacl, [Ref]$ppSacl, [Ref]$ppSecurityDescriptor)
    if ($retVal -ne 0)
    {
        Write-Error "Unable to call GetSecurityInfo. ErrorCode: $retVal"
    }

    if ($ppDacl -ne [IntPtr]::Zero)
    {
        $AclObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppDacl, [Type]$ACL)

        #Enumerate acl
        for ($AceIndex = 0; $AceIndex -lt $AclObj.AceCount; $AceIndex++)
        {
            $AcePtr = [IntPtr]::Zero
            $Success = $GetAce.Invoke($ppDacl, $AceIndex, [Ref]$AcePtr)
            if (-not $Success)
            {
                Throw (New-Object ComponentModel.Win32Exception)
            }

            $AceHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AcePtr, [Type]$ACE_HEADER)
            if ($AceHeader.AceType -eq $Constants.ACCESS_ALLOWED_ACE_TYPE)
            {
                if ($AceHeader.AceSize -eq 0)
                {
                    throw "AceHeader is empty"
                }

                $AccessAllowedAce = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AcePtr, [Type]$ACCESS_ALLOWED_ACE)
                $SidOffset = [System.Runtime.InteropServices.Marshal]::OffsetOf([Type]$ACCESS_ALLOWED_ACE, "SidStart")
                $PSid = [IntPtr](Add-SignedIntAsUnsigned $AcePtr $SidOffset)

                [UInt32]$NameSize = 256
                $UsernameBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($NameSize)
                $DomainBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($NameSize)
                [UInt32]$RealNameSize = $NameSize
                [UInt32]$RealDomainSize = $NameSize
                [UInt32]$SidNameUse = 0

                $Success = $LookupAccountSidW.Invoke([IntPtr]::Zero, $PSid, $UsernameBuffer, [Ref]$RealNameSize, $DomainBuffer, [Ref]$RealDomainSize, [Ref]$SidNameUse)
                if (-not $Success)
                {
                    #Throw (New-Object ComponentModel.Win32Exception)
                }
                else
                {
                    $SidUsername = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UsernameBuffer)
                    Write-Output "$($SidUsername): $($AccessAllowedAce.Mask.ToString("x8"))"
                }
            }
        }
    }
}

function Set-SecurityInfo
{
    Param(
        [IntPtr]$hObject
        )

    [IntPtr]$ppSidOwner = [IntPtr]::Zero
    [IntPtr]$ppsidGroup = [IntPtr]::Zero
    [IntPtr]$ppDacl = [IntPtr]::Zero
    [IntPtr]$ppSacl = [IntPtr]::Zero
    [IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero #todo: free using localfree
    #todo: 0x7 is window station, change for other types
    $retVal = $GetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, [Ref]$ppSidOwner, [Ref]$ppSidGroup, [Ref]$ppDacl, [Ref]$ppSacl, [Ref]$ppSecurityDescriptor)
    if ($retVal -ne 0)
    {
        Write-Error "Unable to call GetSecurityInfo. ErrorCode: $retVal"
    }

    if ($ppDacl -ne [IntPtr]::Zero)
    {
        $AclObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ppDacl, [Type]$ACL)

        #Add all users to acl
        [UInt32]$RealSize = 2000
        $pAllUsersSid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RealSize)
        $Success = $CreateWellKnownSid.Invoke(1, [IntPtr]::Zero, $pAllUsersSid, [Ref]$RealSize)
        if (-not $Success)
        {
            Throw (New-Object ComponentModel.Win32Exception)
        }

        $TrusteeSize = [System.Runtime.InteropServices.Marshal]::SizeOf($TRUSTEE)
        $TrusteePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TrusteeSize)
        $TrusteeObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TrusteePtr, [Type]$TRUSTEE)
        $TrusteeObj.pMultipleTrustee = [IntPtr]::Zero
        $TrusteeObj.MultipleTrusteeOperation = 0
        $TrusteeObj.TrusteeForm = $Win32Constants.TRUSTEE_IS_SID
        $TrusteeObj.TrusteeType = $Win32Constants.TRUSTEE_IS_WELL_KNOWN_GROUP
        $TrusteeObj.ptstrName = $pAllUsersSid

        $ExplicitAccessSize = [System.Runtime.InteropServices.Marshal]::SizeOf($EXPLICIT_ACCESS)
        $ExplicitAccessPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ExplicitAccessSize)
        $ExplicitAccess = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExplicitAccessPtr, [Type]$EXPLICIT_ACCESS)
        $ExplicitAccess.grfAccessPermissions = 0xf03ff
        $ExplicitAccess.grfAccessMode = $Win32constants.GRANT_ACCESS
        $ExplicitAccess.grfInheritance = $Win32Constants.OBJECT_INHERIT_ACE
        $ExplicitAccess.Trustee = $TrusteeObj

        [IntPtr]$NewDacl = [IntPtr]::Zero

        $RetVal = $SetEntriesInAclW.Invoke(1, [Ref]$ExplicitAccess, $ppDacl, [Ref]$NewDacl)
        if ($RetVal -ne 0)
        {
            Write-Error "Error calling SetEntriesInAclW: $RetVal"
        }

        if ($NewDacl -eq [IntPtr]::Zero)
        {
            throw "New DACL is null"
        }

        #todo: 0x7 is window station, change for other types
        $RetVal = $SetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, $ppSidOwner, $ppSidGroup, $NewDacl, $ppSacl)
        if ($RetVal -ne 0)
        {
            Write-Error "SetSecurityInfo failed. Return value: $RetVal"
        }
    }
}

Enable-SeSecurityPrivilege

$WindowStationStr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
$hWinsta = $OpenWindowStationW.Invoke($WindowStationStr, $false, $Win32Constants.ACCESS_SYSTEM_SECURITY -bor $Win32Constants.READ_CONTROL -bor $Win32Constants.WRITE_DAC)

if ($hWinsta -eq [IntPtr]::Zero)
{
    Throw (New-Object ComponentModel.Win32Exception)
}

#Get the security info of the windowstation
Write-Output "Desktop window Station info:"
#Get-SecurityInfo $hWinsta
#Set-SecurityInfo $hWinsta
Get-SecurityInfo $hWinsta



$hDesktop = $OpenDesktopA.Invoke("default", 0, $false, $Win32Constants.DESKTOP_GENERIC_ALL -bor $Win32Constants.WRITE_DAC)
if ($hDesktop -eq [IntPtr]::Zero)
{
    Throw (New-Object ComponentModel.Win32Exception)
}
Write-Output ""
Write-Output ""
Write-Output "Desktop info:"
#Set-SecurityInfo $hDesktop
Get-SecurityInfo $hDesktop

