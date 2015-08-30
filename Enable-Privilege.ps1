#Enable SeSecurityPrivilege, needed to query security information for desktop DACL
function Enable-Privilege
{
    Param(
        [Parameter()]
        [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
            "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
            "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        [String]
        $Privilege
    )

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

    $CloseHandle.Invoke($ThreadHandle) | Out-Null

    $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
    $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
    $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

    $Result = $LookupPrivilegeValue.Invoke($null, $Privilege, [Ref] $LuidObject)

    if ($Result -eq $false)
    {
	    Throw (New-Object ComponentModel.Win32Exception)
    }

    [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
    $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
    $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

    $LuidAndAttributes.Luid = $LuidObject
    $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

    [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
    $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
    $TokenPrivileges.PrivilegeCount = 1
    $TokenPrivileges.Privileges = $LuidAndAttributes

    $Global:TokenPriv = $TokenPrivileges

    Write-Verbose "Attempting to enable privilege: $Privilege"
    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($Result -eq $false)
    {
        Throw (New-Object ComponentModel.Win32Exception)
    }

    $CloseHandle.Invoke($ThreadToken) | Out-Null
    Write-Verbose "Enabled privilege: $Privilege"
}
