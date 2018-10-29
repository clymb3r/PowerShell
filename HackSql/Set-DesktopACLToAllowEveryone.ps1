function Set-DesktopACLToAllowEveryone
{
    Param(
        [IntPtr]$hObject
        )

    [IntPtr]$ppSidOwner = [IntPtr]::Zero
    [IntPtr]$ppsidGroup = [IntPtr]::Zero
    [IntPtr]$ppDacl = [IntPtr]::Zero
    [IntPtr]$ppSacl = [IntPtr]::Zero
    [IntPtr]$ppSecurityDescriptor = [IntPtr]::Zero
    #0x7 is window station, change for other types
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

        #For user "Everyone"
        $TrusteeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TRUSTEE)
        $TrusteePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TrusteeSize)
        $TrusteeObj = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TrusteePtr, [Type]$TRUSTEE)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TrusteePtr)
        $TrusteeObj.pMultipleTrustee = [IntPtr]::Zero
        $TrusteeObj.MultipleTrusteeOperation = 0
        $TrusteeObj.TrusteeForm = $Win32Constants.TRUSTEE_IS_SID
        $TrusteeObj.TrusteeType = $Win32Constants.TRUSTEE_IS_WELL_KNOWN_GROUP
        $TrusteeObj.ptstrName = $pAllUsersSid

        #Give full permission
        $ExplicitAccessSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$EXPLICIT_ACCESS)
        $ExplicitAccessPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ExplicitAccessSize)
        $ExplicitAccess = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExplicitAccessPtr, [Type]$EXPLICIT_ACCESS)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ExplicitAccessPtr)
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

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pAllUsersSid)

        if ($NewDacl -eq [IntPtr]::Zero)
        {
            throw "New DACL is null"
        }

        #0x7 is window station, change for other types
        $RetVal = $SetSecurityInfo.Invoke($hObject, 0x7, $Win32Constants.DACL_SECURITY_INFORMATION, $ppSidOwner, $ppSidGroup, $NewDacl, $ppSacl)
        if ($RetVal -ne 0)
        {
            Write-Error "SetSecurityInfo failed. Return value: $RetVal"
        }

        $LocalFree.Invoke($ppSecurityDescriptor) | Out-Null
    }
}
