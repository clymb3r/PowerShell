#Gets important information about the token such as the logon type associated with the logon
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
                #Get the username and domainname associated with the token
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


                #Query the token sessionid
                $ReturnObj | Add-Member -Type NoteProperty -Name SessionID -Value "Unknown"

                [UInt32]$TokenSessionIdSize = 4
                [IntPtr]$TokenSessionIdPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenSessionIdSize)
                [UInt32]$RealSize = 0
                $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenSessionId, $TokenSessionIdPtr, $TokenSessionIdSize, [Ref]$RealSize)
                if (-not $Success)
                {
                    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                }
                else
                {
                    [UInt32]$TokenSessionId = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSessionIdPtr, [Type][UInt32])
                    $ReturnObj.SessionID = $TokenSessionId
                }
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)


                #Query the token privileges
                $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesEnabled -Value @()
                $ReturnObj | Add-Member -Type NoteProperty -Name PrivilegesAvailable -Value @()

                [UInt32]$TokenPrivilegesSize = 1000
                [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesSize)
                [UInt32]$RealSize = 0
                $Success = $GetTokenInformation.Invoke($hToken, $TOKEN_INFORMATION_CLASS::TokenPrivileges, $TokenPrivilegesPtr, $TokenPrivilegesSize, [Ref]$RealSize)
                if (-not $Success)
                {
                    $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning "GetTokenInformation failed to retrieve Token SessionId. ErrorCode: $ErrorCode"
                }
                else
                {
                    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)

                    #Loop through each privilege
                    [IntPtr]$PrivilegesBasePtr = [IntPtr](Add-SignedIntAsUnsigned $TokenPrivilegesPtr ([System.Runtime.InteropServices.Marshal]::OffsetOf([Type]$TOKEN_PRIVILEGES, "Privileges")))
                    $LuidAndAttributeSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
                    for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
                    {
                        $LuidAndAttributePtr = [IntPtr](Add-SignedIntAsUnsigned $PrivilegesBasePtr ($LuidAndAttributeSize * $i))

                        $LuidAndAttribute = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributePtr, [Type]$LUID_AND_ATTRIBUTES)

                        #Lookup privilege name
                        [UInt32]$PrivilegeNameSize = 60
                        $PrivilegeNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PrivilegeNameSize)
                        $PLuid = $LuidAndAttributePtr #The Luid structure is the first object in the LuidAndAttributes structure, so a ptr to LuidAndAttributes also points to Luid

                        $Success = $LookupPrivilegeNameW.Invoke([IntPtr]::Zero, $PLuid, $PrivilegeNamePtr, [Ref]$PrivilegeNameSize)
                        if (-not $Success)
                        {
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            Write-Warning "Call to LookupPrivilegeNameW failed. Error code: $ErrorCode. RealSize: $PrivilegeNameSize"
                        }
                        $PrivilegeName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($PrivilegeNamePtr)

                        #Get the privilege attributes
                        $PrivilegeStatus = ""
                        $Enabled = $false

                        if ($LuidAndAttribute.Attributes -eq 0)
                        {
                            $Enabled = $false
                        }
                        if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) -eq $Win32Constants.SE_PRIVILEGE_ENABLED_BY_DEFAULT) #enabled by default
                        {
                            $Enabled = $true
                        }
                        if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_ENABLED) -eq $Win32Constants.SE_PRIVILEGE_ENABLED) #enabled
                        {
                            $Enabled = $true
                        }
                        if (($LuidAndAttribute.Attributes -band $Win32Constants.SE_PRIVILEGE_REMOVED) -eq $Win32Constants.SE_PRIVILEGE_REMOVED) #SE_PRIVILEGE_REMOVED. This should never exist. Write a warning if it is found so I can investigate why/how it was found.
                        {
                            Write-Warning "Unexpected behavior: Found a token with SE_PRIVILEGE_REMOVED. Please report this as a bug. "
                        }

                        if ($Enabled)
                        {
                            $ReturnObj.PrivilegesEnabled += ,$PrivilegeName
                        }
                        else
                        {
                            $ReturnObj.PrivilegesAvailable += ,$PrivilegeName
                        }

                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PrivilegeNamePtr)
                    }
                }
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

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
