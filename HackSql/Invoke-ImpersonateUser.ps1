function Invoke-ImpersonateUser
{
    param (
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
