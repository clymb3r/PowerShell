function Get-ThreadToken
{
    param (
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
