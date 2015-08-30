#Get the primary token for the specified processId
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
