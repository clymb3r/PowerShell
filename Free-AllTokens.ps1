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
