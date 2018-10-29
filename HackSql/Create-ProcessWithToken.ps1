function Create-ProcessWithToken
{
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $hToken,

        [Parameter(Position=1, Mandatory=$true)]
        [String]
        $ProcessName,

        [Parameter(Position=2)]
        [String]
        $ProcessArgs,

        [Parameter(Position=3)]
        [Switch]
        $PassThru
    )
    Write-Verbose "Entering Create-ProcessWithToken"
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

        $ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$ProcessName")
        $ProcessArgsPtr = [IntPtr]::Zero
        if (-not [String]::IsNullOrEmpty($ProcessArgs))
        {
            $ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$ProcessName`" $ProcessArgs")
        }

        $FunctionName = ""
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0)
        {
            #Cannot use CreateProcessWithTokenW when in Session0 because CreateProcessWithTokenW throws an ACCESS_DENIED error. I believe it is because
            #this API attempts to modify the desktop ACL. I would just use this API all the time, but it requires that I enable SeAssignPrimaryTokenPrivilege
            #which is not ideal.
            Write-Verbose "Running in Session 0. Enabling SeAssignPrimaryTokenPrivilege and calling CreateProcessAsUserW to create a process with alternate token."
            Enable-Privilege -Privilege SeAssignPrimaryTokenPrivilege
            $Success = $CreateProcessAsUserW.Invoke($NewHToken, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            $FunctionName = "CreateProcessAsUserW"
        }
        else
        {
            Write-Verbose "Not running in Session 0, calling CreateProcessWithTokenW to create a process with alternate token."
            $Success = $CreateProcessWithTokenW.Invoke($NewHToken, 0x0, $ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
            $FunctionName = "CreateProcessWithTokenW"
        }
        if ($Success)
        {
            #Free the handles returned in the ProcessInfo structure
            $ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
            $CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
            $CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null

	#Pass created System.Diagnostics.Process object to pipeline
	if ($PassThru) {
		#Retrieving created System.Diagnostics.Process object
		$returnProcess = Get-Process -Id $ProcessInfo.dwProcessId

		#Caching process handle so we don't lose it when the process exits
		$null = $returnProcess.Handle

		#Passing System.Diagnostics.Process object to pipeline
		$returnProcess
	}
        }
        else
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "$FunctionName failed. Error code: $ErrorCode"
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
    }
}
