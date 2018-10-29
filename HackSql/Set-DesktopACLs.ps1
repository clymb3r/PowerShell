#Change the ACL of the WindowStation and Desktop
function Set-DesktopACLs
{
    Enable-Privilege -Privilege SeSecurityPrivilege

    #Change the privilege for the current window station to allow full privilege for all users
    $WindowStationStr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("WinSta0")
    $hWinsta = $OpenWindowStationW.Invoke($WindowStationStr, $false, $Win32Constants.ACCESS_SYSTEM_SECURITY -bor $Win32Constants.READ_CONTROL -bor $Win32Constants.WRITE_DAC)

    if ($hWinsta -eq [IntPtr]::Zero)
    {
        Throw (New-Object ComponentModel.Win32Exception)
    }

    Set-DesktopACLToAllowEveryone -hObject $hWinsta
    $CloseHandle.Invoke($hWinsta) | Out-Null

    #Change the privilege for the current desktop to allow full privilege for all users
    $hDesktop = $OpenDesktopA.Invoke("default", 0, $false, $Win32Constants.DESKTOP_GENERIC_ALL -bor $Win32Constants.WRITE_DAC)
    if ($hDesktop -eq [IntPtr]::Zero)
    {
        Throw (New-Object ComponentModel.Win32Exception)
    }

    Set-DesktopACLToAllowEveryone -hObject $hDesktop
    $CloseHandle.Invoke($hDesktop) | Out-Null
}
