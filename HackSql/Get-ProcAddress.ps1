#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
function Get-ProcAddress
{
    param
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
