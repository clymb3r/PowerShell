#Enumerate all tokens on the system. Returns an array of objects with the token and information about the token.
function Enum-AllTokens
{
    $AllTokens = @()

    #First GetSystem. The script cannot enumerate all tokens unless it is system for some reason. Luckily it can impersonate a system token.
    #Even if already running as system, later parts on the script depend on having a SYSTEM token with most privileges, so impersonate the wininit token.
    $systemTokenInfo = Get-PrimaryToken -ProcessId (Get-Process wininit | where {$_.SessionId -eq 0}).Id
    if ($systemTokenInfo -eq $null -or (-not (Invoke-ImpersonateUser -hToken $systemTokenInfo.hProcToken)))
    {
        Write-Warning "Unable to impersonate SYSTEM, the script will not be able to enumerate all tokens"
    }

    if ($systemTokenInfo -ne $null -and $systemTokenInfo.hProcToken -ne [IntPtr]::Zero)
    {
        $CloseHandle.Invoke($systemTokenInfo.hProcToken) | Out-Null
        $systemTokenInfo = $null
    }

    $ProcessIds = get-process | where {$_.name -inotmatch "^csrss$" -and $_.name -inotmatch "^system$" -and $_.id -ne 0}

    #Get all tokens
    foreach ($Process in $ProcessIds)
    {
        $PrimaryTokenInfo = (Get-PrimaryToken -ProcessId $Process.Id -FullPrivs)

        #If a process is a protected process, it's primary token cannot be obtained. Don't try to enumerate it.
        if ($PrimaryTokenInfo -ne $null)
        {
            [IntPtr]$hToken = [IntPtr]$PrimaryTokenInfo.hProcToken

            if ($hToken -ne [IntPtr]::Zero)
            {
                #Get the LUID corrosponding to the logon
                $ReturnObj = Get-TokenInformation -hToken $hToken
                if ($ReturnObj -ne $null)
                {
                    $ReturnObj | Add-Member -MemberType NoteProperty -Name ProcessId -Value $Process.Id

                    $AllTokens += $ReturnObj
                }
            }
            else
            {
                Write-Warning "Couldn't retrieve token for Process: $($Process.Name). ProcessId: $($Process.Id)"
            }

            foreach ($Thread in $Process.Threads)
            {
                $ThreadTokenInfo = Get-ThreadToken -ThreadId $Thread.Id
                [IntPtr]$hToken = ($ThreadTokenInfo.hThreadToken)

                if ($hToken -ne [IntPtr]::Zero)
                {
                    $ReturnObj = Get-TokenInformation -hToken $hToken
                    if ($ReturnObj -ne $null)
                    {
                        $ReturnObj | Add-Member -MemberType NoteProperty -Name ThreadId -Value $Thread.Id
                
                        $AllTokens += $ReturnObj
                    }
                }
            }
        }
    }

    return $AllTokens
}
