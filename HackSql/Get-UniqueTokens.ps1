#Takes an array of TokenObjects built by the script and returns the unique ones
function Get-UniqueTokens
{
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [Object[]]
        $AllTokens
    )

    $TokenByUser = @{}
    $TokenByEnabledPriv = @{}
    $TokenByAvailablePriv = @{}

    #Filter tokens by user
    foreach ($Token in $AllTokens)
    {
        $Key = $Token.Domain + "\" + $Token.Username
        if (-not $TokenByUser.ContainsKey($Key))
        {
            #Filter out network logons and junk Windows accounts. This filter eliminates accounts which won't have creds because
            #    they are network logons (type 3) or logons for which the creds don't matter like LOCOAL SERVICE, DWM, etc..
            if ($Token.LogonType -ne 3 -and
                $Token.Username -inotmatch "^DWM-\d+$" -and
                $Token.Username -inotmatch "^LOCAL\sSERVICE$")
            {
                $TokenByUser.Add($Key, $Token)
            }
        }
        else
        {
            #If Tokens have equal elevation levels, compare their privileges.
            if($Token.IsElevated -eq $TokenByUser[$Key].IsElevated)
            {
                if (($Token.PrivilegesEnabled.Count + $Token.PrivilegesAvailable.Count) -gt ($TokenByUser[$Key].PrivilegesEnabled.Count + $TokenByUser[$Key].PrivilegesAvailable.Count))
                {
                    $TokenByUser[$Key] = $Token
                }
            }
            #If the new token is elevated and the current token isn't, use the new token
            elseif (($Token.IsElevated -eq $true) -and ($TokenByUser[$Key].IsElevated -eq $false))
            {
                $TokenByUser[$Key] = $Token
            }
        }
    }

    #Filter tokens by privilege
    foreach ($Token in $AllTokens)
    {
        $Fullname = "$($Token.Domain)\$($Token.Username)"

        #Filter currently enabled privileges
        foreach ($Privilege in $Token.PrivilegesEnabled)
        {
            if ($TokenByEnabledPriv.ContainsKey($Privilege))
            {
                if($TokenByEnabledPriv[$Privilege] -notcontains $Fullname)
                {
                    $TokenByEnabledPriv[$Privilege] += ,$Fullname
                }
            }
            else
            {
                $TokenByEnabledPriv.Add($Privilege, @($Fullname))
            }
        }

        #Filter currently available (but not enable) privileges
        foreach ($Privilege in $Token.PrivilegesAvailable)
        {
            if ($TokenByAvailablePriv.ContainsKey($Privilege))
            {
                if($TokenByAvailablePriv[$Privilege] -notcontains $Fullname)
                {
                    $TokenByAvailablePriv[$Privilege] += ,$Fullname
                }
            }
            else
            {
                $TokenByAvailablePriv.Add($Privilege, @($Fullname))
            }
        }
    }

    $ReturnDict = @{
        TokenByUser = $TokenByUser
        TokenByEnabledPriv = $TokenByEnabledPriv
        TokenByAvailablePriv = $TokenByAvailablePriv
    }

    return (New-Object PSObject -Property $ReturnDict)
}
