function Invoke-RevertToSelf
{
    param (
        [Parameter(Position=0)]
        [Switch]
        $ShowOutput
    )

    $Success = $RevertToSelf.Invoke()

    if ($ShowOutput)
    {
        if ($Success)
        {
            Write-Output "RevertToSelf was successful. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
        else
        {
            Write-Output "RevertToSelf failed. Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
        }
    }
}
