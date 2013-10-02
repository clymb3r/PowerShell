Param(
[Parameter(Position=0, Mandatory=$true)]
[String]
$File
)

[Byte[]]$Bytes = [System.IO.File]::ReadAllBytes($File)

$B64String = [String][Convert]::ToBase64String($Bytes)

Write-Output $B64String