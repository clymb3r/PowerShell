Param(
[Parameter(Position=0, Mandatory=$true)]
[String]
$File
)

[Byte[]]$Bytes = [System.IO.File]::ReadAllBytes($File)

$ByteStr = ""
for ($i = 0; $i -lt $Bytes.Length; $i++)
{
    $ByteStr += $Bytes[$i]
    if ($i -ne ($Bytes.Length-1))
    {
        $ByteStr += ","
    }
}

return $ByteStr