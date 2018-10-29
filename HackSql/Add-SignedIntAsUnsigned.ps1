#Used to add 64bit memory addresses
function Add-SignedIntAsUnsigned
{
	param (
	[Parameter(Position = 0, Mandatory = $true)]
	[Int64]
	$Value1,

	[Parameter(Position = 1, Mandatory = $true)]
	[Int64]
	$Value2
	)

	[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
	[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
	[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

	if ($Value1Bytes.Count -eq $Value2Bytes.Count)
	{
		$CarryOver = 0
		for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
		{
			#Add bytes
			[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

			$FinalBytes[$i] = $Sum -band 0x00FF

			if (($Sum -band 0xFF00) -eq 0x100)
			{
				$CarryOver = 1
			}
			else
			{
				$CarryOver = 0
			}
		}
	}
	else
	{
		Throw "Cannot add bytearrays of different sizes"
	}

	return [BitConverter]::ToInt64($FinalBytes, 0)
}
