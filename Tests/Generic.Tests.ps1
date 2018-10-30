Describe "Generic" {
    $ErrorActionPreference = "Stop"
    Set-StrictMode -Version Latest

    function Test-FileContent {
        [CmdletBinding()]
        [OutputType([System.Boolean])]
        param (
            [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
            $FullName,

            [switch] $Repair,
            $TabSize = 4
        )

        begin {
        }

        process {
            $rewrite = $false

            $file = Get-Item $FullName
            if ($file -is [System.IO.DirectoryInfo] -or $file.Extension -notin ".ps1", ".psm1", ".psd1", ".md", ".sql") {
                Write-Verbose "$FullName skipped"
                return $false
            }

            $content = Get-Content $file.FullName -Encoding Byte
            if ($content -and $content[0] -gt 126) {
                $rewrite = $true
                Write-Verbose "$FullName contains BOM"
            }

            $content = (Get-Content $file.FullName -Raw) -split [Environment]::NewLine
            $newContent = @()

            foreach ($line in $content) {
                $charIndex = 1
                $newLine = New-Object System.Text.StringBuilder($line.Length)
                foreach ($char in $line.ToCharArray()) {
                    if ($char -eq '`t') {
                        $rewrite = $true
                        Write-Verbose "$FullName contains TAB"

                        $spaceCount = $TabSize - ($charIndex % $TabSize) + 1
                        [void] $newLine.Append(' ' * $spaceCount)
                        $charIndex += $spaceCount
                    } elseif ([int] $char -eq 10) {
                        $rewrite = $true
                        Write-Verbose "$FullName contains NL"
                        [void] $newLine.Append("`r")
                    } elseif ([int] $char -eq 0 -or [int] $char -gt 126) {
                        $rewrite = $true
                        Write-Verbose "$FullName contains High ASCII $([int] $char)"
                        [void] $newLine.Append($char)
                    } else {
                        [void] $newLine.Append($char)
                    }
                }

                $newContent += $newLine.ToString()
            }

            $newContent = $newContent -join [Environment]::NewLine
            if ($rewrite) {
                if (!$Repair) {
                    return $true
                } else {
                    [System.IO.File]::WriteAllText($file.FullName, $newContent, [System.Text.UTF8Encoding] $false)
                }
            }
        }

        end {
        }
    }

    $moduleName = Get-Item . | ForEach-Object BaseName

    It "Module should load by path" {
        { Import-Module .\$moduleName -Force } | Should -Not -Throw
    }

    $files = Get-ChildItem . *-*.ps1 -Exclude *.Steps.ps1, *.Tests.ps1, *.ps1xml -Recurse
    foreach ($file in $files) {
        $relativeName = $file.FullName.Replace((Get-Location).Path + "\", "")

        It "$relativeName should have a function with a matching name" {
            $parser = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref] $null, [ref] $null)
            $functionName = $parser.EndBlock.Statements[0].Name
            $file.BaseName | Should -BeExactly $functionName

            $parser.EndBlock.Statements.Count | Should -BeLessOrEqual 2
            if ($parser.EndBlock.Statements.Count -eq 2) {
                $parser.EndBlock.Statements[1].Extent.Text | Should -BeLike "Set-Alias *"
            }
        }
    }

    It "Should not have duplicate file names" {
        $files | Group-Object BaseName | ForEach-Object {
            $_.Count | Should -Be 1
        }
    }

    $files = Get-ChildItem . -Recurse
    foreach ($file in $files) {
        $relativeName = $file.FullName.Replace((Get-Location).Path + "\", "")

        It "$relativeName should not contain weird characters" {
            $file | Test-FileContent | Should -Not -Be $true
        }
    }

    It "Should pass basic ScriptAnalyzer tests" {
        $result = Invoke-ScriptAnalyzer . -Recurse -ExcludeRule 'PSAvoidUsingWriteHost'
        $result | Out-String | Write-Host
        $result | Where-Object { $_.Severity -eq 'Error' } | Should -BeNullOrEmpty
    }
}
