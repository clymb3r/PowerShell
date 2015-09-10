[CmdletBinding()] 
param(
)

# Because these are set once in a script scope (modules and functions are all considered in one script scope)
# they will be effective in every function, and won't override or be overridden by changes in parent scopes.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($fileName in (Get-ChildItem $PSScriptRoot "*.ps1" -Recurse)) {
    try {
	    Write-Verbose "Loading function from path '$fileName'."
	    . $fileName.FullName
    } catch {
	    Write-Error $_
    }
}
