<# Toolchain | SPDX-License-Identifier: MPL-2.0 #>

BeforeAll {
	$script:HostExecutable = (Get-Process -Id $PID -ErrorAction Stop).Path
	$script:SourceEntry = (Resolve-Path (Join-Path $PSScriptRoot 'tlc.ps1')).Path
	$script:CatalogSource = (Resolve-Path (Join-Path $PSScriptRoot 'remote-catalog.ps1')).Path
}

Describe 'Startup and catalog performance budgets' {
	It 'loads Toolchain source in a fresh process within the startup budget' {
		$budget = if ($env:TOOLCHAIN_STARTUP_BUDGET_MS) { [int]$env:TOOLCHAIN_STARTUP_BUDGET_MS } else { 3000 }
		$entry = $script:SourceEntry.Replace("'", "''")
		$measurement = & $script:HostExecutable -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command @"
`$ErrorActionPreference = 'Stop'
`$env:TOOLCHAIN_DISABLE_UPDATE_CHECK = '1'
`$stopwatch = [Diagnostics.Stopwatch]::StartNew()
. '$entry'
`$stopwatch.Stop()
Write-Output `$stopwatch.ElapsedMilliseconds
"@
		$LASTEXITCODE | Should -Be 0
		$milliseconds = [long]@($measurement)[-1]
		$milliseconds | Should -BeLessOrEqual $budget
	}

	It 'classifies a 10,000-marker model catalog within its budget' {
		$budget = if ($env:TOOLCHAIN_CATALOG_BUDGET_MS) { [int]$env:TOOLCHAIN_CATALOG_BUDGET_MS } else { 2000 }
		$catalogSource = $script:CatalogSource.Replace("'", "''")
		$measurement = & $script:HostExecutable -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command @"
`$ErrorActionPreference = 'Stop'
. '$catalogSource'
`$tags = for (`$index = 0; `$index -lt 10000; `$index++) { 'tlc-kind-model-v1-42-10000--model-{0:d5}' -f `$index }
`$stopwatch = [Diagnostics.Stopwatch]::StartNew()
`$catalog = GetCompleteRemoteModelCatalog -Tags `$tags
`$stopwatch.Stop()
if (-not `$catalog.Found -or @(`$catalog.Packages).Count -ne 10000) { throw 'Synthetic catalog classification was incomplete.' }
Write-Output `$stopwatch.ElapsedMilliseconds
"@
		$LASTEXITCODE | Should -Be 0
		$milliseconds = [long]@($measurement)[-1]
		$milliseconds | Should -BeLessOrEqual $budget
	}
}
