<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

param (
	[string[]]$Paths,
	[string[]]$ExcludePaths
)

$Paths = if ($Paths) { $Paths } else { @('.\src') }

if (-not $ExcludePaths -and $env:TOOLCHAIN_PESTER_EXCLUDE_PATHS) {
	$ExcludePaths = $env:TOOLCHAIN_PESTER_EXCLUDE_PATHS -split '[,;\r\n]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }
}

if ($ExcludePaths -and $ExcludePaths.Count -gt 0) {
	$ExcludePaths = @(
		foreach ($p in $ExcludePaths) {
			if (-not $p) { continue }
			$p2 = $p.Trim()
			if (-not $p2) { continue }

			if ($p2 -match '[\*\?]') {
				$p2
				continue
			}

			try {
				(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot $p2) -ErrorAction Stop).Path
			} catch {
				$p2
			}
		}
	)
}

$srcRoot = Join-Path $PSScriptRoot 'src'
$coveragePaths = Get-ChildItem -Path $srcRoot -Recurse -File -Filter '*.ps1' |
    Where-Object { $_.Name -notlike '*.Tests.ps1' } |
    ForEach-Object { $_.FullName }


$modules = 'ps_modules'

if (-not (Test-Path $modules)) {
	New-Item -Path $modules -ItemType Directory | Out-Null
}

foreach ($name in 'Pester', 'PSScriptAnalyzer') {
	if (-not (Test-Path "$modules\$name")) {
		Save-Module -Name $name -Path $modules
	}
	Remove-Module -Name $name -ErrorAction SilentlyContinue
	Import-Module (Get-ChildItem -Path "$modules\$name" -Recurse -Include "$name.psd1").Fullname
}

foreach ($path in $Paths) {
	$analysis = @(Invoke-ScriptAnalyzer -Severity Error -Path $path -ExcludeRule 'PSAvoidUsingWriteHost', 'PSUseProcessBlockForPipelineCommand', 'PSUseBOMForUnicodeEncodedFile')
	if ($analysis.Count -gt 0) {
		$analysis
		throw "failed with $($analysis.Count) findings"
	}
}


$runConfig = @{
	Path = $Paths
	Exit = $true
}

if ($ExcludePaths -and $ExcludePaths.Count -gt 0) {
	$runConfig.ExcludePath = $ExcludePaths
}

$global:PesterPreference = (New-PesterConfiguration -Hashtable @{
	Run = $runConfig
	CodeCoverage = @{
		Enabled = $true
		Path = $coveragePaths
		OutputFormat = 'JaCoCo'
		OutputPath = 'coverage.xml'
	}
	TestResult = @{
		Enabled = $true
	}
	Output = @{
		Verbosity = 'Detailed'
	}
})

$coverageTarget = 100
if ($env:TOOLCHAIN_COVERAGE_TARGET) {
	[int]$coverageTarget = $env:TOOLCHAIN_COVERAGE_TARGET
}

$global:PesterPreference.CodeCoverage.CoveragePercentTarget = $coverageTarget

Invoke-Pester -Configuration $PesterPreference
