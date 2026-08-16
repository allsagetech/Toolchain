<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

param (
	[string[]]$Paths,
	[string[]]$ExcludePaths,
	[ValidateRange(0, 100)]
	[double]$CoverageTarget = 80
)

$ErrorActionPreference = 'Stop'

$Paths = if ($Paths) { $Paths } else { @('.\src', '.\build.Tests.ps1') }

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


$modules = Join-Path $PSScriptRoot 'ps_modules'

if (-not (Test-Path $modules)) {
	New-Item -Path $modules -ItemType Directory | Out-Null
}

function Import-DevModule {
	param(
		[Parameter(Mandatory)]
		[string]$Name,
		[Parameter(Mandatory)]
		[Version]$RequiredVersion
	)

	$localModuleDir = Join-Path $modules $Name
	$hasRequiredLocalVersion = $false
	if (Test-Path $localModuleDir) {
		$hasRequiredLocalVersion = $null -ne (Get-ChildItem -Path $localModuleDir -Recurse -File -Filter "$Name.psd1" -ErrorAction SilentlyContinue |
			Where-Object { try { (Test-ModuleManifest -Path $_.FullName -ErrorAction Stop).Version -eq $RequiredVersion } catch { $false } } |
			Select-Object -First 1)
	}
	if (-not $hasRequiredLocalVersion) {
		try {
			Save-Module -Name $Name -RequiredVersion $RequiredVersion -Path $modules -ErrorAction Stop
		} catch {
			Write-Warning "Could not download module '$Name' from PowerShell Gallery. Falling back to installed modules."
		}
	}

	$candidates = @()

	if (Test-Path $localModuleDir) {
		$manifests = Get-ChildItem -Path $localModuleDir -Recurse -File -Filter "$Name.psd1" -ErrorAction SilentlyContinue
		foreach ($manifest in $manifests) {
			try {
				$info = Test-ModuleManifest -Path $manifest.FullName -ErrorAction Stop
				if ($info.Version -eq $RequiredVersion) {
					$candidates += [PSCustomObject]@{
						Version = $info.Version
						Path = $manifest.FullName
					}
				}
			} catch {
				Write-Debug "Skipping invalid module manifest '$($manifest.FullName)': $($_.Exception.Message)"
			}
		}
	}

	$globalCandidates = Get-Module -ListAvailable -Name $Name |
		Where-Object { $_.Version -eq $RequiredVersion } |
		ForEach-Object {
			[PSCustomObject]@{
				Version = $_.Version
				Path = $_.Path
			}
		}
	$candidates += $globalCandidates

	if (-not $candidates -or $candidates.Count -eq 0) {
		throw "$Name $RequiredVersion is required but not available. Ensure internet access to PowerShell Gallery or pre-populate '$modules'."
	}

	$selected = $candidates | Sort-Object Version -Descending | Select-Object -First 1

	Remove-Module -Name $Name -ErrorAction SilentlyContinue
	Import-Module -Name $selected.Path -Force -ErrorAction Stop
}

$dependencyPath = Join-Path $PSScriptRoot 'test.dependencies.psd1'
$requiredModules = Import-PowerShellDataFile -Path $dependencyPath

foreach ($kv in $requiredModules.GetEnumerator()) {
	Import-DevModule -Name $kv.Key -RequiredVersion ([Version]$kv.Value)
}

foreach ($path in $Paths) {
	$analysis = @(Invoke-ScriptAnalyzer -Path $path -Settings (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'))
	if ($analysis.Count -gt 0) {
		$analysis
		throw "failed with $($analysis.Count) findings"
	}
}

if ($env:TOOLCHAIN_COVERAGE_TARGET) {
	[double]$CoverageTarget = $env:TOOLCHAIN_COVERAGE_TARGET
}

$runConfig = @{
	Path = $Paths
	Exit = $false
	PassThru = $true
}

if ($ExcludePaths -and $ExcludePaths.Count -gt 0) {
	$runConfig.ExcludePath = $ExcludePaths
}

$pesterConfiguration = New-PesterConfiguration -Hashtable @{
	Run = $runConfig
	CodeCoverage = @{
		Enabled = ($CoverageTarget -gt 0)
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
}

$pesterConfiguration.CodeCoverage.CoveragePercentTarget = $CoverageTarget

$result = Invoke-Pester -Configuration $pesterConfiguration
if ($result.Result -ne 'Passed' -or $result.FailedCount -gt 0) {
	throw "Pester failed with $($result.FailedCount) failing test(s)."
}

if ($CoverageTarget -gt 0) {
	$coveragePath = Join-Path (Get-Location) 'coverage.xml'
	if (-not (Test-Path -LiteralPath $coveragePath -PathType Leaf)) {
		throw "Coverage report was not created: $coveragePath"
	}
	$coverageDocument = [xml](Get-Content -LiteralPath $coveragePath -Raw)
	$coverageCounter = $coverageDocument.DocumentElement.SelectSingleNode("counter[@type='INSTRUCTION']")
	if (-not $coverageCounter) { throw 'Coverage report does not contain an INSTRUCTION counter.' }
	$covered = [double]$coverageCounter.covered
	$total = $covered + [double]$coverageCounter.missed
	$coveragePercent = if ($total -eq 0) { 100.0 } else { 100.0 * $covered / $total }
	if ($coveragePercent -lt $CoverageTarget) {
		throw ('Code coverage {0:N2}% is below the required {1:N2}%.' -f $coveragePercent, $CoverageTarget)
	}
}
