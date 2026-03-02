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


$modules = Join-Path $PSScriptRoot 'ps_modules'

if (-not (Test-Path $modules)) {
	New-Item -Path $modules -ItemType Directory | Out-Null
}

function Import-DevModule {
	param(
		[Parameter(Mandatory)]
		[string]$Name,
		[Parameter(Mandatory)]
		[Version]$MinimumVersion
	)

	$localModuleDir = Join-Path $modules $Name
	if (-not (Test-Path $localModuleDir)) {
		try {
			Save-Module -Name $Name -Path $modules -ErrorAction Stop
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
				if ($info.Version -ge $MinimumVersion) {
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
		Where-Object { $_.Version -ge $MinimumVersion } |
		ForEach-Object {
			[PSCustomObject]@{
				Version = $_.Version
				Path = $_.Path
			}
		}
	$candidates += $globalCandidates

	if (-not $candidates -or $candidates.Count -eq 0) {
		$highestFound = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
		if ($highestFound) {
			throw "$Name $MinimumVersion or newer is required. Highest installed version is $($highestFound.Version) at '$($highestFound.Path)'."
		}
		throw "$Name $MinimumVersion or newer is required but not available. Ensure internet access to PowerShell Gallery or pre-populate '$modules'."
	}

	$selected = $candidates | Sort-Object Version -Descending | Select-Object -First 1

	Remove-Module -Name $Name -ErrorAction SilentlyContinue
	Import-Module -Name $selected.Path -Force -ErrorAction Stop
}

$requiredModules = [ordered]@{
	Pester = [Version]'5.0.0'
	PSScriptAnalyzer = [Version]'1.20.0'
}

foreach ($kv in $requiredModules.GetEnumerator()) {
	Import-DevModule -Name $kv.Key -MinimumVersion $kv.Value
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
