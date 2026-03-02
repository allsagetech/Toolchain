<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\config.ps1
. $PSScriptRoot\package.ps1
. $PSScriptRoot\registry.ps1
. $PSScriptRoot\definition.ps1

function GetSessionState {
	return @{
		Vars = (Get-Variable -Scope Global | ForEach-Object { [psvariable]::new($_.Name, $_.Value) })
		Env = (Get-ChildItem Env:)
	}
}

function SaveSessionState {
	param (
		[Parameter(Mandatory)]
		[string]$GUID
	)
	Set-Variable -Name "ToolchainSaveState_$GUID" -Value (GetSessionState) -Scope Global
}

function ClearSessionState {
	param (
		[Parameter(Mandatory)]
		[string]$GUID
	)
	$default = "ToolchainSaveState_$GUID", '__LastHistoryId', '__VSCodeOriginalPrompt', '__VSCodeOriginalPSConsoleHostReadLine', '?', '^', '$', 'args', 'ConfirmPreference', 'DebugPreference', 'EnabledExperimentalFeatures', 'Error', 'ErrorActionPreference', 'ErrorView', 'ExecutionContext', 'false', 'FormatEnumerationLimit', 'HOME', 'Host', 'InformationPreference', 'input', 'IsCoreCLR', 'IsLinux', 'IsMacOS', 'IsWindows', 'MaximumHistoryCount', 'MyInvocation', 'NestedPromptLevel', 'null', 'OutputEncoding', 'PID', 'PROFILE', 'ProgressPreference', 'PSBoundParameters', 'PSCommandPath', 'PSCulture', 'PSDefaultParameterValues', 'PSEdition', 'PSEmailServer', 'PSHOME', 'PSScriptRoot', 'PSSessionApplicationName', 'PSSessionConfigurationName', 'PSSessionOption', 'PSStyle', 'PSUICulture', 'PSVersionTable', 'PWD', 'ShellId', 'StackTrace', 'true', 'VerbosePreference', 'WarningPreference', 'WhatIfPreference', 'ConsoleFileName', 'MaximumAliasCount', 'MaximumDriveCount', 'MaximumErrorCount', 'MaximumFunctionCount', 'MaximumVariableCount'
	foreach ($v in (Get-Variable -Scope Global)) {
		if ($v.name -notin $default) {
			Remove-Variable -Name $v.name -Scope Global -Force -ErrorAction SilentlyContinue
		}
	}
	$defaultEnv = @(
		'TEMP','TMP','Path','PATHEXT','PSModulePath',
		'ComSpec','SystemRoot','windir',
		'USERNAME','USERPROFILE','HOMEDRIVE','HOMEPATH',
		'APPDATA','LOCALAPPDATA','ProgramData','PUBLIC',
		'ProgramFiles','ProgramFiles(x86)','ProgramW6432',
		'PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','OS',
		'ToolchainPath'
	)
	foreach ($e in (Get-ChildItem Env:)) {
		if ($e.Name -notin $defaultEnv) {
			Remove-Item "env:$($e.Name)" -Force -ErrorAction SilentlyContinue
		}
	}
	Remove-Item 'env:ToolchainLoadedPackages' -Force -ErrorAction SilentlyContinue
	Remove-Item 'env:ToolchainLoadedPackageRefs' -Force -ErrorAction SilentlyContinue
}

function RestoreSessionState {
	param (
		[Parameter(Mandatory)]
		[string]$GUID
	)
	$state = (Get-Variable "ToolchainSaveState_$GUID").value
	foreach ($v in $state.vars) {
		Set-Variable -Name $v.name -Value $v.value -Scope Global -Force -ErrorAction SilentlyContinue
	}
	foreach ($e in $state.env) {
		Set-Item -Path "env:$($e.name)" -Value $e.value -Force -ErrorAction SilentlyContinue
	}
	Remove-Variable "ToolchainSaveState_$GUID" -Force -Scope Global -ErrorAction SilentlyContinue
}

function GetPackageDefinition {
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [string]$Digest
  )
  if (-not $Digest) { return $null }

  if ($Digest.StartsWith('file:///')) {
    $root = ($Digest | ParseLocalPackageRef).Root
  } else {
    $root = ResolvePackagePath -Digest $Digest
  }

  $def = $null
  try {
    $def = GetToolchainDefinitionFromLabels -Ref $Digest -RootPath $root
  } catch {
    $def = $null
  }
  if ($def) { return $def }

  $tlcPath = Join-Path $root ".tlc"
  $pwrPath = Join-Path $root ".pwr"

  $defPath = $null
  if (Test-Path -LiteralPath $tlcPath) { $defPath = $tlcPath }
  elseif (Test-Path -LiteralPath $pwrPath) { $defPath = $pwrPath }

  if (-not $defPath) {
    $sample = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
                Select-Object -First 15 -ExpandProperty Name) -join ', '
    throw "Package definition not found (labels/.tlc/.pwr). Digest: $Digest. Root contents: $sample"
  }

  return (Get-Content -Raw -LiteralPath $defPath).
    Replace('${.}', $root.Replace('\','\\')) |
    ConvertFrom-Json |
    ConvertTo-HashTable
}

function Get-ToolchainLoadedRefKey {
	param(
		[Parameter(Mandatory)]
		[Collections.Hashtable]$Pkg
	)
	$cfg = if ($Pkg.Config) { [string]$Pkg.Config } else { 'default' }
	return "$($Pkg.Package):$($Pkg.Tag | AsTagString)::${cfg}"
}

function Get-ToolchainLoadedRefMap {
	$map = @{}
	$raw = $env:ToolchainLoadedPackageRefs
	if (-not $raw) {
		return $map
	}
	foreach ($entry in ($raw -split ';')) {
		if (-not $entry) { continue }
		$i = $entry.IndexOf('=')
		if ($i -le 0) { continue }
		$k = $entry.Substring(0, $i)
		$v = $entry.Substring($i + 1)
		if ($k -and $v) {
			$map[$k] = $v
		}
	}
	return $map
}

function Set-ToolchainLoadedRefMap {
	param(
		[Parameter(Mandatory)]
		[Collections.Hashtable]$Map
	)
	$parts = @()
	foreach ($k in ($Map.Keys | Sort-Object)) {
		$parts += "$k=$($Map[$k])"
	}
	$raw = ($parts -join ';')
	if ($raw) {
		$env:ToolchainLoadedPackageRefs = $raw
	} else {
		Remove-Item 'env:ToolchainLoadedPackageRefs' -Force -ErrorAction SilentlyContinue
	}
}

function Get-ToolchainPathEntriesFromPackageDefinition {
	param(
		[Parameter(Mandatory)]
		[Collections.Hashtable]$Pkg,
		[Parameter(Mandatory)]
		[string]$Digest
	)
	$defn = $Digest | GetPackageDefinition
	$cfgName = if ($Pkg.Config) { [string]$Pkg.Config } else { 'default' }
	$cfg = if ($cfgName -eq 'default') { $defn } else { $defn.$cfgName }
	if (-not $cfg -or -not $cfg.env -or -not $cfg.env.ContainsKey('Path')) {
		return @()
	}
	$joined = $cfg.env.Path | ConvertTo-SemicolonString
	if (-not $joined) {
		return @()
	}
	return @(
		$joined -split ';' |
			Where-Object { $_ -and $_.Trim() } |
			ForEach-Object { $_.Trim() }
	)
}

function Remove-ToolchainPathEntries {
	param(
		[string[]]$Entries
	)
	if (-not $Entries -or -not $env:Path) {
		return
	}
	$toRemove = @(
		$Entries |
			Where-Object { $_ -and $_.Trim() } |
			ForEach-Object { $_.Trim() }
	)
	if (-not $toRemove -or $toRemove.Count -eq 0) {
		return
	}
	$current = @(
		$env:Path -split ';' |
			Where-Object { $_ -and $_.Trim() } |
			ForEach-Object { $_.Trim() }
	)
	$filtered = [System.Collections.Generic.List[string]]::new()
	foreach ($entry in $current) {
		$drop = $false
		foreach ($r in $toRemove) {
			if ([string]::Equals($entry, $r, [StringComparison]::OrdinalIgnoreCase)) {
				$drop = $true
				break
			}
		}
		if (-not $drop) {
			[void]$filtered.Add($entry)
		}
	}
	$env:Path = ($filtered.ToArray() -join ';')
}


function ConfigurePackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg,
		[switch]$AppendPath
	)
	$digest = $Pkg | ResolvePackageDigest
	if (-not $digest) { throw "no such package $($Pkg.Package):$($Pkg.Tag | AsTagString)" }
	$ver = $null
	try {
		$m = [Db]::Get(('metadatadb', $digest))
		if ($m -and $m.Version) { $ver = $m.Version }
	} catch {
		Write-Debug "Metadata lookup failed for digest $($digest): $_"
	}
	Assert-ToolchainPolicyAllowed -Action 'load' -Package $Pkg.Package -Version $ver -Tag ($Pkg.Tag | AsTagString) -Digest $digest

	$defn = $Pkg.Digest | GetPackageDefinition
	$cfg = if ($Pkg.Config -eq 'default') { $defn } else { $defn.$($Pkg.Config) }
	if (-not $cfg) {
		throw "configuration '$($Pkg.Config)' not found for $($Pkg.Package):$($Pkg.Tag | AsTagString)"
	}

	Assert-ToolchainDefinition -Definition $defn -Context "$($Pkg.Package):$($Pkg.Tag | AsTagString)"

	foreach ($k in $cfg.env.keys) {
		$isPath = ($k -ieq 'Path')
		$val = $cfg.env.$k | ConvertTo-SemicolonString

		if ($isPath) {
			if ($AppendPath) {
				$pre = "$env:Path$(if ($env:Path -and -not $env:Path.EndsWith(';')) { ';' })"
				$post = ''
			} else {
				$pre = ''
				$post = "$(if ($env:Path) { ';' })$env:Path"
			}
			Set-Item "env:Path" "$pre$val$post"
		} else {
			Set-Item "env:$k" "$val"
		}
	}
}


function LoadPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	$digest = $Pkg | ResolvePackageDigest
	$ref = "$($Pkg.Package):$($Pkg.Tag | AsTagString)"
	if (-not $digest) {
		throw "no such package $ref"
	}
	$Pkg.Digest = $digest
	Write-ToolchainInfo "Digest: $digest"

	$refKey = Get-ToolchainLoadedRefKey -Pkg $Pkg
	$loadedRefMap = Get-ToolchainLoadedRefMap
	$previousDigest = if ($loadedRefMap.ContainsKey($refKey)) { [string]$loadedRefMap[$refKey] } else { $null }

	if ($previousDigest -and $previousDigest -ne $digest) {
		try {
			$oldPathEntries = Get-ToolchainPathEntriesFromPackageDefinition -Pkg $Pkg -Digest $previousDigest
			Remove-ToolchainPathEntries -Entries $oldPathEntries
		} catch {
			Write-Debug "failed to remove previous path entries for ${ref}: $($_.Exception.Message)"
		}
	}

	$shouldConfigure = (-not $previousDigest -or $previousDigest -ne $digest)
	if ($shouldConfigure) {
		$Pkg | ConfigurePackage
		Write-ToolchainInfo "Status: Session configured for $ref"
	} else {
		Write-ToolchainInfo "Status: Session is up to date for $ref"
	}

	$loadedRefMap[$refKey] = $digest
	Set-ToolchainLoadedRefMap -Map $loadedRefMap

	$loadedDigests = @(
		$loadedRefMap.Values |
			ForEach-Object { [string]$_ } |
			Where-Object { $_ -and $_.Trim() } |
			ForEach-Object { $_.Trim() } |
			Select-Object -Unique
	)
	$loadedJoined = ($loadedDigests -join ';')
	if ($loadedJoined) {
		$env:ToolchainLoadedPackages = $loadedJoined
	} else {
		Remove-Item 'env:ToolchainLoadedPackages' -Force -ErrorAction SilentlyContinue
	}
}

function ExecuteScript {
	param (
		[Parameter(Mandatory)]
		[scriptblock]$ScriptBlock,
		[Parameter(Mandatory)]
		[Collections.Hashtable[]]$Pkgs
	)
	$GUID = New-Guid
	SaveSessionState $GUID
	try {
		ClearSessionState $GUID
		$env:Path = ''
		foreach ($pkg in $Pkgs) {
			$pkg.digest = $pkg | ResolvePackageDigest
			$ref = "$($Pkg.Package):$($Pkg.Tag | AsTagString)"
			if (-not $pkg.digest) {
				throw "no such package $ref"
			}
			$pkg | ConfigurePackage -AppendPath
		}
		$env:Path = "$(if ($env:Path) { "$env:Path;" })$env:SYSTEMROOT;$env:SYSTEMROOT\System32;$PSHOME"
		& $ScriptBlock
	} finally {
		RestoreSessionState $GUID
	}
}
