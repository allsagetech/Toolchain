<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function New-ToolchainCompletionResult {
	param([Parameter(Mandatory)][string]$Value)
	return [Management.Automation.CompletionResult]::new($Value, $Value, 'ParameterValue', $Value)
}

function Get-ToolchainCompletionMatches {
	param(
		[AllowEmptyCollection()][string[]]$Values,
		[AllowEmptyString()][string]$WordToComplete = ''
	)

	$completionMatches = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
	foreach ($value in @($Values)) {
		if ([string]::IsNullOrWhiteSpace($value)) { continue }
		if ($WordToComplete -and -not $value.StartsWith($WordToComplete, [StringComparison]::OrdinalIgnoreCase)) { continue }
		[void]$completionMatches.Add($value)
	}
	return @($completionMatches | Sort-Object)
}

function ConvertTo-ToolchainCompletionPackageName {
	param([AllowEmptyString()][string]$Reference)

	if ([string]::IsNullOrWhiteSpace($Reference) -or $Reference.StartsWith('file:///', [StringComparison]::OrdinalIgnoreCase)) {
		return $null
	}
	$match = [regex]::Match($Reference.Trim(), '^([A-Za-z0-9][A-Za-z0-9._-]*)')
	if (-not $match.Success) { return $null }
	return $match.Groups[1].Value
}

function Get-ToolchainCompletionProfilePackageNames {
	$profilePathCommand = Get-Command -Name 'Get-ToolchainPowerShellProfilePath' -ErrorAction SilentlyContinue
	$profileStateCommand = Get-Command -Name 'Read-ToolchainProfileState' -ErrorAction SilentlyContinue
	if (-not $profilePathCommand -or -not $profileStateCommand) { return @() }

	try {
		$state = Read-ToolchainProfileState -Path (Get-ToolchainPowerShellProfilePath)
		return @(foreach ($package in @($state.Packages)) { ConvertTo-ToolchainCompletionPackageName -Reference ([string]$package) })
	} catch {
		Write-Debug "Toolchain profile completion skipped: $($_.Exception.Message)"
		return @()
	}
}

function Get-ToolchainCompletionPackageNames {
	$names = [Collections.Generic.List[string]]::new()
	$addReference = {
		param([AllowEmptyString()][string]$Reference)
		$name = ConvertTo-ToolchainCompletionPackageName -Reference $Reference
		if ($name) { $names.Add($name) }
	}

	if (Get-Command -Name 'GetConfigPackages' -ErrorAction SilentlyContinue) {
		try { foreach ($package in @(GetConfigPackages)) { & $addReference ([string]$package) } }
		catch { Write-Debug "Toolchain project-package completion skipped: $($_.Exception.Message)" }
	}
	foreach ($package in @(Get-ToolchainCompletionProfilePackageNames)) { & $addReference $package }

	if (Get-Command -Name 'GetLocalPackages' -ErrorAction SilentlyContinue) {
		try {
			foreach ($package in @(GetLocalPackages)) {
				if ($package -and $package.Package) { & $addReference ([string]$package.Package) }
			}
		} catch { Write-Debug "Toolchain local-package completion skipped: $($_.Exception.Message)" }
	}

	if (Get-Command -Name 'Read-ToolchainCatalogCache' -ErrorAction SilentlyContinue) {
		try {
			$catalog = Read-ToolchainCatalogCache -AllowStale
			foreach ($tag in @($catalog.Tags)) {
				$metadata = if (Get-Command -Name 'Test-ToolchainRegistryMetadataTag' -ErrorAction SilentlyContinue) {
					Test-ToolchainRegistryMetadataTag -Tag ([string]$tag)
				} else {
					([string]$tag -match '(?i)^(sha256-[0-9a-f]{64}\.(sig|att|sbom)|sbom-v[0-9]+-|tlc-kind-|tlc-catalog-|tlc-platform-|staging-)')
				}
				if ($metadata -or [string]$tag -notmatch '^(.*)-([0-9].+)$') { continue }
				& $addReference $Matches[1]
			}
		} catch { Write-Debug "Toolchain catalog completion skipped: $($_.Exception.Message)" }
	}

	return @(Get-ToolchainCompletionMatches -Values $names.ToArray())
}

function Get-ToolchainCompletionClusterNames {
	if (-not (Get-Command -Name 'Get-ToolchainClusterStates' -ErrorAction SilentlyContinue)) { return @() }
	try {
		return @(Get-ToolchainClusterStates -WarningAction SilentlyContinue | ForEach-Object { [string]$_.name } | Where-Object { $_ })
	} catch {
		Write-Debug "Toolchain cluster completion skipped: $($_.Exception.Message)"
		return @()
	}
}

function Get-ToolchainNestedCompletionValues {
	param(
		[Parameter(Mandatory)][string]$Subcommand,
		[Parameter(Mandatory)][string[]]$Elements,
		[AllowEmptyString()][string]$WordToComplete = ''
	)
	$helpValues = @('help','--help')

	$previous = if ($WordToComplete -and $Elements.Count -gt 1) {
		$Elements[$Elements.Count - 2]
	} elseif ($Elements.Count -gt 0) {
		$Elements[$Elements.Count - 1]
	} else {
		''
	}
	if ($previous -eq '-Cluster') {
		return Get-ToolchainCompletionMatches -Values (Get-ToolchainCompletionClusterNames) -WordToComplete $WordToComplete
	}

	if ($Subcommand -in @('load','pull','remove','save','exec') -and
		$previous -notin @('-Output','-Path') -and -not $WordToComplete.StartsWith('-')) {
		return Get-ToolchainCompletionMatches -Values (@(Get-ToolchainCompletionPackageNames) + $helpValues) -WordToComplete $WordToComplete
	}

	if ($Subcommand -eq 'profile' -and $Elements.Count -ge 3 -and $Elements[2] -in @('add','remove') -and -not $WordToComplete.StartsWith('-')) {
		$packages = if ($Elements[2] -eq 'remove') { Get-ToolchainCompletionProfilePackageNames } else { Get-ToolchainCompletionPackageNames }
		return Get-ToolchainCompletionMatches -Values (@($packages) + $helpValues) -WordToComplete $WordToComplete
	}

	if ($Subcommand -eq 'remote' -and $Elements.Count -ge 4 -and $Elements[2] -in @('list','models','all','health','info') -and -not $WordToComplete.StartsWith('-')) {
		return Get-ToolchainCompletionMatches -Values (@(Get-ToolchainCompletionPackageNames) + $helpValues) -WordToComplete $WordToComplete
	}

	switch ($Subcommand) {
		'completion' {
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('enable','disable','status') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			return $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'shell' {
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('pwsh') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			return $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'remote' {
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('list','models','all','health','info','tags') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			return @('-Refresh','-Json','-OnlyProblems') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'profile' {
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('init','add','remove','list','path') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			return $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'package' {
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('create','deploy','remove') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			$options = switch ($Elements[2]) {
				'create' { @('-Output','-Force') }
				'deploy' { @('-Components','-Set','-Cluster','-Kubeconfig','-Values','-Config','-Namespace','-WaitSeconds','-Confirm','-DryRun','-NoRollback','-PassThru') }
				'remove' { @('-Components','-Set','-Cluster','-Kubeconfig','-Config','-Namespace','-WaitSeconds','-Confirm','-DryRun','-PassThru') }
				default { @() }
			}
			return @($options) + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'cluster' {
			if ($previous -eq '-Provider') { return @('kind','k0s','k3s') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-Engine') { return @('auto','docker','podman','nerdctl') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-AgentMutationPolicy') { return @('all','labeled') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-Components') { return @('git-server','none') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('create','init','deinit','reset','restore','doctor','list','status','kubeconfig','use','current','delete') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			$clusterCommand = [string]$Elements[2]
			$options = switch ($clusterCommand) {
				'create' { @('-Provider','-Engine','-Servers','-Workers','-ApiPort','-WaitSeconds','-Image','-Config') }
				'init' { @('-Kubeconfig','-Confirm','-Components','-AgentMutationPolicy','-StorageClass','-RegistryStorage','-GitStorage','-RegistryNodePort','-WaitSeconds','-PassThru') }
				'deinit' { @('-Kubeconfig','-Confirm','-KeepStorage','-BackupPath','-Force','-DryRun','-WaitSeconds','-PassThru') }
				'reset' { @('-Kubeconfig','-Confirm','-Components','-KeepStorage','-BackupPath','-Force','-DryRun','-WaitSeconds','-PassThru') }
				'restore' { @('-Kubeconfig','-Confirm','-DryRun','-PassThru') }
				'doctor' { @('-Kubeconfig','-Raw','-Force','-PassThru') }
				'list' { @('-Provider') }
				'kubeconfig' { @('-Raw') }
				'use' { @('-PassThru') }
				'current' { @('-PassThru') }
				default { @() }
			}
			if ($clusterCommand -in @('init','deinit','reset','restore','doctor','status','kubeconfig','use','delete') -and -not $WordToComplete.StartsWith('-')) {
				return Get-ToolchainCompletionMatches -Values (@(Get-ToolchainCompletionClusterNames) + @($options) + $helpValues) -WordToComplete $WordToComplete
			}
			return @($options) + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
		}
		'k9s' {
			return @('-Cluster','-Kubeconfig','--all-namespaces','--command','--context','--namespace','--readonly') + $helpValues |
				Where-Object { $_ -like "$WordToComplete*" }
		}
		'doctor' { return @('-Strict','-PassThru','-Json','-Refresh') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'lock' { return @('-Packages','-Path','-Update') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'restore' { return @('-Path') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'sync' { return @('-Path','-Update','-Frozen','-NoRestore','-Activate','-PassThru') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'activate' { return @('-Path','-NoSync','-PassThru') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'deactivate' { return @('-PassThru') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'audit' { return @('-Path','-Refresh','-VerifySignatures','-Fix','-WhatIf','-Confirm','-Strict','-Json') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'verify' { return @('-Json') + $helpValues | Where-Object { $_ -like "$WordToComplete*" } }
		'help' {
			return @('version','remote','list','load','pull','exec','run','shell','remove','save','prune','update','init','lock','restore','sync','activate','deactivate','verify','audit','profile','package','cluster','k9s','doctor','completion') |
				Where-Object { $_ -like "$WordToComplete*" }
		}
	}
	return $helpValues | Where-Object { $_ -like "$WordToComplete*" }
}

$script:ToolchainCompletionCommands = @('version','remote','list','load','pull','exec','run','shell','remove','save','prune','update','init','lock','restore','sync','activate','deactivate','verify','audit','profile','package','cluster','k9s','doctor','completion','help')

function Register-ToolchainArgumentCompleters {
	Register-ArgumentCompleter -CommandName Invoke-Toolchain,toolchain,tool,tlc -ParameterName Command -ScriptBlock {
		param($commandName, $parameterName, $wordToComplete)
		$script:ToolchainCompletionCommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
	}

	Register-ArgumentCompleter -CommandName Invoke-Toolchain,toolchain,tool,tlc -ParameterName ArgumentList -ScriptBlock {
		param($commandName, $parameterName, $wordToComplete, $commandAst)
		$subcommand = if ($commandAst.CommandElements.Count -gt 1) { [string]$commandAst.CommandElements[1].Value } else { '' }
		$elements = @($commandAst.CommandElements | ForEach-Object {
			if ($_ -is [Management.Automation.Language.CommandParameterAst]) { '-' + $_.ParameterName } else { [string]$_.Value }
		})
		Get-ToolchainNestedCompletionValues -Subcommand $subcommand -Elements $elements -WordToComplete $wordToComplete |
			ForEach-Object { New-ToolchainCompletionResult $_ }
	}

	Register-ArgumentCompleter -Native -CommandName toolchain,tool,tlc -ScriptBlock {
		param($wordToComplete, $commandAst, $cursorPosition)
		$elements = @($commandAst.CommandElements | ForEach-Object {
			if ($_ -is [Management.Automation.Language.CommandParameterAst]) { '-' + $_.ParameterName } else { [string]$_.Value }
		})
		if ($elements.Count -le 1 -or ($elements.Count -eq 2 -and $wordToComplete)) {
			$script:ToolchainCompletionCommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
			return
		}
		$subcommand = if ($elements.Count -gt 1) { $elements[1] } else { '' }
		Get-ToolchainNestedCompletionValues -Subcommand $subcommand -Elements $elements -WordToComplete $wordToComplete |
			ForEach-Object { New-ToolchainCompletionResult $_ }
	}
}
