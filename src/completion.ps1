<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function New-ToolchainCompletionResult {
	param([Parameter(Mandatory)][string]$Value)
	return [Management.Automation.CompletionResult]::new($Value, $Value, 'ParameterValue', $Value)
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

	switch ($Subcommand) {
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
		'cluster' {
			if ($previous -eq '-Provider') { return @('kind','k0s','k3s') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-Engine') { return @('auto','docker','podman','nerdctl') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-AgentMutationPolicy') { return @('all','labeled') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($previous -eq '-Components') { return @('git-server') | Where-Object { $_ -like "$WordToComplete*" } }
			if ($Elements.Count -le 2 -or ($Elements.Count -eq 3 -and $WordToComplete)) {
				return @('create','init','list','status','kubeconfig','use','current','delete') + $helpValues | Where-Object { $_ -like "$WordToComplete*" }
			}
			$options = switch ($Elements[2]) {
				'create' { @('-Provider','-Engine','-Servers','-Workers','-ApiPort','-WaitSeconds','-Image','-Config') }
				'init' { @('-Kubeconfig','-Confirm','-Components','-AgentMutationPolicy','-StorageClass','-RegistryStorage','-GitStorage','-RegistryNodePort','-WaitSeconds','-PassThru') }
				'list' { @('-Provider') }
				'kubeconfig' { @('-Raw') }
				'use' { @('-PassThru') }
				'current' { @('-PassThru') }
				default { @() }
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
			return @('version','remote','list','load','pull','exec','run','remove','save','prune','update','init','lock','restore','sync','activate','deactivate','verify','audit','profile','cluster','k9s','doctor') |
				Where-Object { $_ -like "$WordToComplete*" }
		}
	}
	return $helpValues | Where-Object { $_ -like "$WordToComplete*" }
}

$script:ToolchainCompletionCommands = @('version','remote','list','load','pull','exec','run','remove','save','prune','update','init','lock','restore','sync','activate','deactivate','verify','audit','profile','cluster','k9s','doctor','help')

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
