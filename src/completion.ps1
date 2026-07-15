<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function New-ToolchainCompletionResult {
	param([Parameter(Mandatory)][string]$Value)
	return [Management.Automation.CompletionResult]::new($Value, $Value, 'ParameterValue', $Value)
}

function Register-ToolchainArgumentCompleters {
	$commands = @('version','remote','list','load','pull','exec','run','remove','save','prune','update','init','profile','doctor','help')
	Register-ArgumentCompleter -CommandName Invoke-Toolchain,toolchain,tool,tlc -ParameterName Command -ScriptBlock {
		param($commandName, $parameterName, $wordToComplete)
		$commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
	}

	Register-ArgumentCompleter -CommandName Invoke-Toolchain,toolchain,tool,tlc -ParameterName ArgumentList -ScriptBlock {
		param($commandName, $parameterName, $wordToComplete, $commandAst)
		$subcommand = if ($commandAst.CommandElements.Count -gt 1) { [string]$commandAst.CommandElements[1].Value } else { '' }
		if ($subcommand -eq 'remote') {
			@('list','models','all','tags','-Refresh','-Json') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
			return
		}
		if ($subcommand -eq 'profile') {
			if ($commandAst.CommandElements.Count -le 3) {
				@('init','add','remove','list','path') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
			}
			return
		}
		if ($subcommand -eq 'doctor') {
			@('-Strict','-PassThru','-Json','-Refresh') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { New-ToolchainCompletionResult $_ }
		}
	}
}
