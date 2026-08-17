<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain nested argument completion' {
	It 'creates a standard PowerShell completion result' {
		$result = New-ToolchainCompletionResult -Value 'cluster'
		$result.CompletionText | Should -Be 'cluster'
		$result.ListItemText | Should -Be 'cluster'
		$result.ToolTip | Should -Be 'cluster'
	}

	It 'covers grouped commands, scalar options, and fallback help' {
		@(Get-ToolchainNestedCompletionValues -Subcommand remote -Elements @('tlc','remote','m') -WordToComplete 'm') | Should -Be @('models')
		@(Get-ToolchainNestedCompletionValues -Subcommand remote -Elements @('tlc','remote','health','-O') -WordToComplete '-O') | Should -Be @('-OnlyProblems')
		@(Get-ToolchainNestedCompletionValues -Subcommand profile -Elements @('tlc','profile','a') -WordToComplete 'a') | Should -Be @('add')
		@(Get-ToolchainNestedCompletionValues -Subcommand profile -Elements @('tlc','profile','add','h') -WordToComplete 'h') | Should -Be @('help')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('tlc','cluster','create','dev','-Engine','p') -WordToComplete 'p') | Should -Be @('podman')
		@(Get-ToolchainNestedCompletionValues -Subcommand doctor -Elements @('tlc','doctor','-J') -WordToComplete '-J') | Should -Be @('-Json')
		@(Get-ToolchainNestedCompletionValues -Subcommand lock -Elements @('tlc','lock','-U') -WordToComplete '-U') | Should -Be @('-Update')
		@(Get-ToolchainNestedCompletionValues -Subcommand restore -Elements @('tlc','restore') -WordToComplete '') | Should -Contain '-Path'
		@(Get-ToolchainNestedCompletionValues -Subcommand sync -Elements @('tlc','sync','-F') -WordToComplete '-F') | Should -Be @('-Frozen')
		@(Get-ToolchainNestedCompletionValues -Subcommand activate -Elements @('tlc','activate') -WordToComplete '') | Should -Contain '-NoSync'
		@(Get-ToolchainNestedCompletionValues -Subcommand deactivate -Elements @('tlc','deactivate') -WordToComplete '') | Should -Contain '-PassThru'
		@(Get-ToolchainNestedCompletionValues -Subcommand verify -Elements @('tlc','verify') -WordToComplete '') | Should -Contain '-Json'
		@(Get-ToolchainNestedCompletionValues -Subcommand audit -Elements @('tlc','audit','-V') -WordToComplete '-V') | Should -Be @('-VerifySignatures')
		@(Get-ToolchainNestedCompletionValues -Subcommand unknown -Elements @('tlc','unknown') -WordToComplete '--') | Should -Be @('--help')
	}

	It 'completes cluster subcommands and create options' {
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','cr') -WordToComplete 'cr') |
			Should -Be @('create')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','create') -WordToComplete '') |
			Should -Contain '-Provider'
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','init') -WordToComplete '') |
			Should -Contain '-Confirm'
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','init','-RegistryN') -WordToComplete '-RegistryN') |
			Should -Be @('-RegistryNodePort')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','init','-Components','g') -WordToComplete 'g') |
			Should -Be @('git-server')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','create') -WordToComplete '') |
			Should -Contain 'help'
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','u') -WordToComplete 'u') |
			Should -Be @('use')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','current') -WordToComplete '') |
			Should -Contain '-PassThru'
	}

	It 'completes cluster providers after the nested provider option' {
		$values = @(Get-ToolchainNestedCompletionValues -Subcommand cluster `
			-Elements @('toolchain','cluster','create','dev','-Provider','k') -WordToComplete 'k')
		$values | Should -Be @('kind','k0s','k3s')
	}

	It 'offers command-scoped help across simple and grouped commands' {
		@(Get-ToolchainNestedCompletionValues -Subcommand load -Elements @('tlc','load') -WordToComplete '') |
			Should -Contain 'help'
		@(Get-ToolchainNestedCompletionValues -Subcommand remote -Elements @('tlc','remote','list') -WordToComplete '') |
			Should -Contain '--help'
		@(Get-ToolchainNestedCompletionValues -Subcommand profile -Elements @('tlc','profile','add') -WordToComplete '') |
			Should -Contain 'help'
		@(Get-ToolchainNestedCompletionValues -Subcommand help -Elements @('tlc','help','cl') -WordToComplete 'cl') |
			Should -Be @('cluster')
	}

	It 'completes Toolchain and native K9s options' {
		@(Get-ToolchainNestedCompletionValues -Subcommand k9s -Elements @('tlc','k9s') -WordToComplete '') |
			Should -Contain '-Cluster'
		@(Get-ToolchainNestedCompletionValues -Subcommand k9s -Elements @('tlc','k9s','--read') -WordToComplete '--read') |
			Should -Be @('--readonly')
	}

	It 'registers command, argument-list, and native completers' {
		$script:registrations = @()
		Mock Register-ArgumentCompleter {
			param($CommandName, $ParameterName, $ScriptBlock, [switch]$Native)
			$script:registrations += [pscustomobject]@{
				Native = [bool]$Native
				ParameterName = $ParameterName
				ScriptBlock = $ScriptBlock
			}
		}

		Register-ToolchainArgumentCompleters
		$script:registrations.Count | Should -Be 3

		$commandRegistration = @($script:registrations | Where-Object ParameterName -eq 'Command')[0]
		$commandResults = @(& $commandRegistration.ScriptBlock 'tlc' 'Command' 'cl')
		$commandResults.CompletionText | Should -Be @('cluster')

		$tokens = $null
		$errors = $null
		$ast = [Management.Automation.Language.Parser]::ParseInput('tlc cluster create dev -Provider k', [ref]$tokens, [ref]$errors)
		$commandAst = $ast.EndBlock.Statements[0].PipelineElements[0]
		$argumentRegistration = @($script:registrations | Where-Object ParameterName -eq 'ArgumentList')[0]
		$argumentResults = @(& $argumentRegistration.ScriptBlock 'tlc' 'ArgumentList' 'k' $commandAst)
		$argumentResults.CompletionText | Should -Contain 'kind'

		$nativeAst = [Management.Automation.Language.Parser]::ParseInput('tlc cl', [ref]$tokens, [ref]$errors)
		$nativeCommandAst = $nativeAst.EndBlock.Statements[0].PipelineElements[0]
		$nativeRegistration = @($script:registrations | Where-Object Native)[0]
		$nativeResults = @(& $nativeRegistration.ScriptBlock 'cl' $nativeCommandAst 2)
		$nativeResults.CompletionText | Should -Contain 'cluster'
	}
}
