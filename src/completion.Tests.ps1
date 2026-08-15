<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain nested argument completion' {
	It 'completes cluster subcommands and create options' {
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','cr') -WordToComplete 'cr') |
			Should -Be @('create')
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','create') -WordToComplete '') |
			Should -Contain '-Provider'
		@(Get-ToolchainNestedCompletionValues -Subcommand cluster -Elements @('toolchain','cluster','create') -WordToComplete '') |
			Should -Contain 'help'
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
}
