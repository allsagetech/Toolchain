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
	}

	It 'completes cluster providers after the nested provider option' {
		$values = @(Get-ToolchainNestedCompletionValues -Subcommand cluster `
			-Elements @('toolchain','cluster','create','dev','-Provider','k') -WordToComplete 'k')
		$values | Should -Be @('kind','k0s','k3s')
	}
}
