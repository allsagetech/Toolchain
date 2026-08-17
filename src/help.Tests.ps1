<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain command help catalog' {
	It 'covers every top-level and nested command' {
		$expected = @(
			'version','list','remote','remote list','remote models','remote all','remote tags',
			'remote health','remote info',
			'pull','load','exec','run','update','prune','remove','save','init',
			'lock','restore','sync','activate','deactivate','verify','audit',
			'profile','profile init','profile add','profile remove','profile list','profile path',
			'cluster','cluster create','cluster init','cluster list','cluster status','cluster kubeconfig','cluster delete',
			'k9s','doctor','help'
		)
		$topics = Get-ToolchainHelpTopics
		@($topics.Keys) | Should -Be $expected
		foreach ($key in $expected) {
			$text = Invoke-ToolchainHelp -CommandPath ($key -split ' ')
			$text | Should -Match ([regex]::Escape("Toolchain command: $key"))
			$text | Should -Match 'Description:'
			$text | Should -Match 'Usage:'
			$text | Should -Match 'Documentation:'
		}
	}

	It 'returns an overview with command-scoped help instructions' {
		$text = Invoke-ToolchainHelp
		$text | Should -Match 'Toolchain command line help'
		$text | Should -Match 'tlc COMMAND help'
		$text | Should -Match 'remote'
		$text | Should -Match 'cluster'
		$text | Should -Match 'k9s'
		$text | Should -Match 'audit'
		$text | Should -Match 'sync'
		$text | Should -Match 'activate'
	}

	It 'normalizes command aliases in help paths' {
		(Invoke-ToolchainHelp -CommandPath @('v')) | Should -Match 'Toolchain command: version'
		(Invoke-ToolchainHelp -CommandPath @('rm')) | Should -Match 'Toolchain command: remove'
		(Invoke-ToolchainHelp -CommandPath @('H')) | Should -Match 'Toolchain command: help'
	}

	It 'rejects unknown help topics with a useful recovery command' {
		{ Invoke-ToolchainHelp -CommandPath @('missing') } | Should -Throw "*Run 'tlc help'*"
	}
}

Describe 'Toolchain help request routing' {
	It 'recognizes supported help tokens' {
		foreach ($token in @('help','h','-h','--help','?','/?','HELP')) {
			Test-ToolchainHelpToken $token | Should -BeTrue
		}
		Test-ToolchainHelpToken $null | Should -BeFalse
		Test-ToolchainHelpToken 'node' | Should -BeFalse
	}

	It 'routes suffix help for top-level and nested commands' {
		$request = Get-ToolchainHelpRequest -Command load -ArgumentList @('help')
		$request.Requested | Should -BeTrue
		$request.CommandPath | Should -Be @('load')
		(Get-ToolchainHelpRequest -Command load -ArgumentList @('node','--help')).CommandPath | Should -Be @('load')

		$request = Get-ToolchainHelpRequest -Command cluster -ArgumentList @('create','--help')
		$request.Requested | Should -BeTrue
		$request.CommandPath | Should -Be @('cluster','create')
		(Get-ToolchainHelpRequest -Command cluster -ArgumentList @('create','dev','--help')).CommandPath | Should -Be @('cluster','create')
		(Get-ToolchainHelpRequest -Command cluster -ArgumentList @('init','--help')).CommandPath | Should -Be @('cluster','init')
		(Get-ToolchainHelpRequest -Command remote -ArgumentList @('-Refresh','help')).CommandPath | Should -Be @('remote')
	}

	It 'routes prefix help and preserves the help topic itself' {
		(Get-ToolchainHelpRequest -Command help -ArgumentList @()).CommandPath.Count | Should -Be 0
		(Get-ToolchainHelpRequest -Command help -ArgumentList @('remote','tags')).CommandPath | Should -Be @('remote','tags')
		(Get-ToolchainHelpRequest -Command help -ArgumentList @('help')).CommandPath | Should -Be @('help')
		(Get-ToolchainHelpRequest -Command help -ArgumentList @('--help')).CommandPath.Count | Should -Be 0
	}

	It 'does not intercept ordinary command arguments' {
		$request = Get-ToolchainHelpRequest -Command load -ArgumentList @('node')
		$request.Requested | Should -BeFalse
		$request.CommandPath.Count | Should -Be 0
	}
}
