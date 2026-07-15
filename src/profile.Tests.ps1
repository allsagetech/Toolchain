<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'log.ps1')
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain PowerShell profile management' {
	BeforeEach {
		$caseDirectory = 'case-' + [guid]::NewGuid().ToString('n')
		$script:testProfile = Join-Path $TestDrive "$caseDirectory\Microsoft.PowerShell_profile.ps1"
		Mock Get-ToolchainPowerShellProfilePath { $script:testProfile }
	}

	It 'Returns the current-user current-host profile path without creating it' {
		Invoke-ToolchainProfile -Command path | Should -Be $script:testProfile
		Test-Path -LiteralPath $script:testProfile | Should -BeFalse
	}

	It 'Creates an empty profile and its parent directory' {
		Invoke-ToolchainProfile -Command init

		Test-Path -LiteralPath $script:testProfile -PathType Leaf | Should -BeTrue
		[IO.File]::ReadAllText($script:testProfile) | Should -BeExactly ''
	}

	It 'Leaves an existing profile unchanged during init' {
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $script:testProfile))
		[IO.File]::WriteAllText($script:testProfile, "Set-Alias old new`r`n")

		Invoke-ToolchainProfile -Command init

		[IO.File]::ReadAllText($script:testProfile) | Should -BeExactly "Set-Alias old new`r`n"
	}

	It 'Adds packages to a clearly marked managed block' {
		Invoke-ToolchainProfile -Command add -Packages @('node', 'git:latest')

		$content = [IO.File]::ReadAllText($script:testProfile)
		$content | Should -Match '(?m)^# >>> Toolchain managed packages >>>\r?$'
		$content | Should -Match "(?m)^toolchain load 'node'\r?$"
		$content | Should -Match "(?m)^toolchain load 'git:latest'\r?$"
		$content | Should -Match '(?m)^# <<< Toolchain managed packages <<<\r?$'
		@(Invoke-ToolchainProfile -Command list) | Should -Be @('node', 'git:latest')
	}

	It 'Does not add the same package twice' {
		Invoke-ToolchainProfile -Command add -Packages @('node', 'NODE')
		Invoke-ToolchainProfile -Command add -Packages @('Node')

		@(Invoke-ToolchainProfile -Command list) | Should -Be @('node')
		([regex]::Matches([IO.File]::ReadAllText($script:testProfile), "(?m)^toolchain load ")).Count | Should -Be 1
	}

	It 'quotes package references as safe PowerShell literals' {
		Invoke-ToolchainProfile -Command add -Packages @("team's-node")

		[IO.File]::ReadAllText($script:testProfile) | Should -Match "(?m)^toolchain load 'team''s-node'\r?$"
		@(Invoke-ToolchainProfile -Command list) | Should -Be @("team's-node")
	}

	It 'preserves unrelated content and removes only managed package lines' {
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $script:testProfile))
		$original = "Set-Alias my-command Get-ChildItem`r`n"
		[IO.File]::WriteAllText($script:testProfile, $original)
		Invoke-ToolchainProfile -Command add -Packages @('node', 'git')

		Invoke-ToolchainProfile -Command remove -Packages @('node')

		$content = [IO.File]::ReadAllText($script:testProfile)
		$content | Should -Match '(?m)^Set-Alias my-command Get-ChildItem\r?$'
		$content | Should -Not -Match "(?m)^toolchain load 'node'\r?$"
		$content | Should -Match "(?m)^toolchain load 'git'\r?$"

		Invoke-ToolchainProfile -Command remove -Packages @('git')
		[IO.File]::ReadAllText($script:testProfile) | Should -BeExactly $original
	}

	It 'does not remove a matching line written outside the managed block' {
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $script:testProfile))
		$manual = "toolchain load 'node'`r`n"
		[IO.File]::WriteAllText($script:testProfile, $manual)
		Invoke-ToolchainProfile -Command add -Packages @('node')

		Invoke-ToolchainProfile -Command remove -Packages @('node')

		[IO.File]::ReadAllText($script:testProfile) | Should -BeExactly $manual
	}

	It 'rejects line breaks in package references' {
		{ Invoke-ToolchainProfile -Command add -Packages @("node`nWrite-Host injected") } | Should -Throw '*cannot contain line breaks*'
	}

	It 'refuses to rewrite a malformed managed block' {
		[void][IO.Directory]::CreateDirectory((Split-Path -Parent $script:testProfile))
		$original = "# >>> Toolchain managed packages >>>`r`nWrite-Host unexpected`r`n# <<< Toolchain managed packages <<<`r`n"
		[IO.File]::WriteAllText($script:testProfile, $original)

		{ Invoke-ToolchainProfile -Command add -Packages @('node') } | Should -Throw '*unrecognized line*'
		[IO.File]::ReadAllText($script:testProfile) | Should -BeExactly $original
	}

	It 'does not create a profile for list or remove' {
		@(Invoke-ToolchainProfile -Command list).Count | Should -Be 0
		Invoke-ToolchainProfile -Command remove -Packages @('node')
		Test-Path -LiteralPath $script:testProfile | Should -BeFalse
	}

	It 'requires packages only for add and remove' {
		{ Invoke-ToolchainProfile -Command add } | Should -Throw '*requires at least one package*'
		{ Invoke-ToolchainProfile -Command remove } | Should -Throw '*requires at least one package*'
		{ Invoke-ToolchainProfile -Command init -Packages @('node') } | Should -Throw '*use profile add*'
	}
}
