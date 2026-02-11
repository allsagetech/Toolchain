<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\shell.ps1"
	. "$PSScriptRoot\log.ps1"
}

Describe 'Session state management' {
	It 'saves, clears, and restores global variables and env vars' {
		$guid = 'abc'
		Set-Variable -Name 'ToolchainTestVar' -Scope Global -Value 42 -Force
		$env:TOOLCHAIN_TEST_ENV = 'hello'
		SaveSessionState $guid
		ClearSessionState $guid
		(Get-Variable -Name 'ToolchainTestVar' -Scope Global -ErrorAction SilentlyContinue) | Should -Be $null
		$env:TOOLCHAIN_TEST_ENV | Should -Be $null
		RestoreSessionState $guid
		(Get-Variable -Name 'ToolchainTestVar' -Scope Global).Value | Should -Be 42
		$env:TOOLCHAIN_TEST_ENV | Should -Be 'hello'
		(Get-Variable -Name "ToolchainSaveState_$guid" -Scope Global -ErrorAction SilentlyContinue) | Should -Be $null
		Remove-Variable -Name 'ToolchainTestVar' -Scope Global -Force -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_TEST_ENV -ErrorAction SilentlyContinue
	}
}

Describe 'GetPackageDefinition' {
	It 'returns definition from labels when present' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		Mock GetToolchainDefinitionFromLabels { @{ env = @{ FOO = 'BAR' } } }
		$def = GetPackageDefinition -Digest ("file:///$root")
		$def.env.FOO | Should -Be 'BAR'
		Remove-Item -Recurse -Force $root
	}

	It 'reads .tlc when label definition is absent' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		Mock GetToolchainDefinitionFromLabels { throw 'no labels' }
		'{"env":{"ROOT":"${.}"}}' | Set-Content -LiteralPath (Join-Path $root '.tlc')
		$def = GetPackageDefinition -Digest ("file:///$root<ignored>")
		$def.env.ROOT | Should -Match ([Regex]::Escape($root))
		Remove-Item -Recurse -Force $root
	}

	It 'throws when no definition exists' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		New-Item -ItemType File -Path (Join-Path $root 'a.txt') | Out-Null
		Mock GetToolchainDefinitionFromLabels { throw 'no labels' }
		{ GetPackageDefinition -Digest ("file:///$root") } | Should -Throw '*Package definition not found*Root contents*'
		Remove-Item -Recurse -Force $root
	}
}

Describe 'ConfigurePackage and LoadPackage' {
	BeforeEach {
		$env:ToolchainLoadedPackages = ''
		Mock Assert-ToolchainPolicyAllowed { }
		Mock Assert-ToolchainDefinition { }
	}

	It 'throws when digest is missing' {
		{ ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Config='default' } } | Should -Throw '*no such package*'
	}

	It 'throws when config is missing' {
		Mock GetPackageDefinition { @{ env=@{ Path='x' }; other=@{} } }
		{ ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Digest='sha256:' + ('a'*64); Config='missing' } } | Should -Throw '*configuration*not found*'
	}

	It 'sets env vars and can append/prepend PATH' {
		$origPath = $env:Path
		try {
			Mock GetPackageDefinition { @{ env=@{ Path='A;B'; FOO='BAR' } } }
			$env:Path = 'C'
		ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Digest='sha256:' + ('a'*64); Config='default' }
		$env:FOO | Should -Be 'BAR'
		$env:Path | Should -Match '^A;B;C$'
		$env:Path = 'C'
		ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Digest='sha256:' + ('a'*64); Config='default' } -AppendPath
		$env:Path | Should -Match '^C;A;B$'
		} finally {
			$env:Path = $origPath
			Remove-Item env:FOO -ErrorAction SilentlyContinue
		}
	}

	It 'only configures a digest once' {
		Mock ConfigurePackage { }
		Mock ResolvePackageDigest { 'sha256:' + ('b'*64) }
		$p = @{ Package='p'; Tag=@{ Latest=$true }; Config='default' }
		LoadPackage $p
		LoadPackage $p
		Should -Invoke ConfigurePackage -Exactly -Times 1
	}
}
