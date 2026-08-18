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
		@(Get-ToolchainEnvironmentItems | Where-Object { $_.Name -ieq 'TOOLCHAIN_TEST_ENV' }).Count | Should -Be 0
		$env:TOOLCHAIN_TEST_ENV | Should -BeNullOrEmpty
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
		Mock ResolvePackagePath { $root }
		Mock GetToolchainDefinitionFromLabels { @{ env = @{ FOO = 'BAR' } } }
		$def = GetPackageDefinition -Digest ('sha256:' + ('a' * 64))
		$def.env.FOO | Should -Be 'BAR'
		Remove-Item -Recurse -Force $root
	}

	It 'reads .tlc when label definition is absent' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		'{"env":{"ROOT":"${.}"}}' | Set-Content -LiteralPath (Join-Path $root '.tlc')
		$def = GetPackageDefinition -Digest ("file:///$root<ignored>")
		$def.env.ROOT | Should -Match ([Regex]::Escape($root))
		Remove-Item -Recurse -Force $root
	}

	It 'throws when no definition exists' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		New-Item -ItemType File -Path (Join-Path $root 'a.txt') | Out-Null
		{ GetPackageDefinition -Digest ("file:///$root") } | Should -Throw '*Package definition not found*Root contents*'
		Remove-Item -Recurse -Force $root
	}

	It 'does not fall back to .tlc when OCI label integrity validation fails' {
		$root = Join-Path $env:TEMP ('pkg-' + [Guid]::NewGuid())
		New-Item -ItemType Directory -Path $root | Out-Null
		try {
			'{"env":{"FALLBACK":"must-not-load"}}' | Set-Content -LiteralPath (Join-Path $root '.tlc')
			Mock ResolvePackagePath { $root }
			Mock GetToolchainDefinitionFromLabels { throw 'toolchain definition sha256 mismatch' }
			{ GetPackageDefinition -Digest ('sha256:' + ('b' * 64)) } | Should -Throw '*sha256 mismatch*'
		} finally {
			Remove-Item -Recurse -Force $root
		}
	}

	It 'directs legacy short-digest caches through a verified pull' {
		$digest = 'sha256:' + ('c' * 64)
		$legacyRoot = Join-Path $TestDrive ('c' * 12)
		New-Item -ItemType Directory -Path $legacyRoot | Out-Null
		Mock GetPwrContentPath { $TestDrive }
		Mock ResolvePackagePath { Join-Path $TestDrive ('c' * 64) }

		{ GetPackageDefinition -Digest $digest } | Should -Throw "*legacy short-digest cache layout*tlc pull <package>@${digest}*"
	}
}

Describe 'ConfigurePackage and LoadPackage' {
	BeforeEach {
		$env:ToolchainLoadedPackages = ''
		Remove-Item env:ToolchainLoadedPackageRefs -ErrorAction SilentlyContinue
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
		$origPath = Get-ToolchainPathValue
		try {
			Mock GetPackageDefinition { @{ env=@{ Path='A;B'; FOO='BAR' } } }
			Set-ToolchainPathValue 'C'
		ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Digest='sha256:' + ('a'*64); Config='default' }
		$env:FOO | Should -Be 'BAR'
		Get-ToolchainPathValue | Should -Match '^A;B;C$'
		Set-ToolchainPathValue 'C'
		ConfigurePackage @{ Package='p'; Tag=@{ Latest=$true }; Digest='sha256:' + ('a'*64); Config='default' } -AppendPath
		Get-ToolchainPathValue | Should -Match '^C;A;B$'
		} finally {
			Set-ToolchainPathValue $origPath
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

	It 'configures same digest when loaded under a different config' {
		Mock ConfigurePackage { }
		$d = 'sha256:' + ('b' * 64)
		Mock ResolvePackageDigest { $d }
		$p1 = @{ Package='p'; Tag=@{ Latest=$true }; Config='default' }
		$p2 = @{ Package='p'; Tag=@{ Latest=$true }; Config='alt' }
		LoadPackage $p1
		LoadPackage $p2
		Should -Invoke ConfigurePackage -Exactly -Times 2
		$env:ToolchainLoadedPackages | Should -Be $d
		$env:ToolchainLoadedPackageRefs | Should -Match 'p:latest::default='
		$env:ToolchainLoadedPackageRefs | Should -Match 'p:latest::alt='
	}

	It 'replaces previous PATH entries when digest changes between loads' {
		$origPath = Get-ToolchainPathValue
		$script:d1 = 'sha256:' + ('1' * 64)
		$script:d2 = 'sha256:' + ('2' * 64)
		try {
			Set-ToolchainPathValue 'BASE'
			$script:resolveCall = 0
			Mock ResolvePackageDigest {
				$script:resolveCall += 1
				if ($script:resolveCall -eq 1) { return $script:d1 }
				return $script:d2
			}
			Mock GetPackageDefinition {
				param([Parameter(ValueFromPipeline)][string]$Digest)
				if ($Digest -eq $script:d1) {
					return @{ env = @{ Path = 'C:\pkg\v1\bin'; FOO = 'one' } }
				}
				return @{ env = @{ Path = 'C:\pkg\v2\bin'; FOO = 'two' } }
			}

			$p = @{ Package='p'; Tag=@{ Latest=$true }; Config='default' }
			LoadPackage $p
			Get-ToolchainPathValue | Should -Be 'C:\pkg\v1\bin;BASE'

			LoadPackage $p
			Get-ToolchainPathValue | Should -Be 'C:\pkg\v2\bin;BASE'
			Get-ToolchainPathValue | Should -Not -Match ([Regex]::Escape('C:\pkg\v1\bin'))
			$env:FOO | Should -Be 'two'
			$env:ToolchainLoadedPackages | Should -Be $script:d2
			$env:ToolchainLoadedPackageRefs | Should -Match 'p:latest::default='
		} finally {
			Set-ToolchainPathValue $origPath
			Remove-Item env:FOO -ErrorAction SilentlyContinue
			Remove-Item env:ToolchainLoadedPackageRefs -ErrorAction SilentlyContinue
		}
	}

	It 'keeps other ref digests tracked when one ref updates' {
		$origPath = Get-ToolchainPathValue
		$script:d1 = 'sha256:' + ('1' * 64)
		$script:d2 = 'sha256:' + ('2' * 64)
		try {
			Set-ToolchainPathValue 'BASE'
			$script:defaultCalls = 0
			Mock ResolvePackageDigest {
				param([Parameter(ValueFromPipeline)][Collections.Hashtable]$Pkg)
				if ($Pkg.Config -eq 'alt') { return $script:d1 }
				$script:defaultCalls += 1
				if ($script:defaultCalls -eq 1) { return $script:d1 }
				return $script:d2
			}
			Mock GetPackageDefinition {
				param([Parameter(ValueFromPipeline)][string]$Digest)
				if ($Digest -eq $script:d1) {
					return @{
						env = @{ Path = 'C:\pkg\v1\bin'; FOO = 'one' }
						alt = @{ env = @{ Path = 'C:\pkg\v1\alt'; BAR = 'altone' } }
					}
				}
				return @{
					env = @{ Path = 'C:\pkg\v2\bin'; FOO = 'two' }
					alt = @{ env = @{ Path = 'C:\pkg\v2\alt'; BAR = 'alttwo' } }
				}
			}

			$pDefault = @{ Package='p'; Tag=@{ Latest=$true }; Config='default' }
			$pAlt = @{ Package='p'; Tag=@{ Latest=$true }; Config='alt' }

			LoadPackage $pDefault
			LoadPackage $pAlt
			LoadPackage $pDefault

			$loaded = @(
				$env:ToolchainLoadedPackages -split ';' |
					Where-Object { $_ -and $_.Trim() } |
					ForEach-Object { $_.Trim() }
			) | Sort-Object
			$loaded | Should -Be @($script:d1, $script:d2)
			$env:ToolchainLoadedPackageRefs | Should -Match ([Regex]::Escape("p:latest::alt=$script:d1"))
			$env:ToolchainLoadedPackageRefs | Should -Match ([Regex]::Escape("p:latest::default=$script:d2"))
			Get-ToolchainPathValue | Should -Match ([Regex]::Escape('C:\pkg\v2\bin'))
			Get-ToolchainPathValue | Should -Match ([Regex]::Escape('C:\pkg\v1\alt'))
			Get-ToolchainPathValue | Should -Not -Match ([Regex]::Escape('C:\pkg\v1\bin'))
		} finally {
			Set-ToolchainPathValue $origPath
			Remove-Item env:FOO -ErrorAction SilentlyContinue
			Remove-Item env:BAR -ErrorAction SilentlyContinue
			Remove-Item env:ToolchainLoadedPackageRefs -ErrorAction SilentlyContinue
		}
	}
}
