<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\config.ps1"

	function Get-TestEnvironmentValue {
		param([string]$Name)
		[Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Process)
	}

	function Set-TestEnvironmentValue {
		param([string]$Name, [AllowNull()][string]$Value)
		[Environment]::SetEnvironmentVariable($Name, $Value, [EnvironmentVariableTarget]::Process)
	}
}

Describe 'ConvertTo-HashTable' {
	It 'returns null for null input' {
		($null | ConvertTo-HashTable) | Should -Be $null
	}

	It 'converts nested PSCustomObject and arrays' {
		$obj = [PSCustomObject]@{ A = 1; B = [PSCustomObject]@{ C = 'x' }; D = @('a','b') }
		$ht = $obj | ConvertTo-HashTable
		$ht.A | Should -Be 1
		$ht.B.C | Should -Be 'x'
		,$ht.D | Should -BeOfType 'System.Collections.ArrayList'
		$ht.D.Count | Should -Be 2
	}
}

Describe 'Toolchain config getters' {
	BeforeEach {
		$script:prevToolchainPath = $global:ToolchainPath
		$script:prevToolchainRepo = $global:ToolchainRepo
		$script:prevPullPolicy = $global:ToolchainPullPolicy
		$script:prevAutoprune = $global:ToolchainAutoprune
		$script:prevAutoupdate = $global:ToolchainAutoupdate

		$script:prevEnv = @{}
		foreach ($k in 'ToolchainPath','ToolchainRepo','ToolchainPullPolicy','ToolchainAutoprune','ToolchainAutoupdate','LocalAppData') {
			$script:prevEnv[$k] = Get-TestEnvironmentValue $k
		}
	}
	AfterEach {
		$global:ToolchainPath = $script:prevToolchainPath
		$global:ToolchainRepo = $script:prevToolchainRepo
		$global:ToolchainPullPolicy = $script:prevPullPolicy
		$global:ToolchainAutoprune = $script:prevAutoprune
		$global:ToolchainAutoupdate = $script:prevAutoupdate
		foreach ($k in $script:prevEnv.Keys) {
			Set-TestEnvironmentValue $k $script:prevEnv[$k]
		}
	}

	It 'GetToolchainPath prefers global, then env, then default' {
		$global:ToolchainPath = 'C:\tc1'
		$env:ToolchainPath = 'C:\tc2'
		GetToolchainPath | Should -Be 'C:\tc1'

		$global:ToolchainPath = $null
		GetToolchainPath | Should -Be 'C:\tc2'

		Set-TestEnvironmentValue 'ToolchainPath' $null
		$env:LocalAppData = 'C:\Local'
		GetToolchainPath | Should -Be 'C:\Local\Toolchain'
	}

	It 'GetToolchainRepo returns global or env and otherwise null' {
		$global:ToolchainRepo = 'C:\repo'
		$env:ToolchainRepo = 'C:\repo2'
		GetToolchainRepo | Should -Be 'C:\repo'
		$global:ToolchainRepo = $null
		GetToolchainRepo | Should -Be 'C:\repo2'
		Set-TestEnvironmentValue 'ToolchainRepo' $null
		GetToolchainRepo | Should -Be $null
	}

	It 'GetToolchainPullPolicy defaults to IfNotPresent' {
		$global:ToolchainPullPolicy = $null
		Set-TestEnvironmentValue 'ToolchainPullPolicy' $null
		GetToolchainPullPolicy | Should -Be 'IfNotPresent'
		$env:ToolchainPullPolicy = 'Always'
		GetToolchainPullPolicy | Should -Be 'Always'
		$global:ToolchainPullPolicy = 'Never'
		GetToolchainPullPolicy | Should -Be 'Never'
	}

	It 'GetToolchainAutoprune and GetToolchainAutoupdate return overrides' {
		$global:ToolchainAutoprune = '1'
		$env:ToolchainAutoprune = '0'
		GetToolchainAutoprune | Should -Be '1'
		$global:ToolchainAutoprune = $null
		GetToolchainAutoprune | Should -Be '0'

		$global:ToolchainAutoupdate = '1'
		$env:ToolchainAutoupdate = '0'
		GetToolchainAutoupdate | Should -Be '1'
		$global:ToolchainAutoupdate = $null
		GetToolchainAutoupdate | Should -Be '0'
	}

	It 'path helpers compose under ToolchainPath' {
		$global:ToolchainPath = 'C:\tc'
		GetPwrDBPath | Should -Be 'C:\tc\cache'
		GetPwrTempPath | Should -Be 'C:\tc\temp'
		GetPwrContentPath | Should -Be 'C:\tc\content'
	}

	It 'ResolvePackagePath uses the complete canonical digest hash' {
		$global:ToolchainPath = 'C:\tc'
		$d = 'sha256:' + ('a' * 64)
		($d | ResolvePackagePath) | Should -Be ('C:\tc\content\' + ('a' * 64))
	}

	It 'never assigns an unmarked legacy prefix directory to a colliding digest' {
		$global:ToolchainPath = Join-Path $TestDrive 'tc-collision'
		$legacy = Join-Path (GetPwrContentPath) 'aaaaaaaaaaaa'
		New-Item -ItemType Directory -Path $legacy -Force | Out-Null
		Set-Content -LiteralPath (Join-Path $legacy 'owner.txt') -Value 'legacy bytes'
		$digestA = 'sha256:' + ('a' * 64)
		$digestB = 'sha256:aaaaaaaaaaaa' + ('b' * 52)

		$pathA = $digestA | ResolvePackagePath
		$pathB = $digestB | ResolvePackagePath

		$pathA | Should -Not -Be $pathB
		$pathA | Should -Not -Be $legacy
		$pathB | Should -Not -Be $legacy
		Test-Path -LiteralPath $pathA | Should -BeFalse
		Test-Path -LiteralPath $pathB | Should -BeFalse
		(Get-Content -LiteralPath (Join-Path $legacy 'owner.txt') -Raw).Trim() | Should -Be 'legacy bytes'
	}

	It 'MakeDirIfNotExist creates directory idempotently' {
		$root = Join-Path $env:TEMP ('tc-' + [Guid]::NewGuid().ToString())
		try {
			MakeDirIfNotExist $root | Out-Null
			(Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
			MakeDirIfNotExist $root | Out-Null
			(Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
		} finally {
			Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
		}
	}
}
