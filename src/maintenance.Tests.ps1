<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'tlc.ps1')
}

Describe 'Toolchain update-check scheduling' {
	BeforeEach {
		$script:oldUpdateCheckTtl = $env:TOOLCHAIN_UPDATE_CHECK_TTL
		$script:oldDisableUpdateCheck = $env:TOOLCHAIN_DISABLE_UPDATE_CHECK
		Remove-Item Env:TOOLCHAIN_UPDATE_CHECK_TTL,Env:TOOLCHAIN_DISABLE_UPDATE_CHECK -ErrorAction SilentlyContinue
		Mock GetPwrDBPath { Join-Path $TestDrive 'db' }
	}

	AfterEach {
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = $script:oldUpdateCheckTtl
		$env:TOOLCHAIN_DISABLE_UPDATE_CHECK = $script:oldDisableUpdateCheck
	}

	It 'uses a one-day default and validates overrides' {
		Get-ToolchainUpdateCheckTtl | Should -Be ([timespan]::FromDays(1))
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = '00:05:00'
		Get-ToolchainUpdateCheckTtl | Should -Be ([timespan]::FromMinutes(5))
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = 'invalid'
		{ Get-ToolchainUpdateCheckTtl } | Should -Throw '*must be a TimeSpan*'
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = '-00:00:01'
		{ Get-ToolchainUpdateCheckTtl } | Should -Throw '*cannot be negative*'
	}

	It 'disables checks explicitly and treats zero TTL or a missing timestamp as due' {
		$env:TOOLCHAIN_DISABLE_UPDATE_CHECK = '1'
		Test-ToolchainUpdateCheckDue | Should -BeFalse
		Remove-Item Env:TOOLCHAIN_DISABLE_UPDATE_CHECK
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = '00:00:00'
		Test-ToolchainUpdateCheckDue | Should -BeTrue
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = '01:00:00'
		Test-ToolchainUpdateCheckDue | Should -BeTrue
	}

	It 'distinguishes fresh, stale, and malformed timestamps' {
		$env:TOOLCHAIN_UPDATE_CHECK_TTL = '01:00:00'
		$path = Get-ToolchainUpdateCheckPath
		New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
		[IO.File]::WriteAllText($path, [datetime]::UtcNow.ToString('o'))
		Test-ToolchainUpdateCheckDue | Should -BeFalse
		[IO.File]::WriteAllText($path, [datetime]::UtcNow.AddHours(-2).ToString('o'))
		Test-ToolchainUpdateCheckDue | Should -BeTrue
		[IO.File]::WriteAllText($path, 'not-a-date')
		Test-ToolchainUpdateCheckDue | Should -BeTrue
	}

	It 'persists a parseable UTC timestamp' {
		Set-ToolchainUpdateCheckTime
		$path = Get-ToolchainUpdateCheckPath
		Test-Path -LiteralPath $path | Should -BeTrue
		$parsed = [datetime]::MinValue
		[datetime]::TryParse((Get-Content -LiteralPath $path -Raw), [ref]$parsed) | Should -BeTrue
		$parsed.ToUniversalTime() | Should -BeGreaterThan ([datetime]::UtcNow.AddMinutes(-1))
	}

	It 'runs a deferred update check at most once' {
		$script:ToolchainDeferredUpdateCheckPending = $false
		Mock CheckForUpdates { }
		Invoke-ToolchainDeferredUpdateCheck
		Should -Invoke CheckForUpdates -Times 0 -Exactly
		Request-ToolchainDeferredUpdateCheck
		Invoke-ToolchainDeferredUpdateCheck
		Invoke-ToolchainDeferredUpdateCheck
		Should -Invoke CheckForUpdates -Times 1 -Exactly
	}
}
