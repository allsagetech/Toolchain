<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\progress.ps1"
}

Describe 'Progress helpers' {
	It 'GetUnicodeBlock returns expected glyphs' {
		(GetUnicodeBlock 0) | Should -Be ' '
		(GetUnicodeBlock 1) | Should -Not -BeNullOrEmpty
		(GetUnicodeBlock 2) | Should -Not -BeNullOrEmpty
	}

	It 'AsByteString formats units and decimal options' {
		(1 | AsByteString) | Should -Match '1'
		(2048 | AsByteString) | Should -Match 'kB'
		(1024*1024 | AsByteString) | Should -Match 'MB'
		(1024*1024*1024 | AsByteString) | Should -Match 'GB'
		(1536 | AsByteString -FixDecimals) | Should -Match '\.\d\d'
	}

	It 'GetProgress builds a bar string' {
		$r = GetProgress -Current 5 -Total 10
		$r | Should -Match '/'
	}

	It 'WriteConsole writes only when ProgressPreference=Continue and throws otherwise' {
		$pp = $ProgressPreference
		try {
			$global:ProgressPreference = 'SilentlyContinue'
			{ WriteConsole 'x' } | Should -Not -Throw

			$global:ProgressPreference = 'Stop'
			{ WriteConsole 'x' } | Should -Throw

			$global:ProgressPreference = 'Continue'
			{ WriteConsole 'x' } | Should -Not -Throw
		} finally {
			$global:ProgressPreference = $pp
		}
	}

	It 'WritePeriodicConsole throttles output' {
		Mock WriteConsole { }
		$script:lastwrite = $null
		WritePeriodicConsole { 'a' }
		$script:lastwrite = (Get-Date)
		WritePeriodicConsole { 'b' }
		(Assert-MockCalled WriteConsole -Times 1 -Exactly) | Out-Null
	}

	It 'SetCursorVisible handles cursor errors' {
		Mock Set-ToolchainConsoleCursorVisible { throw 'no console' }
		Mock Write-Error { }
		{ SetCursorVisible -Enable $true } | Should -Not -Throw
		Should -Invoke -CommandName Write-Error -Times 1 -Exactly
	}
}
