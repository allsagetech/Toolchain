<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'FindConfig' {
	BeforeAll {
		$script:ToolchainPath = "$root\toolchain"
		Mock Get-Location {
			@{Path = 'C:\a\b\c\d'}
		}
	}
	It 'Local config' {
		Mock Test-Path {
			return $true
		}
		$cfg = FindConfig
		$cfg | Should -Be 'C:\a\b\c\d\Toolchain.ps1'
	}
	It 'Parent config' {
		$script:i = 0
		Mock Test-Path {
			return ($script:i++) -gt 0
		}
		$cfg = FindConfig
		$cfg | Should -Be 'C:\a\b\c\Toolchain.ps1'
	}
	It 'No config' {
		Mock Test-Path {
			return $false
		}
		$cfg = FindConfig
		$cfg | Should -Be $null
	}

	It 'Root path does not loop' {
		Mock Get-Location { @{ Path = 'C:\' } }
		Mock Test-Path { return $false }
		$cfg = FindConfig
		$cfg | Should -Be $null
	}
}
