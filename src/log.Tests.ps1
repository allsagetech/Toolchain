<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Write-ToolchainInfo' {
	BeforeEach {
		Mock Write-Information { }
	}

	It 'writes information with Toolchain tags' {
		Write-ToolchainInfo 'hello'
		Should -Invoke -CommandName Write-Information -Exactly -Times 1 -ParameterFilter {
			$MessageData -eq 'hello' -and $InformationAction -eq 'Continue' -and ($Tags -contains 'Toolchain') -and ($Tags -contains 'Info')
		}
	}

	It 'supports warning-only, JSON, and development log configuration' {
		$previous = Set-ToolchainLogConfiguration -Level warn -Format console
		try {
			Write-ToolchainInfo 'hidden'
			Should -Invoke -CommandName Write-Information -Times 0
		} finally { Reset-ToolchainLogConfiguration -Configuration $previous }

		$previous = Set-ToolchainLogConfiguration -Level debug -Format json
		try {
			Write-ToolchainInfo 'structured'
			Should -Invoke -CommandName Write-Information -Times 1 -ParameterFilter {
				$record = $MessageData | ConvertFrom-Json
				$record.level -eq 'info' -and $record.message -eq 'structured'
			}
		} finally { Reset-ToolchainLogConfiguration -Configuration $previous }

		$previous = Set-ToolchainLogConfiguration -Level trace -Format dev
		try {
			Write-ToolchainInfo 'diagnostic'
			Should -Invoke -CommandName Write-Information -Times 1 -ParameterFilter { $MessageData -eq "INFO`tdiagnostic" }
		} finally { Reset-ToolchainLogConfiguration -Configuration $previous }
	}
}
