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
}
