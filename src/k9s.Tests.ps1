<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain K9s launcher' {
	BeforeEach {
		$script:k9sArguments = @()
		function global:k9s-test {
			param([Parameter(ValueFromRemainingArguments)][object[]]$Remaining)
			$script:k9sArguments = @($Remaining | ForEach-Object { [string]$_ })
			$global:LASTEXITCODE = 0
		}
		Mock Get-ToolchainClusterExecutable { 'k9s-test' }
	}

	AfterEach {
		Remove-Item Function:\global:k9s-test -Force -ErrorAction SilentlyContinue
	}

	It 'launches against the current kubecontext and forwards K9s arguments' {
		Invoke-ToolchainK9s -ArgumentList @('--readonly','-n','default')
		$script:k9sArguments | Should -Be @('--readonly','-n','default')
		Should -Invoke Get-ToolchainClusterExecutable -Times 1 -Exactly -ParameterFilter { $Name -eq 'k9s' -and $Package -eq 'k9s' }
	}

	It 'uses a Toolchain-managed cluster kubeconfig' {
		Mock Invoke-ToolchainCluster { 'C:\clusters\dev\kubeconfig.yaml' }
		Invoke-ToolchainK9s -Cluster dev -ArgumentList @('-A')
		$script:k9sArguments | Should -Be @('--kubeconfig','C:\clusters\dev\kubeconfig.yaml','-A')
		Should -Invoke Invoke-ToolchainCluster -Times 1 -Exactly -ParameterFilter { $Command -eq 'kubeconfig' -and $Name -eq 'dev' }
	}

	It 'resolves an explicit kubeconfig file' {
		$path = Join-Path $TestDrive 'kubeconfig.yaml'
		Set-Content -LiteralPath $path -Value 'apiVersion: v1'
		Invoke-ToolchainK9s -Kubeconfig $path
		$script:k9sArguments | Should -Be @('--kubeconfig',(Resolve-Path -LiteralPath $path).Path)
	}

	It 'rejects conflicting or non-file kubeconfig selections' {
		{ Invoke-ToolchainK9s -Cluster dev -Kubeconfig config.yaml } | Should -Throw '*cannot be used together*'
		{ Invoke-ToolchainK9s -Kubeconfig $TestDrive } | Should -Throw '*kubeconfig is not a file*'
	}

	It 'surfaces a nonzero K9s exit code' {
		function global:k9s-test { $global:LASTEXITCODE = 7 }
		{ Invoke-ToolchainK9s } | Should -Throw '*k9s exited with code 7*'
	}
}
