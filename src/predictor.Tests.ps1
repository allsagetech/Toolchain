<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$script:predictorApiAvailable = $PSVersionTable.PSVersion -ge [Version]'7.2' -and
	$null -ne ('System.Management.Automation.Subsystem.Prediction.PredictionContext' -as [type])

BeforeAll {
	. (Join-Path $PSScriptRoot 'predictor.ps1')
}

Describe 'Toolchain predictive IntelliSense' {
	It 'rejects redirected console output before attempting to configure PSReadLine' -Skip:(-not [Console]::IsOutputRedirected -or $PSVersionTable.PSVersion -lt [Version]'7.2') {
		$support = Get-ToolchainPredictiveIntelliSenseSupport
		$support.Supported | Should -BeFalse
		$support.Reason | Should -Match 'non-redirected console output'
	}

	It 'returns local inline candidates for Toolchain command paths' -Skip:(-not $script:predictorApiAvailable) {
		Initialize-ToolchainPredictiveIntelliSenseType
		$predictor = [Activator]::CreateInstance(('AllSageTech.Toolchain.ToolchainCommandPredictor' -as [type]))

		@($predictor.GetSuggestionTexts('tlc cl')) | Should -Be @('tlc cluster')
		@($predictor.GetSuggestionTexts('toolchain cluster ')) | Should -Contain 'toolchain cluster create'
		@($predictor.GetSuggestionTexts('tlc completion e')) | Should -Be @('tlc completion enable')
		@($predictor.GetSuggestionTexts('tlc shell p')) | Should -Be @('tlc shell pwsh')
		@($predictor.GetSuggestionTexts('git status')) | Should -BeNullOrEmpty
	}

	It 'registers only for supported current-session terminals and restores PSReadLine settings' {
		$support = Get-ToolchainPredictiveIntelliSenseSupport
		if (-not $support.Supported) {
			$support.Reason | Should -Not -BeNullOrEmpty
			return
		}
		$originalSource = [string](Get-PSReadLineOption).PredictionSource
		try {
			$enabled = Enable-ToolchainPredictiveIntelliSense
			$enabled.Enabled | Should -BeTrue
			(Get-ToolchainPredictiveIntelliSenseStatus).PredictionSource | Should -Match 'Plugin'
		} finally {
			$disabled = Disable-ToolchainPredictiveIntelliSense
			$disabled.Enabled | Should -BeFalse
			(Get-PSReadLineOption).PredictionSource.ToString() | Should -Be $originalSource
		}
	}

	It 'reports and safely declines unsupported terminals' {
		$support = Get-ToolchainPredictiveIntelliSenseSupport
		$status = Invoke-ToolchainPredictiveIntelliSense -Command status
		$status.Supported | Should -Be $support.Supported
		$status.Reason | Should -Be $support.Reason

		if (-not $support.Supported) {
			{ Invoke-ToolchainPredictiveIntelliSense -Command enable } | Should -Throw '*Toolchain predictive IntelliSense*'
			(Invoke-ToolchainPredictiveIntelliSense -Command disable).Supported | Should -BeFalse
		}
	}


	It 'returns no predictor implementation when the host lacks prediction support' -Skip:$script:predictorApiAvailable {
		Get-ToolchainPredictiveIntelliSenseImplementation | Should -BeNullOrEmpty
	}
}
