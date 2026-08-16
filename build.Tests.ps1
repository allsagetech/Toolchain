<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

Describe 'Toolchain release build' {
	BeforeAll {
		$repoRoot = $PSScriptRoot
		$outsideDirectory = Join-Path ([IO.Path]::GetTempPath()) ("toolchain-build-test-" + [Guid]::NewGuid().ToString('n'))
		New-Item -Path $outsideDirectory -ItemType Directory -Force | Out-Null
	}

	AfterAll {
		Remove-Item -LiteralPath $outsideDirectory -Recurse -Force -ErrorAction SilentlyContinue
	}

	It 'builds and validates an importable release from another working directory' {
		Push-Location $outsideDirectory
		try {
			& (Join-Path $repoRoot 'build.ps1')
		} finally {
			Pop-Location
		}

		$manifestPath = Join-Path $repoRoot 'build\Toolchain\Toolchain.psd1'
		$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
		$manifest.Version.ToString() | Should -Be ((Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim())
		$manifest.ExportedFunctions.Keys | Should -Contain 'Invoke-Toolchain'
		$manifest.ExportedAliases.Keys | Should -Contain 'tlc'
		foreach ($fileName in @('README.md', 'CHANGELOG.md', 'LICENSE.md', 'ATTRIBUTION.md', 'COPYRIGHT.md', 'TRADEMARKS.md', 'SECURITY.md')) {
			Test-Path -LiteralPath (Join-Path (Split-Path -Parent $manifestPath) $fileName) | Should -BeTrue
		}
	}
}
