<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function GetToolchainRepo {}
	function GetImageConfigJsonFromRef { param([string]$Ref,[string]$ExpectedManifestDigest) }
	function GetResolvedManifestResponse { param([string]$Ref,[string]$Method) }
	function GetDigest { param($Resp) }
	function GetRegistryBaseUrl { 'https://registry.example.test' }
	function GetRegistryRepoName { 'owner/toolchains' }
	function Invoke-ToolchainCosignVerify { param($RepoDigestRef) }
	function GetDockerTags { param($Kind, [switch]$Refresh, [switch]$SkipHealthPolicy) }
	function AsTagString { param([Parameter(ValueFromPipeline)]$Tag) process { [string]$Tag } }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')

	function Compress-TestHealthLabel {
		param([Parameter(Mandatory)][string]$Text)
		$output = [IO.MemoryStream]::new()
		$gzip = [IO.Compression.GZipStream]::new($output, [IO.Compression.CompressionMode]::Compress, $true)
		try {
			$bytes = [Text.Encoding]::UTF8.GetBytes($Text)
			$gzip.Write($bytes, 0, $bytes.Length)
		} finally { $gzip.Dispose() }
		try { return [Convert]::ToBase64String($output.ToArray()) } finally { $output.Dispose() }
	}
}

Describe 'Toolchain signed package health catalog' {
	BeforeEach {
		$script:ToolchainHealthCatalogCache = $null
		$script:ToolchainHealthCatalogCachedAt = $null
	}
	It 'round trips the compressed health label' {
		$value = Compress-TestHealthLabel -Text '{"schemaVersion":1}'
		Expand-ToolchainHealthCatalogLabel -Value $value | Should -Be '{"schemaVersion":1}'
	}

	It 'rejects malformed and oversized health labels' {
		{ Expand-ToolchainHealthCatalogLabel -Value 'not-base64' } | Should -Throw
		$value = Compress-TestHealthLabel -Text ('a' * 4194305)
		{ Expand-ToolchainHealthCatalogLabel -Value $value } | Should -Throw '*4 MiB*'
	}

	It 'does not use a remote catalog for an offline repository' {
		Mock GetToolchainRepo { 'C:\offline' }
		Mock Get-ToolchainHealthCatalogImageConfig {}
		Get-ToolchainHealthCatalog | Should -BeNullOrEmpty
		Should -Invoke Get-ToolchainHealthCatalogImageConfig -Times 0
	}

	It 'pins the catalog config to its digest and applies optional Cosign policy' {
		$digest = 'sha256:' + ('a' * 64)
		$response = New-MockObject -Type 'System.Object' -Methods @{ Dispose = {} }
		Mock GetResolvedManifestResponse { $response }
		Mock GetDigest { $digest }
		Mock Invoke-ToolchainCosignVerify {}
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ Labels = @{} } }
		$null = Get-ToolchainHealthCatalogImageConfig
		Should -Invoke Invoke-ToolchainCosignVerify -Times 1 -ParameterFilter { $RepoDigestRef -eq "registry.example.test/owner/toolchains@$digest" }
		Should -Invoke GetImageConfigJsonFromRef -Times 1 -ParameterFilter { $Ref -eq $digest -and $ExpectedManifestDigest -eq $digest }
	}

	It 'reads the signed catalog label and restores refresh state' {
		$document = @{ schemaVersion = 1; generatedAt = [datetime]::UtcNow.ToString('o'); packages = @() } | ConvertTo-Json -Compress
		$label = Compress-TestHealthLabel -Text $document
		$script:refreshDuringHealthRead = $null
		Mock GetToolchainRepo { $null }
		Mock Get-ToolchainHealthCatalogImageConfig {
			$script:refreshDuringHealthRead = $env:TOOLCHAIN_CATALOG_REFRESH
			[pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.healthCatalogGzipBase64' = $label } } }
		}
		$previous = $env:TOOLCHAIN_CATALOG_REFRESH
		$env:TOOLCHAIN_CATALOG_REFRESH = 'old'
		try {
			(Get-ToolchainHealthCatalog -Refresh).schemaVersion | Should -Be 1
			$script:refreshDuringHealthRead | Should -Be '1'
			$env:TOOLCHAIN_CATALOG_REFRESH | Should -Be 'old'
		} finally { $env:TOOLCHAIN_CATALOG_REFRESH = $previous }
	}

	It 'caches a valid health catalog for repeated resolution' {
		$document = @{ schemaVersion = 1; generatedAt = [datetime]::UtcNow.ToString('o'); packages = @() } | ConvertTo-Json -Compress
		$label = Compress-TestHealthLabel -Text $document
		Mock GetToolchainRepo { $null }
		Mock Get-ToolchainHealthCatalogImageConfig { [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.healthCatalogGzipBase64' = $label } } }
		$null = Get-ToolchainHealthCatalog
		$null = Get-ToolchainHealthCatalog
		Should -Invoke Get-ToolchainHealthCatalogImageConfig -Times 1
	}

	It 'falls back cleanly when the catalog is absent or invalid' {
		Mock GetToolchainRepo { $null }
		Mock Get-ToolchainHealthCatalogImageConfig { [pscustomobject]@{ Labels = [pscustomobject]@{} } }
		Get-ToolchainHealthCatalog | Should -BeNullOrEmpty

		$label = Compress-TestHealthLabel -Text '{"schemaVersion":2,"generatedAt":"now","packages":[]}'
		Mock Get-ToolchainHealthCatalogImageConfig { [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.healthCatalogGzipBase64' = $label } } }
		Get-ToolchainHealthCatalog | Should -BeNullOrEmpty
	}
}

Describe 'Toolchain package health views' {
	It 'filters, sorts, and normalizes signed health entries' {
		Mock Get-ToolchainHealthCatalog {
			[pscustomobject]@{ packages = @(
				[pscustomobject]@{ name='zeta'; state='scan-blocked'; reason='CVE'; versions=@('1'); platforms=@('linux/amd64'); lastScannedAt='2026-08-15T00:00:00Z'; stateSince='2026-08-14T00:00:00Z'; lastCleanScannedAt='2026-08-07T00:00:00Z'; digest='sha256:z'; upstream='https://example.test/z' },
				[pscustomobject]@{ name='alpha'; state='available'; reason=''; versions=@('2'); platforms=@('windows/amd64'); lastScannedAt=$null; digest='sha256:a'; upstream='https://example.test/a' }
			) }
		}
		$all = @(Get-ToolchainPackageHealth)
		$all.Name | Should -Be @('alpha','zeta')
		$all[0].PSTypeNames | Should -Contain 'Toolchain.PackageHealth'
		$all[1].LastScannedAt | Should -BeOfType [datetime]
		$all[1].StateSince | Should -BeOfType [datetime]
		$all[1].LastCleanScannedAt | Should -BeOfType [datetime]
		$all[0].StateSince | Should -BeNullOrEmpty
		@(Get-ToolchainPackageHealth -OnlyProblems).Name | Should -Be @('zeta')
		(Get-ToolchainPackageHealth -Package ALPHA).Name | Should -Be 'alpha'
	}

	It 'uses a live registry fallback and reports unknown packages' {
		Mock Get-ToolchainHealthCatalog { $null }
		Mock GetDockerTags { [pscustomobject]@{ node = @('22.0.0','20.0.0') } }
		$result = Get-ToolchainPackageHealth -Package node -Refresh
		$result.State | Should -Be 'available'
		$result.Reason | Should -Match 'fallback'
		$result.Versions | Should -Be @('22.0.0','20.0.0')
		Should -Invoke GetDockerTags -Times 1 -ParameterFilter { $Kind -eq 'All' -and $Refresh -and $SkipHealthPolicy }
		{ Get-ToolchainPackageHealth -Package missing } | Should -Throw '*not found*'
	}

	It 'removes blocked versions and packages from the installable catalog' {
		Mock Get-ToolchainHealthCatalog {
			[pscustomobject]@{ packages = @(
				[pscustomobject]@{ name='node'; aliases=@(); versions=@('20.1.0') },
				[pscustomobject]@{ name='kubectl'; aliases=@('kubectl-linux'); versions=@('1.34.0') }
			) }
		}
		$catalog = @{ node=@('22.1.0','20.1.0'); 'kubectl-linux'=@('1.34.0','1.33.0'); unknown=@('1.0.0') }
		$result = Protect-ToolchainRemoteCatalogWithHealthPolicy -Catalog $catalog
		@($result.node) | Should -Be @('20.1.0')
		@($result.'kubectl-linux') | Should -Be @('1.34.0')
		$result.ContainsKey('unknown') | Should -BeFalse
	}
}
