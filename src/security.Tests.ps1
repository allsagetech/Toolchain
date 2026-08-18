<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	$script:testRegistryUrl = 'https://registry.example.test'
	$script:testRegistryRepo = 'owner/toolchains'
	function GetRegistryBaseUrl { $script:testRegistryUrl }
	function GetRegistryRepoName { $script:testRegistryRepo }
	function GetToolchainPath { Join-Path $TestDrive 'toolchain-default' }
	function Write-ToolchainInfo { param([string]$Message) }
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Invoke-ToolchainCommand' {
	It 'Returns output on success' {
		$exe = if ($PSVersionTable.PSEdition -eq 'Desktop') { (Get-Command 'powershell' -ErrorAction Stop).Source } else { (Get-Command 'pwsh' -ErrorAction Stop).Source }
		$out = Invoke-ToolchainCommand -File $exe -ArgumentList @('-NoProfile','-Command','Write-Output ok')
		($out -join "\n") | Should -Match 'ok'
	}

	It 'Returns null when -Quiet' {
		$exe = if ($PSVersionTable.PSEdition -eq 'Desktop') { (Get-Command 'powershell' -ErrorAction Stop).Source } else { (Get-Command 'pwsh' -ErrorAction Stop).Source }
		$val = Invoke-ToolchainCommand -File $exe -ArgumentList @('-NoProfile','-Command','Write-Output ok') -Quiet
		$val | Should -Be $null
	}

	It 'Throws on non-zero exit code' {
		$exe = if ($PSVersionTable.PSEdition -eq 'Desktop') { (Get-Command 'powershell' -ErrorAction Stop).Source } else { (Get-Command 'pwsh' -ErrorAction Stop).Source }
		{ Invoke-ToolchainCommand -File $exe -ArgumentList @('-NoProfile','-Command','exit 5') } | Should -Throw
	}
}

Describe 'Cosign settings' {
	BeforeEach {
		$script:testRegistryUrl = 'https://registry.example.test'
		$script:testRegistryRepo = 'owner/toolchains'
		Mock GetToolchainRepo { return $null }
		Remove-Item Env:TOOLCHAIN_COSIGN_VERIFY -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_COSIGN_KEY -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_COSIGN_CERT_IDENTITY -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_COSIGN_OIDC_ISSUER -ErrorAction Ignore
	}

	It 'Get-ToolchainCosignVerifyEnabled respects policy' {
		Mock Get-ToolchainPolicyRequireCosign { return $true }
		(Get-ToolchainCosignVerifyEnabled) | Should -Be $true
	}

	It 'Get-ToolchainCosignVerifyEnabled respects env var' {
		Mock Get-ToolchainPolicyRequireCosign { return $false }
		$env:TOOLCHAIN_COSIGN_VERIFY = 'true'
		(Get-ToolchainCosignVerifyEnabled) | Should -Be $true
	}

	It 'Get-ToolchainCosignVerifyEnabled defaults to false' {
		Mock Get-ToolchainPolicyRequireCosign { return $false }
		(Get-ToolchainCosignVerifyEnabled) | Should -Be $false
	}

	It 'requires official package verification by default with an explicit opt-out' {
		Mock Get-ToolchainPolicyRequireCosign { return $false }
		$script:testRegistryUrl = 'https://registry-1.docker.io'
		$script:testRegistryRepo = 'allsagetech/toolchains'
		Get-ToolchainCosignVerifyEnabled | Should -BeTrue
		$env:TOOLCHAIN_COSIGN_VERIFY = '0'
		Get-ToolchainCosignVerifyEnabled | Should -BeFalse
	}

	It 'Get-ToolchainCosignKey prefers policy over env' {
		Mock Get-ToolchainPolicyCosignKey { return 'policy.pem' }
		$env:TOOLCHAIN_COSIGN_KEY = 'env.pem'
		(Get-ToolchainCosignKey) | Should -Be 'policy.pem'
	}

	It 'Invoke-ToolchainCosignVerify no-ops when disabled' {
		Mock Get-ToolchainCosignVerifyEnabled { return $false }
		Mock Resolve-ToolchainCosignApplication { throw 'should not be called' }
		{ Invoke-ToolchainCosignVerify -RepoDigestRef 'repo@sha256:abc' } | Should -Not -Throw
	}

	It 'Invoke-ToolchainCosignVerify fails closed when bootstrap fails' {
		Mock Get-ToolchainCosignVerifyEnabled { return $true }
		Mock Resolve-ToolchainCosignApplication { throw 'verified bootstrap failed' }
		{ Invoke-ToolchainCosignVerify -RepoDigestRef 'repo@sha256:abc' } | Should -Throw '*verified bootstrap failed*'
	}

	It 'Invoke-ToolchainCosignVerify calls cosign with flags' {
		Mock Get-ToolchainCosignVerifyEnabled { return $true }
		Mock Get-ToolchainCosignKey { return 'key.pem' }
		$env:TOOLCHAIN_COSIGN_CERT_IDENTITY = 'me@example.com'
		$env:TOOLCHAIN_COSIGN_OIDC_ISSUER = 'https://issuer.example'

		Mock Resolve-ToolchainCosignApplication {
			return [pscustomobject]@{ Source = 'cosign.exe' }
		}
		Mock Invoke-ToolchainCommand { }

		Invoke-ToolchainCosignVerify -RepoDigestRef 'repo@sha256:abc'
		Should -Invoke -CommandName Invoke-ToolchainCommand -Times 1 -Exactly -ParameterFilter {
			$File -eq 'cosign.exe' -and
			($ArgumentList -contains 'verify') -and
			($ArgumentList -contains '--key') -and
			($ArgumentList -contains 'key.pem') -and
			($ArgumentList -contains '--certificate-identity') -and
			($ArgumentList -contains 'me@example.com') -and
			($ArgumentList -contains '--certificate-oidc-issuer') -and
			($ArgumentList -contains 'https://issuer.example') -and
			($ArgumentList -contains 'repo@sha256:abc')
		}
	}

	It 'pins the official keyless workflow identity when no custom trust root is configured' {
		$script:testRegistryUrl = 'https://registry-1.docker.io'
		$script:testRegistryRepo = 'allsagetech/toolchains'
		Mock Get-ToolchainPolicyRequireCosign { return $false }
		Mock Get-ToolchainCosignKey { return $null }
		Mock Resolve-ToolchainCosignApplication { [pscustomobject]@{ Source='cosign' } }
		Mock Invoke-ToolchainCommand { }

		Invoke-ToolchainCosignVerify -RepoDigestRef ('registry-1.docker.io/allsagetech/toolchains@sha256:' + ('a' * 64))
		Should -Invoke Invoke-ToolchainCommand -Times 1 -Exactly -ParameterFilter {
			$ArgumentList -contains 'https://github.com/allsagetech/Toolchains/.github/workflows/build-push.yml@refs/heads/main' -and
			$ArgumentList -contains 'https://token.actions.githubusercontent.com'
		}
	}
}

Describe 'Cosign bootstrap' {
	BeforeEach {
		Mock Write-ToolchainInfo { }
	}

	It 'pins the current supported platform to an official release checksum' {
		$asset = Get-ToolchainCosignBootstrapAsset
		$asset.Version | Should -Be 'v2.6.0'
		$asset.Uri | Should -BeLike 'https://github.com/sigstore/cosign/releases/download/v2.6.0/*'
		$asset.Sha256 | Should -Match '^[0-9a-f]{64}$'
	}

	It 'uses a compatible application from PATH without bootstrapping' {
		$assetName = (Get-ToolchainCosignBootstrapAsset).AssetName
		Mock Get-Command {
			param($Name)
			if ($Name -eq $assetName) { return [pscustomobject]@{ Source='platform-cosign' } }
			return $null
		}
		Mock Install-ToolchainCosignBootstrap { throw 'should not bootstrap' }

		(Resolve-ToolchainCosignApplication).Source | Should -Be 'platform-cosign'
		Should -Invoke Install-ToolchainCosignBootstrap -Times 0
	}

	It 'installs and reuses a checksum-verified bootstrap atomically' {
		$bytes = [Text.Encoding]::UTF8.GetBytes('verified-cosign-test-binary')
		$sha = [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
		$asset = [pscustomobject]@{
			Version='v-test'
			AssetName='cosign-test.exe'
			ExecutableName='cosign.exe'
			Sha256=$sha
			Uri='https://example.test/cosign.exe'
		}
		Mock Get-ToolchainCosignBootstrapAsset { $asset }
		Mock GetToolchainPath { Join-Path $TestDrive 'toolchain' }
		Mock Invoke-WebRequest {
			param($Uri, $Method, $Headers, $OutFile)
			[IO.File]::WriteAllBytes($OutFile, $bytes)
		}

		$installed = Install-ToolchainCosignBootstrap
		Test-ToolchainCosignBootstrapFile -Path $installed.Source -ExpectedSha256 $sha | Should -BeTrue
		(Resolve-ToolchainCosignApplication).Source | Should -Be $installed.Source
		Should -Invoke Invoke-WebRequest -Times 1 -Exactly
	}

	It 'rejects a bootstrap download whose checksum does not match' {
		$asset = [pscustomobject]@{
			Version='v-test-bad'
			AssetName='cosign-test.exe'
			ExecutableName='cosign.exe'
			Sha256=('0' * 64)
			Uri='https://example.test/cosign.exe'
		}
		Mock Get-ToolchainCosignBootstrapAsset { $asset }
		Mock GetToolchainPath { Join-Path $TestDrive 'toolchain-bad' }
		Mock Invoke-WebRequest {
			param($Uri, $Method, $Headers, $OutFile)
			[IO.File]::WriteAllText($OutFile, 'tampered')
		}

		{ Install-ToolchainCosignBootstrap } | Should -Throw '*SHA-256 mismatch*'
		Test-Path -LiteralPath (Get-ToolchainCosignBootstrapPath -Asset $asset) | Should -BeFalse
	}
}

Describe 'Import-ToolchainPkcs' {
	It 'Handles Add-Type failures gracefully' {
		$script:calls = 0
		Mock Add-Type {
			$script:calls++
			throw 'nope'
		}
		{ Import-ToolchainPkcs } | Should -Not -Throw
		$script:calls | Should -BeGreaterThan 0
	}
}

Describe 'Get-ToolchainSigningCert' {
	It 'Selects by thumbprint when provided' {
		$good = [pscustomobject]@{ Thumbprint='AA BB'; HasPrivateKey=$true; EnhancedKeyUsageList=@(); NotAfter=(Get-Date).AddDays(1); Subject='CN=good' }
		$other = [pscustomobject]@{ Thumbprint='CC DD'; HasPrivateKey=$true; EnhancedKeyUsageList=@(); NotAfter=(Get-Date).AddDays(2); Subject='CN=other' }
		Mock Get-ChildItem { return @($other,$good) }
		$env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT = 'AABB'
		$r = Get-ToolchainSigningCert
		$r.Subject | Should -Be 'CN=good'
	}

	It 'Prefers code signing cert when thumbprint not provided' {
		$eku = @([pscustomobject]@{ FriendlyName='Code Signing' })
		$code = [pscustomobject]@{ Thumbprint='11'; HasPrivateKey=$true; EnhancedKeyUsageList=$eku; NotAfter=(Get-Date).AddDays(5); Subject='CN=code' }
		$plain = [pscustomobject]@{ Thumbprint='22'; HasPrivateKey=$true; EnhancedKeyUsageList=@(); NotAfter=(Get-Date).AddDays(10); Subject='CN=plain' }
		Mock Get-ChildItem { return @($plain,$code) }
		Remove-Item Env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT -ErrorAction Ignore
		$r = Get-ToolchainSigningCert
		$r.Subject | Should -Be 'CN=code'
	}

	It 'Falls back to any private-key cert when no code signing cert present' {
		$plain1 = [pscustomobject]@{ Thumbprint='33'; HasPrivateKey=$true; EnhancedKeyUsageList=@(); NotAfter=(Get-Date).AddDays(1); Subject='CN=a' }
		$plain2 = [pscustomobject]@{ Thumbprint='44'; HasPrivateKey=$true; EnhancedKeyUsageList=@(); NotAfter=(Get-Date).AddDays(9); Subject='CN=b' }
		Mock Get-ChildItem { return @($plain1,$plain2) }
		$r = Get-ToolchainSigningCert
		$r.Subject | Should -Be 'CN=b'
	}

	It 'Throws with helpful message when thumbprint not found' {
		Mock Get-ChildItem { return @() }
		$env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT = 'FFFF'
		{ Get-ToolchainSigningCert } | Should -Throw
	}
}

Describe 'CMS signatures' {
	BeforeAll {
		$script:cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Toolchain CI Test' -CertStoreLocation 'Cert:\CurrentUser\My'
		$env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT = $script:cert.Thumbprint
	}
	AfterAll {
		try {
			Remove-Item -LiteralPath ("Cert:\\CurrentUser\\My\\" + $script:cert.Thumbprint) -Force -ErrorAction SilentlyContinue
		} catch { Write-Debug "Certificate cleanup failed: $($_.Exception.Message)" }
		Remove-Item Env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT -ErrorAction Ignore
	}

	It 'New-ToolchainFileCmsSignature respects ShouldProcess' {
		$p = Join-Path $TestDrive 'a.txt'
		Set-Content -LiteralPath $p -Value 'hello' -Encoding utf8
		$s = Join-Path $TestDrive 'a.sig'
		$r = New-ToolchainFileCmsSignature -Path $p -SignaturePath $s -WhatIf
		$r | Should -Be $null
		(Test-Path -LiteralPath $s) | Should -Be $false
	}

	It 'Signs and verifies a file with trusted allowlist' {
		$p = Join-Path $TestDrive 'b.txt'
		Set-Content -LiteralPath $p -Value 'hello' -Encoding utf8
		$s = Join-Path $TestDrive 'b.sig'

		$r = New-ToolchainFileCmsSignature -Path $p -SignaturePath $s
		(Test-Path -LiteralPath $r) | Should -Be $true

		$info = Confirm-ToolchainFileCmsSignature -Path $p -SignaturePath $s -TrustedThumbprints @($script:cert.Thumbprint)
		$info.Thumbprint | Should -Be ($script:cert.Thumbprint -replace ' ','').ToUpperInvariant()
	}

	It 'Rejects untrusted signers' {
		$p = Join-Path $TestDrive 'c.txt'
		Set-Content -LiteralPath $p -Value 'hello' -Encoding utf8
		$s = Join-Path $TestDrive 'c.sig'
		$null = New-ToolchainFileCmsSignature -Path $p -SignaturePath $s
		{ Confirm-ToolchainFileCmsSignature -Path $p -SignaturePath $s -TrustedThumbprints @('DEADBEEF') } | Should -Throw
	}

	It 'Throws when signature file is missing' {
		$p = Join-Path $TestDrive 'd.txt'
		Set-Content -LiteralPath $p -Value 'hello' -Encoding utf8
		$s = Join-Path $TestDrive 'd.sig'
		{ Confirm-ToolchainFileCmsSignature -Path $p -SignaturePath $s } | Should -Throw
	}

	It 'Throws on invalid signature bytes' {
		$p = Join-Path $TestDrive 'e.txt'
		Set-Content -LiteralPath $p -Value 'hello' -Encoding utf8
		$s = Join-Path $TestDrive 'e.sig'
		[IO.File]::WriteAllBytes($s, [byte[]](1,2,3,4,5))
		{ Confirm-ToolchainFileCmsSignature -Path $p -SignaturePath $s } | Should -Throw
	}
}

Describe 'Assert-ToolchainSignedManifest' {
	It 'No-ops when policy does not require signed manifests' {
		Mock Get-ToolchainPolicyRequireSignedManifest { return $false }
		Mock Confirm-ToolchainFileCmsSignature { throw 'should not' }
		{ Assert-ToolchainSignedManifest -ManifestPath (Join-Path $TestDrive 'm.json') } | Should -Not -Throw
	}

	It 'Validates signature when required' {
		Mock Get-ToolchainPolicyRequireSignedManifest { return $true }
		Mock Get-ToolchainPolicyTrustedSigner { return @('AA') }
		Mock Confirm-ToolchainFileCmsSignature { return @{ Thumbprint='AA'; Subject='CN=x' } }
		{ Assert-ToolchainSignedManifest -ManifestPath (Join-Path $TestDrive 'm.json') } | Should -Not -Throw
		Should -Invoke -CommandName Confirm-ToolchainFileCmsSignature -Times 1 -Exactly
	}

	It 'fails closed when signed manifests are required without configured trust' {
		Mock Get-ToolchainPolicyRequireSignedManifest { return $true }
		Mock Get-ToolchainPolicyTrustedSigner { return @() }
		Mock Confirm-ToolchainFileCmsSignature { throw 'must not verify without trust configuration' }
		{ Assert-ToolchainSignedManifest -ManifestPath (Join-Path $TestDrive 'm.json') } | Should -Throw '*no trustedSigners are configured*'
		Should -Invoke -CommandName Confirm-ToolchainFileCmsSignature -Times 0 -Exactly
	}
}
