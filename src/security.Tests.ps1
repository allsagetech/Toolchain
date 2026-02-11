<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
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

	It 'Get-ToolchainCosignKey prefers policy over env' {
		Mock Get-ToolchainPolicyCosignKey { return 'policy.pem' }
		$env:TOOLCHAIN_COSIGN_KEY = 'env.pem'
		(Get-ToolchainCosignKey) | Should -Be 'policy.pem'
	}

	It 'Invoke-ToolchainCosignVerify no-ops when disabled' {
		Mock Get-ToolchainCosignVerifyEnabled { return $false }
		Mock Get-Command { throw 'should not be called' }
		{ Invoke-ToolchainCosignVerify -RepoDigestRef 'repo@sha256:abc' } | Should -Not -Throw
	}

	It 'Invoke-ToolchainCosignVerify throws when cosign missing' {
		Mock Get-ToolchainCosignVerifyEnabled { return $true }
		Mock Get-Command { return $null }
		{ Invoke-ToolchainCosignVerify -RepoDigestRef 'repo@sha256:abc' } | Should -Throw
	}

	It 'Invoke-ToolchainCosignVerify calls cosign with flags' {
		Mock Get-ToolchainCosignVerifyEnabled { return $true }
		Mock Get-ToolchainCosignKey { return 'key.pem' }
		$env:TOOLCHAIN_COSIGN_CERT_IDENTITY = 'me@example.com'
		$env:TOOLCHAIN_COSIGN_OIDC_ISSUER = 'https://issuer.example'

		Mock Get-Command {
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
		} catch { }
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
}
