<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\policy.ps1

function Import-ToolchainPkcs {
	try {
		Add-Type -AssemblyName System.Security -ErrorAction Stop
	} catch {
		Write-Debug "Add-Type System.Security failed or was unnecessary: $_"
	}
	try {
		Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop
	} catch {
		Write-Debug "Add-Type System.Security.Cryptography.Pkcs failed or was unnecessary: $_"
	}
}

function Invoke-ToolchainCommand {
	param(
		[Parameter(Mandatory)][string]$File,
		[string[]]$ArgumentList = @(),
		[switch]$Quiet
	)
	$prev = $global:PSNativeCommandUseErrorActionPreference
	$global:PSNativeCommandUseErrorActionPreference = $false
	try {
		$out = & $File @ArgumentList 2>&1
		$code = $LASTEXITCODE
		if ($code -ne 0) {
			$joined = ($ArgumentList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
			throw "Command failed (exit code $code): $File $joined`n$out"
		}
		if (-not $Quiet) { return $out }
		return $null
	} finally {
		$global:PSNativeCommandUseErrorActionPreference = $prev
	}
}

function Get-ToolchainCosignVerifyEnabled {
	if (Get-ToolchainPolicyRequireCosign) { return $true }
	if (Test-TruthyValue $env:TOOLCHAIN_COSIGN_VERIFY) { return $true }
	return $false
}

function Get-ToolchainCosignKey {
	$key = Get-ToolchainPolicyCosignKey
	if ($key) { return $key }
	if ($env:TOOLCHAIN_COSIGN_KEY) { return $env:TOOLCHAIN_COSIGN_KEY }
	return $null
}

function Invoke-ToolchainCosignVerify {
	param(
		[Parameter(Mandatory)][string]$RepoDigestRef
	)

	if (-not (Get-ToolchainCosignVerifyEnabled)) { return }

	$cosign = (Get-Command 'cosign' -ErrorAction SilentlyContinue)
	if (-not $cosign) {
		throw "cosign verification requested but 'cosign' was not found in PATH"
	}

	$cosignArgs = @('verify')
	$key = Get-ToolchainCosignKey
	if ($key) { $cosignArgs += @('--key', $key) }
	if ($env:TOOLCHAIN_COSIGN_CERT_IDENTITY) { $cosignArgs += @('--certificate-identity', $env:TOOLCHAIN_COSIGN_CERT_IDENTITY) }
	if ($env:TOOLCHAIN_COSIGN_OIDC_ISSUER) { $cosignArgs += @('--certificate-oidc-issuer', $env:TOOLCHAIN_COSIGN_OIDC_ISSUER) }
	$cosignArgs += @($RepoDigestRef)

	$null = Invoke-ToolchainCommand -File $cosign.Source -ArgumentList $cosignArgs -Quiet
}

function Get-ToolchainSigningCert {
	$thumb = $null
	if ($ToolchainManifestSignThumbprint) { $thumb = $ToolchainManifestSignThumbprint }
	elseif ($env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT) { $thumb = $env:TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT }
	if ($thumb) { $thumb = ([string]$thumb).Replace(' ','').ToUpperInvariant() }

	$stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
	foreach ($s in $stores) {
		try {
			$certs = Get-ChildItem -Path $s -ErrorAction SilentlyContinue
			if (-not $certs) { continue }
			if ($thumb) {
				$c = $certs | Where-Object { ($_.Thumbprint -replace ' ','').ToUpperInvariant() -eq $thumb } | Select-Object -First 1
				if ($c) { return $c }
			} else {
				$c = $certs | Where-Object {
					$_.HasPrivateKey -and ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq 'Code Signing' } | Select-Object -First 1)
				} | Sort-Object NotAfter -Descending | Select-Object -First 1
				if (-not $c) {
					$c = $certs | Where-Object { $_.HasPrivateKey } | Sort-Object NotAfter -Descending | Select-Object -First 1
				}
				if ($c) { return $c }
			}
		} catch {
			Write-Debug "Failed to enumerate certificates from ${s}: $_"
		}
	}

	if ($thumb) {
		throw "No signing certificate found with thumbprint $thumb"
	}
	throw "No signing certificate found. Set TOOLCHAIN_MANIFEST_SIGN_THUMBPRINT to a certificate thumbprint."
}

function New-ToolchainFileCmsSignature {
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
	param(
		[Parameter(Mandatory)][string]$Path,
		[string]$SignaturePath
	)
	if (-not $SignaturePath) { $SignaturePath = "$Path.p7s" }

	if (-not $PSCmdlet.ShouldProcess($SignaturePath, "Write CMS signature for $Path")) {
		return $null
	}
	$cert = Get-ToolchainSigningCert
	Import-ToolchainPkcs
	$contentBytes = [IO.File]::ReadAllBytes($Path)
	$contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (, $contentBytes)
	$cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList ($contentInfo, $true)
	$signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList ($cert)
	$signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
	$cms.ComputeSignature($signer)
	[IO.File]::WriteAllBytes($SignaturePath, $cms.Encode())
	return $SignaturePath
}

function Confirm-ToolchainFileCmsSignature {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][string]$SignaturePath,
		[string[]]$TrustedThumbprints
	)
	Import-ToolchainPkcs
	if (-not (Test-Path -LiteralPath $SignaturePath -PathType Leaf)) {
		throw "Missing signature: $SignaturePath"
	}
	$contentBytes = [IO.File]::ReadAllBytes($Path)
	$sigBytes = [IO.File]::ReadAllBytes($SignaturePath)
	$contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (, $contentBytes)
	$cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList ($contentInfo, $true)
	$cms.Decode($sigBytes)

	try {
		$cms.CheckSignature($true)
	} catch {
		throw "Invalid signature for ${Path}: $_"
	}

	$signer = $cms.SignerInfos | Select-Object -First 1
	$cert = if ($signer) { $signer.Certificate } else { $null }
	$thumb = if ($cert) { ($cert.Thumbprint -replace ' ','').ToUpperInvariant() } else { $null }
	if ($TrustedThumbprints -and $TrustedThumbprints.Count -gt 0) {
		$ok = $false
		foreach ($t in $TrustedThumbprints) {
			if ($thumb -eq (([string]$t).Replace(' ','').ToUpperInvariant())) { $ok = $true; break }
		}
		if (-not $ok) {
			throw "Signature for $Path was made by untrusted signer: $thumb"
		}
	}

	return @{ Thumbprint = $thumb; Subject = if ($cert) { $cert.Subject } else { $null } }
}

function Assert-ToolchainSignedManifest {
	param(
		[Parameter(Mandatory)][string]$ManifestPath
	)
	if (-not (Get-ToolchainPolicyRequireSignedManifest)) { return }
	$sig = "$ManifestPath.p7s"
	$trusted = Get-ToolchainPolicyTrustedSigner
	$null = Confirm-ToolchainFileCmsSignature -Path $ManifestPath -SignaturePath $sig -TrustedThumbprints $trusted
}

Set-Alias -Name Sign-ToolchainFileCms -Value New-ToolchainFileCmsSignature
Set-Alias -Name Verify-ToolchainFileCms -Value Confirm-ToolchainFileCmsSignature
