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
	$prev = $PSNativeCommandUseErrorActionPreference
	$PSNativeCommandUseErrorActionPreference = $false
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
		$PSNativeCommandUseErrorActionPreference = $prev
	}
}

function Test-ToolchainOfficialRepository {
	try {
		$hostName = ([Uri]::new((GetRegistryBaseUrl))).Host
		$officialRegistry = $hostName -in @('registry-1.docker.io', 'index.docker.io')
		$officialRepository = [string]::Equals((GetRegistryRepoName), 'allsagetech/toolchains', [StringComparison]::OrdinalIgnoreCase)
		return ($officialRegistry -and $officialRepository)
	} catch {
		return $false
	}
}

function Get-ToolchainCosignVerifyEnabled {
	$explicit = [Environment]::GetEnvironmentVariable('TOOLCHAIN_COSIGN_VERIFY', [EnvironmentVariableTarget]::Process)
	if (-not [string]::IsNullOrEmpty($explicit)) { return (Test-TruthyValue $explicit) }
	if (Get-ToolchainPolicyRequireCosign) { return $true }
	if (GetToolchainRepo) { return $false }
	return (Test-ToolchainOfficialRepository)
}

function Get-ToolchainCosignKey {
	$key = Get-ToolchainPolicyCosignKey
	if ($key) { return $key }
	if ($env:TOOLCHAIN_COSIGN_KEY) { return $env:TOOLCHAIN_COSIGN_KEY }
	return $null
}

function Get-ToolchainCosignBootstrapAsset {
	$os = if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
		'windows'
	} elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)) {
		'linux'
	} elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::OSX)) {
		'darwin'
	} else {
		throw 'automatic Cosign bootstrap does not support this operating system'
	}

	$arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
		'X64' { 'amd64' }
		'Arm64' { 'arm64' }
		default { throw "automatic Cosign bootstrap does not support architecture '$([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)'" }
	}

	$version = 'v2.6.0'
	$key = "$os/$arch"
	switch ($key) {
		'windows/amd64' {
			$assetName = 'cosign-windows-amd64.exe'
			$sha256 = '7beb4dd1e19a72c328bbf7c0d7342d744edbf5cbb082f227b2b76e04a21c16ef'
			$executableName = 'cosign.exe'
		}
		'linux/amd64' {
			$assetName = 'cosign-linux-amd64'
			$sha256 = 'ea5c65f99425d6cfbb5c4b5de5dac035f14d09131c1a0ea7c7fc32eab39364f9'
			$executableName = 'cosign'
		}
		'linux/arm64' {
			$assetName = 'cosign-linux-arm64'
			$sha256 = 'e09684650882fd721ed22b716ffc399ee11426cd4d1c9b4fec539cba8bf46b86'
			$executableName = 'cosign'
		}
		'darwin/amd64' {
			$assetName = 'cosign-darwin-amd64'
			$sha256 = '83b0fb42bc265e62aef7de49f4979b7957c9b7320d362a9f20046b2f823330f3'
			$executableName = 'cosign'
		}
		'darwin/arm64' {
			$assetName = 'cosign-darwin-arm64'
			$sha256 = 'dea5b83b8b375b99ac803c7bdb1f798963dbeb47789ceb72153202e7f20e8d07'
			$executableName = 'cosign'
		}
		default { throw "automatic Cosign bootstrap does not support platform '$key'" }
	}

	return [pscustomobject]@{
		Version = $version
		AssetName = $assetName
		Sha256 = $sha256
		ExecutableName = $executableName
		Uri = "https://github.com/sigstore/cosign/releases/download/$version/$assetName"
	}
}

function Get-ToolchainCosignBootstrapPath {
	param(
		[Parameter(Mandatory)]$Asset
	)
	$root = Join-Path (GetToolchainPath) 'security'
	return Join-Path (Join-Path (Join-Path $root 'cosign') $Asset.Version) $Asset.ExecutableName
}

function Test-ToolchainCosignBootstrapFile {
	param(
		[Parameter(Mandatory)][string]$Path,
		[Parameter(Mandatory)][string]$ExpectedSha256
	)
	$item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
	if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
		return $false
	}
	$actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
	return [string]::Equals($actual, $ExpectedSha256, [StringComparison]::Ordinal)
}

function Find-ToolchainCosignApplication {
	$asset = $null
	try { $asset = Get-ToolchainCosignBootstrapAsset } catch { Write-Debug "Cosign bootstrap platform detection failed: $($_.Exception.Message)" }
	$candidateNames = @('cosign')
	if ($asset) { $candidateNames += $asset.AssetName }
	foreach ($name in $candidateNames) {
		$command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($command -and $command.Source) { return $command }
	}

	if (-not $asset) { return $null }
	$path = Get-ToolchainCosignBootstrapPath -Asset $asset
	if (Test-ToolchainCosignBootstrapFile -Path $path -ExpectedSha256 $asset.Sha256) {
		return [pscustomobject]@{ Source = $path; Origin = 'verified-bootstrap' }
	}
	return $null
}

function Test-ToolchainCosignBootstrapSupported {
	try {
		$null = Get-ToolchainCosignBootstrapAsset
		return $true
	} catch {
		return $false
	}
}

function Install-ToolchainCosignBootstrap {
	try {
		$asset = Get-ToolchainCosignBootstrapAsset
	} catch {
		throw "Cosign verification is required, but no Cosign executable was found and $($_.Exception.Message). Install Cosign on PATH."
	}

	$destination = Get-ToolchainCosignBootstrapPath -Asset $asset
	if (Test-ToolchainCosignBootstrapFile -Path $destination -ExpectedSha256 $asset.Sha256) {
		return [pscustomobject]@{ Source = $destination; Origin = 'verified-bootstrap' }
	}

	$directory = Split-Path -Parent $destination
	foreach ($path in @(
		(Join-Path (GetToolchainPath) 'security'),
		(Join-Path (Join-Path (GetToolchainPath) 'security') 'cosign'),
		$directory
	)) {
		$item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
		if ($item -and (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
			throw "refusing to use unsafe Cosign bootstrap directory: $path"
		}
		if (-not $item) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
	}

	$existing = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
	if ($existing -and ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
		throw "refusing to replace unsafe Cosign bootstrap path: $destination"
	}

	$tempPath = Join-Path $directory ('.' + $asset.ExecutableName + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
	$backupPath = Join-Path $directory ('.' + $asset.ExecutableName + '.' + [Guid]::NewGuid().ToString('N') + '.bak')
	try {
		Write-ToolchainInfo "Cosign was not found on PATH; downloading pinned verifier $($asset.Version)"
		Invoke-WebRequest -Uri $asset.Uri -Method Get -Headers @{ 'User-Agent' = 'AllSageTech-Toolchain' } -UseBasicParsing -OutFile $tempPath
		if (-not (Test-ToolchainCosignBootstrapFile -Path $tempPath -ExpectedSha256 $asset.Sha256)) {
			$actual = if (Test-Path -LiteralPath $tempPath -PathType Leaf) { (Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { '<missing>' }
			throw "Cosign SHA-256 mismatch for $($asset.AssetName). Expected $($asset.Sha256), received $actual."
		}

		if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
			& chmod '+x' $tempPath
			if ($LASTEXITCODE -ne 0) { throw "could not make the verified Cosign bootstrap executable: $tempPath" }
		}

		if (Test-Path -LiteralPath $destination -PathType Leaf) {
			[IO.File]::Replace($tempPath, $destination, $backupPath)
		} else {
			[IO.File]::Move($tempPath, $destination)
		}
		if (-not (Test-ToolchainCosignBootstrapFile -Path $destination -ExpectedSha256 $asset.Sha256)) {
			throw "verified Cosign bootstrap could not be installed at $destination"
		}
		return [pscustomobject]@{ Source = $destination; Origin = 'verified-bootstrap' }
	} catch {
		throw "Cosign verification is required and automatic verified bootstrap failed: $($_.Exception.Message)"
	} finally {
		[IO.File]::Delete($tempPath)
		[IO.File]::Delete($backupPath)
	}
}

function Resolve-ToolchainCosignApplication {
	$command = Find-ToolchainCosignApplication
	if ($command) { return $command }
	return Install-ToolchainCosignBootstrap
}

function Invoke-ToolchainCosignVerify {
	param(
		[Parameter(Mandatory)][string]$RepoDigestRef,
		[switch]$Force
	)

	if (-not $Force -and -not (Get-ToolchainCosignVerifyEnabled)) { return }

	$cosign = Resolve-ToolchainCosignApplication

	$cosignArgs = @('verify')
	$key = Get-ToolchainCosignKey
	if ($key) { $cosignArgs += @('--key', $key) }
	$identity = [string]$env:TOOLCHAIN_COSIGN_CERT_IDENTITY
	$issuer = [string]$env:TOOLCHAIN_COSIGN_OIDC_ISSUER
	if (-not $key -and -not $identity -and (Test-ToolchainOfficialRepository)) {
		$identity = 'https://github.com/allsagetech/Toolchains/.github/workflows/build-push.yml@refs/heads/main'
		$issuer = 'https://token.actions.githubusercontent.com'
	}
	if ($identity) { $cosignArgs += @('--certificate-identity', $identity) }
	if ($issuer) { $cosignArgs += @('--certificate-oidc-issuer', $issuer) }
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
	if (-not $trusted -or $trusted.Count -eq 0) {
		throw 'Signed offline manifests are required, but no trustedSigners are configured in Toolchain.policy.json.'
	}
	$null = Confirm-ToolchainFileCmsSignature -Path $ManifestPath -SignaturePath $sig -TrustedThumbprints $trusted
}

Set-Alias -Name Sign-ToolchainFileCms -Value New-ToolchainFileCmsSignature
Set-Alias -Name Verify-ToolchainFileCms -Value Confirm-ToolchainFileCmsSignature
