<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\http.ps1
. $PSScriptRoot\config.ps1
. $PSScriptRoot\policy.ps1
. $PSScriptRoot\security.ps1
. $PSScriptRoot\progress.ps1
. $PSScriptRoot\tar.ps1
. $PSScriptRoot\definition.ps1
. $PSScriptRoot\catalog-cache.ps1

. $PSScriptRoot\registry-transport.ps1

. $PSScriptRoot\registry-catalog.ps1

function GetManifest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref,
		[ValidateSet('GET', 'HEAD')]
		[string]$Method = 'GET'
	)

	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		try {
			$manifestPath = Resolve-ToolchainChildPath -Root $repoPath -RelativePath "$Ref/manifest.json" -RejectReparsePoints
		} catch {
			throw "unsafe offline manifest reference '$Ref': $($_.Exception.Message)"
		}
		$file = Get-Item -LiteralPath $manifestPath -ErrorAction SilentlyContinue
		if (-not $file -or -not $file.Exists) {
			return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::NotFound)
		}
		Assert-ToolchainSignedManifest -ManifestPath $file.FullName
		$response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$response.Headers.Add('Docker-Content-Digest', "sha256:$((Get-FileHash $file).Hash.ToLower())")
		if ($Method -eq 'GET') {
			$response.Content = [Net.Http.ByteArrayContent]::new([IO.File]::ReadAllBytes($file))
			$response.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
		}
		return $response
	}
	Assert-ToolchainRegistryPolicyAllowed -Action 'fetch manifest' -RegistryBaseUrl (GetRegistryBaseUrl) -Repository (GetRegistryRepoName)

	$api = "/v2/$(GetRegistryRepoName)/manifests/$Ref"
	$url = GetRegistryUrl $api

	$accept = @(
		'application/vnd.docker.distribution.manifest.v2+json',
		'application/vnd.oci.image.manifest.v1+json',
		'application/vnd.docker.distribution.manifest.list.v2+json',
		'application/vnd.oci.image.index.v1+json'
	) -join ', '

	return InvokeRegistryBaseRequest -Url $url -Method $Method -Accept $accept
}

function GetVerifiedManifestResponse {
	param(
		[Parameter(Mandatory)][string]$Ref,
		[string]$ExpectedDigest,
		[Nullable[long]]$ExpectedSize
	)
	$expected = $null
	if ($ExpectedDigest) {
		$expected = $ExpectedDigest | ConvertTo-CanonicalSha256Digest
	} elseif ($Ref -match '^sha256:') {
		$expected = $Ref | ConvertTo-CanonicalSha256Digest
	}

	$resp = GetManifest -Ref $Ref -Method GET
	try {
		if (-not $resp.IsSuccessStatusCode) {
			throw "cannot fetch manifest for ${Ref}: $($resp.ReasonPhrase)"
		}
		$maxManifestBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_MANIFEST_BYTES' -Default 16777216
		$bytes = Read-ToolchainBoundedResponseBytes -Response $resp -MaximumBytes $maxManifestBytes -ExpectedSize $ExpectedSize -Context "manifest '$Ref'"
		$actual = Get-ToolchainBytesSha256Digest -Bytes $bytes
		$headerDigest = Get-ToolchainResponseDigestHeader -Response $resp
		if ($headerDigest -and $headerDigest -ne $actual) {
			throw "manifest digest header mismatch for ${Ref}: header $headerDigest, content $actual"
		}
		if ($expected -and $expected -ne $actual) {
			throw "manifest digest mismatch for ${Ref}: expected $expected, got $actual"
		}
		Set-ToolchainBufferedResponseContent -Response $resp -Bytes $bytes
		$null = $resp.Headers.Remove('Docker-Content-Digest')
		$null = $resp.Headers.TryAddWithoutValidation('Docker-Content-Digest', $actual)
		return $resp
	} catch {
		$resp.Dispose()
		throw
	}
}

function ResolveManifestToSinglePlatform {
	param(
		[Parameter(Mandatory)][object]$Manifest
	)

	if ($Manifest.layers) { return $Manifest }

	$manifests = $Manifest.manifests
	if (-not $manifests) { return $Manifest }

	$wantOs = GetRegistryPlatformOs
	$wantArch = GetRegistryPlatformArch

	$candidate = $manifests | Where-Object {
		$_.platform -and ($_.platform.os -eq $wantOs) -and ($_.platform.architecture -eq $wantArch)
	} | Select-Object -First 1

	if (-not $candidate) {
		$available = @(
			$manifests | ForEach-Object {
				if ($_.platform -and $_.platform.os -and $_.platform.architecture) {
					"$($_.platform.os)/$($_.platform.architecture)"
				} else {
					'<unknown>'
				}
			} | Sort-Object -Unique
		) -join ', '
		throw "no manifest for requested platform ${wantOs}/${wantArch}; available platforms: $available"
	}
	return $candidate
}

function GetManifestJson {
	param(
		[Parameter(Mandatory)][string]$Ref
	)
	$resp = GetVerifiedManifestResponse -Ref $Ref
	try {
		return $resp | GetJsonResponse
	} finally {
		$resp.Dispose()
	}
}

function GetResolvedManifestResponse {
	param(
		[Parameter(Mandatory)][string]$Ref,
		[ValidateSet('GET','HEAD')][string]$Method='GET',
		[string]$ExpectedDigest
	)

	if ($Method -eq 'HEAD') {
		return (GetManifest -Ref $Ref -Method HEAD)
	}

	$rootResponse = GetVerifiedManifestResponse -Ref $Ref -ExpectedDigest $ExpectedDigest
	try {
		$manifest = $rootResponse | GetJsonResponse
		$choice = ResolveManifestToSinglePlatform -Manifest $manifest
		if ($choice.digest) {
			$maxManifestBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_MANIFEST_BYTES' -Default 16777216
			$descriptor = Assert-ToolchainDescriptor -Descriptor $choice -Context 'platform manifest descriptor' -MaximumSize $maxManifestBytes
			$rootResponse.Dispose()
			$rootResponse = $null
			return (GetVerifiedManifestResponse -Ref $descriptor.Digest -ExpectedDigest $descriptor.Digest -ExpectedSize $descriptor.Size)
		}
		$response = $rootResponse
		$rootResponse = $null
		return $response
	} finally {
		if ($rootResponse) { $rootResponse.Dispose() }
	}
}

function GetJsonFromResponse {
  param([Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Resp)
  $s = $Resp.Content.ReadAsStringAsync().Result
  return ($s | ConvertFrom-Json)
}

function GetResolvedManifestJson {
  param(
    [Parameter(Mandatory)][string]$Ref,
    [string]$ExpectedDigest
  )

  $resp = GetResolvedManifestResponse -Ref $Ref -Method GET -ExpectedDigest $ExpectedDigest
  try {
    if (-not $resp.IsSuccessStatusCode) {
      throw "cannot fetch manifest for ${Ref}: $($resp.ReasonPhrase)"
    }
    return ($resp | GetJsonResponse)
  } finally {
    $resp.Dispose()
  }
}

function GetImageConfigJsonFromRef {
  param(
    [Parameter(Mandatory)][string]$Ref,
    [string]$ExpectedManifestDigest
  )

  $manifest = GetResolvedManifestJson -Ref $Ref -ExpectedDigest $ExpectedManifestDigest
  if (-not $manifest.config -or -not $manifest.config.digest) {
    return $null
  }

	$maxConfigBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_CONFIG_BYTES' -Default 16777216
	$descriptor = Assert-ToolchainDescriptor -Descriptor $manifest.config -Context 'image config descriptor' -MaximumSize $maxConfigBytes
	$resp = GetBlob -Ref $descriptor.Digest -StartByte 0
  try {
    if (-not $resp.IsSuccessStatusCode) {
		throw "cannot fetch image config blob $($descriptor.Digest): $($resp.ReasonPhrase)"
    }
		$bytes = Read-ToolchainBoundedResponseBytes -Response $resp -MaximumBytes $maxConfigBytes -ExpectedSize $descriptor.Size -Context 'image config blob'
		$actual = Get-ToolchainBytesSha256Digest -Bytes $bytes
		if ($actual -ne $descriptor.Digest) {
			throw "image config digest mismatch: expected $($descriptor.Digest), got $actual"
		}
		try {
			return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
		} catch {
			throw "failed to parse image config JSON: $_"
		}
  } finally {
    $resp.Dispose()
  }
}

function GetToolchainDefinitionFromLabels {
  param(
    [Parameter(Mandatory)][string]$Ref,
    [Parameter(Mandatory)][string]$RootPath
  )
	# Offline bundles intentionally contain the verified manifest and package
	# layers, not the image config blob. Definitions therefore come from the
	# extracted .tlc/.pwr file in offline mode.
	if (GetToolchainRepo) { return $null }

  $cfg = GetImageConfigJsonFromRef -Ref $Ref
  if (-not $cfg) { return $null }

  $labels = $null
  if ($cfg.config -and $cfg.config.Labels) { $labels = $cfg.config.Labels }
  elseif ($cfg.Labels) { $labels = $cfg.Labels }

  if (-not $labels) { return $null }


  $spec = $labels.'io.allsagetech.toolchain.specVersion'
  if (-not $spec) { $spec = $labels.'toolchain.specVersion' }
  if ($spec) {
    $want = 0
		if (-not [int]::TryParse([string]$spec, [ref]$want) -or $want -lt 1) {
			throw "package has invalid specVersion '$spec'"
		}
    $supported = 1
    if ($want -gt $supported) {
      throw "package specVersion $want is newer than this Toolchain supports ($supported). Update Toolchain."
    }
  }

  $tlcLabel = $labels.'io.allsagetech.toolchain.tlc'
  if (-not $tlcLabel) { $tlcLabel = $labels.'toolchain.tlc' }

  if ($tlcLabel) {
    $json = [string]$tlcLabel
    $def = ($json | ConvertFrom-Json | ConvertTo-HashTable)
	$null = Expand-ToolchainDefinitionRoot -Definition $def -RootPath $RootPath
    Assert-ToolchainDefinition -Definition $def -Context "labels($Ref)"
    return $def
  }

  $tlcPathLabel = $labels.'io.allsagetech.toolchain.tlcPath'
  if (-not $tlcPathLabel) { $tlcPathLabel = $labels.'toolchain.tlcPath' }

  $tlcSha256Label = $labels.'io.allsagetech.toolchain.tlcSha256'
  if (-not $tlcSha256Label) { $tlcSha256Label = $labels.'toolchain.tlcSha256' }

  if ($tlcPathLabel) {
    $rel = ([string]$tlcPathLabel).Trim()
    if ($rel.StartsWith('/')) { $rel = $rel.Substring(1) }
		try {
			$tlcFile = Resolve-ToolchainChildPath -Root $RootPath -RelativePath $rel -RejectReparsePoints -RejectRootReparsePoint
		} catch {
			throw "unsafe toolchain definition path '$tlcPathLabel': $($_.Exception.Message)"
		}

		if (-not (Test-Path -LiteralPath $tlcFile -PathType Leaf)) {
      throw "toolchain definition file not found at '$tlcFile' (label: $tlcPathLabel)"
    }

    if ($tlcSha256Label) {
      $expected = ([string]$tlcSha256Label).Trim().ToLower()
		if ($expected -notmatch '^[0-9a-f]{64}$') {
			throw "invalid toolchain definition sha256 '$tlcSha256Label'"
		}
		$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tlcFile).Hash.ToLower()
      if ($actual -ne $expected) {
        throw "toolchain definition sha256 mismatch for '$tlcFile': expected $expected, got $actual"
      }
    }

		$json = (Get-Content -LiteralPath $tlcFile -Raw)
    $def = ($json | ConvertFrom-Json | ConvertTo-HashTable)
		$null = Expand-ToolchainDefinitionRoot -Definition $def -RootPath $RootPath
    $ctx = ("file({0}:{1})" -f $Ref, $tlcPathLabel)
    Assert-ToolchainDefinition -Definition $def -Context $ctx
    return $def
  }

  $envMap = @{}
  $props = @()
  if ($labels -is [Collections.Hashtable]) {
    foreach ($k in $labels.Keys) {
      $props += [pscustomobject]@{ Name = [string]$k; Value = $labels[$k] }
    }
  } else {
    $props = $labels.PSObject.Properties
  }

  foreach ($p in $props) {
    if ($p.Name -like 'io.allsagetech.toolchain.env.*') {
      $name = $p.Name.Substring('io.allsagetech.toolchain.env.'.Length)
      $val  = ([string]$p.Value).Replace('${.}', $RootPath)
      $envMap[$name] = $val
    } elseif ($p.Name -like 'toolchain.env.*') {
      $name = $p.Name.Substring('toolchain.env.'.Length)
      $val  = ([string]$p.Value).Replace('${.}', $RootPath)
      $envMap[$name] = $val
    }
  }

  if ($envMap.Count -gt 0) {
    $def = @{ env = $envMap }
    Assert-ToolchainDefinition -Definition $def -Context "labels($Ref)"
    return $def
  }

  return $null
}

function GetBlob {
	param (
		[Parameter(Mandatory)]
		[string]$Ref,
		[long]$StartByte
	)
	$Ref = $Ref | ConvertTo-CanonicalSha256Digest
	if ($StartByte -lt 0) { throw 'blob range start cannot be negative' }
	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		$blobName = "$($Ref.Substring('sha256:'.Length)).tar.gz"
		$repoFull = [IO.Path]::GetFullPath($repoPath).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
		$repoPrefix = $repoFull + [IO.Path]::DirectorySeparatorChar
		$files = @(
			foreach ($candidate in @(Get-ChildItem -LiteralPath $repoPath -Recurse -File -Filter $blobName -ErrorAction SilentlyContinue)) {
				$candidateFull = [IO.Path]::GetFullPath($candidate.FullName)
				if (-not $candidateFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
				$relative = $candidateFull.Substring($repoPrefix.Length)
				try {
					$safePath = Resolve-ToolchainChildPath -Root $repoFull -RelativePath $relative -RejectReparsePoints
					if ($safePath -eq $candidateFull) { $candidate }
				} catch {
					Write-Debug "Skipping unsafe offline blob candidate '$candidateFull': $($_.Exception.Message)"
				}
			}
		)
		$file = $files | Select-Object -First 1
		if (-not $file -or -not $file.Exists -or $file.Length -le $StartByte) {
			return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::NotFound)
		}
		$fs = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
		$fs.Seek($StartByte, [IO.SeekOrigin]::Begin) | Out-Null
		$status = if ($StartByte -gt 0) { [Net.HttpStatusCode]::PartialContent } else { [Net.HttpStatusCode]::OK }
		$response = [Net.Http.HttpResponseMessage]::new($status)
		$response.Headers.Add('Docker-Content-Digest', "sha256:$((Get-FileHash $file.FullName).Hash.ToLower())")
		$response.Content = [Net.Http.StreamContent]::new($fs)
		$response.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/octet-stream')
		$response.Content.Headers.ContentRange = [Net.Http.Headers.ContentRangeHeaderValue]::new($StartByte, $file.Length - 1, $file.Length)
		return $response
	}
	Assert-ToolchainRegistryPolicyAllowed -Action 'fetch blob' -RegistryBaseUrl (GetRegistryBaseUrl) -Repository (GetRegistryRepoName)

	$api = "/v2/$(GetRegistryRepoName)/blobs/$Ref"
	$url = GetRegistryUrl $api
	return InvokeRegistryBaseRequest -Url $url -Accept 'application/octet-stream' -Range "bytes=$StartByte-$($StartByte + 536870911)"
}

function GetDigestForRef {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref
	)
	$resp = $Ref | GetManifest -Method HEAD
	try {
		return ($resp | GetDigest)
	} finally {
		if ($resp) { $resp.Dispose() }
	}
}

function GetDigest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)
	$digest = Get-ToolchainResponseDigestHeader -Response $Resp
	if (-not $digest) { throw 'Missing Docker-Content-Digest header in registry response.' }
	return $digest
}


function DebugRateLimit {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)
	if ($resp.Headers.Contains('ratelimit-limit')) {
		Write-Debug "Registry RateLimit = $($resp.Headers.GetValues('ratelimit-limit'))"
	}
	if ($resp.Headers.Contains('ratelimit-remaining')) {
		Write-Debug "Registry Remaining = $($resp.Headers.GetValues('ratelimit-remaining'))"
	}
}

function GetPackageLayers {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)

	$manifest = $Resp | GetJsonResponse
	$choice = ResolveManifestToSinglePlatform -Manifest $manifest

	$layerResp = $null
	if ($choice.digest) {
		$maxManifestBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_MANIFEST_BYTES' -Default 16777216
		$descriptor = Assert-ToolchainDescriptor -Descriptor $choice -Context 'platform manifest descriptor' -MaximumSize $maxManifestBytes
		$layerResp = GetVerifiedManifestResponse -Ref $descriptor.Digest -ExpectedDigest $descriptor.Digest -ExpectedSize $descriptor.Size
		try {
			$manifest = $layerResp | GetJsonResponse
		} finally {
			$layerResp.Dispose()
		}
	}

	$layers = $manifest.layers
	if (-not $layers) { throw 'resolved image manifest does not contain layers' }
	$packageLayers = [System.Collections.Generic.List[PSObject]]::new()
	$maxLayerBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_LAYER_BYTES' -Default 8589934592
	$maxPackageBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_PACKAGE_BYTES' -Default 17179869184
	$totalPackageBytes = 0L
	for ($i = 0; $i -lt $layers.Length; $i++) {
		$mt = $layers[$i].mediaType
		$isLayer = ($mt -eq 'application/vnd.docker.image.rootfs.diff.tar.gzip') -or ($mt -eq 'application/vnd.oci.image.layer.v1.tar+gzip')
		if ($isLayer) {
			$descriptor = Assert-ToolchainDescriptor -Descriptor $layers[$i] -Context "layer descriptor $i" -MaximumSize $maxLayerBytes
			$totalPackageBytes += $descriptor.Size
			if ($totalPackageBytes -gt $maxPackageBytes) {
				throw "package layers exceed TOOLCHAIN_MAX_PACKAGE_BYTES ($maxPackageBytes bytes)"
			}
			$packageLayers.Add($descriptor)
		}
	}
	return $packageLayers
}

function GetSize {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)
	$layers = $Resp | GetPackageLayers
	$size = 0
	foreach ($layer in $layers) {
		$size += $layer.size
	}
	return $size
}

function SaveBlob {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Digest,
		[String]$Output,
		[Nullable[long]]$ExpectedSize
	)
	$Digest = $Digest | ConvertTo-CanonicalSha256Digest
	$sha256 = $Digest.Substring('sha256:'.Length)
	$maxLayerBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_LAYER_BYTES' -Default 8589934592
	if ($null -ne $ExpectedSize -and ([long]$ExpectedSize -lt 0 -or [long]$ExpectedSize -gt $maxLayerBytes)) {
		throw "blob size $([long]$ExpectedSize) exceeds limit of $maxLayerBytes bytes"
	}
	$basePath = if ($Output) { (Resolve-Path $Output).Path } else { GetPwrTempPath }
	$path = Join-Path $basePath "$sha256.tar.gz"
	if (Test-Path -LiteralPath $path) {
		$existing = Get-Item -LiteralPath $path
		if ($existing.Length -le $maxLayerBytes -and
			($null -eq $ExpectedSize -or $existing.Length -eq [long]$ExpectedSize) -and
			(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ieq $sha256) {
			return $path
		}
	}
	MakeDirIfNotExist (Split-Path $path) | Out-Null
	$fs = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
	if ($fs.Length -gt $maxLayerBytes -or ($null -ne $ExpectedSize -and $fs.Length -ge [long]$ExpectedSize)) {
		$fs.SetLength(0)
	}
	$fs.Seek(0, [IO.SeekOrigin]::End) | Out-Null
	$totalSize = if ($null -ne $ExpectedSize) { [long]$ExpectedSize } else { $null }
	$maxSegments = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_BLOB_SEGMENTS' -Default 1024
	$segments = 0L
	try {
		do {
			$segments += 1
			if ($segments -gt $maxSegments) { throw "blob download exceeded TOOLCHAIN_MAX_BLOB_SEGMENTS ($maxSegments requests)" }
			$startByte = $fs.Length
			$resp = GetBlob -Ref $Digest -StartByte $startByte
			try {
				if (-not $resp.IsSuccessStatusCode) {
					throw "cannot download blob $($Digest): $($resp.ReasonPhrase)"
				}
				if ($startByte -gt 0 -and $resp.StatusCode -ne [Net.HttpStatusCode]::PartialContent) {
					$fs.SetLength(0)
					continue
				}

				$contentRange = $resp.Content.Headers.ContentRange
				if ($contentRange) {
					if (-not $contentRange.HasRange -or $contentRange.From -ne $startByte) {
						throw "invalid Content-Range for blob ${Digest}: $contentRange"
					}
					if ($contentRange.HasLength) {
						if ($null -ne $totalSize -and $totalSize -ne $contentRange.Length) {
							throw "blob size mismatch: descriptor $totalSize, response $($contentRange.Length)"
						}
						$totalSize = [long]$contentRange.Length
					}
				}
				if ($null -eq $totalSize) {
					if ($null -eq $resp.Content.Headers.ContentLength) { throw 'blob response did not include a total size' }
					$totalSize = $startByte + [long]$resp.Content.Headers.ContentLength
				}
				if ($totalSize -gt $maxLayerBytes) { throw "blob exceeds limit of $maxLayerBytes bytes" }
				if ($startByte -gt $totalSize) { throw "blob range starts beyond expected size $totalSize" }

				$stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
				$buffer = New-Object byte[] 65536
				try {
					while ($true) {
						$read = $stream.Read($buffer, 0, $buffer.Length)
						if ($read -eq 0) { break }
						if (($fs.Length + $read) -gt $totalSize -or ($fs.Length + $read) -gt $maxLayerBytes) {
							throw "blob response exceeded expected size $totalSize"
						}
						$fs.Write($buffer, 0, $read)
						$sha256.Substring(0, 12) + ': Downloading ' + (GetProgress -Current $fs.Length -Total $totalSize) + '  ' | WriteConsole
					}
				} finally {
					$stream.Dispose()
				}
				if ($fs.Length -eq $startByte -and $fs.Length -lt $totalSize) {
					throw "blob download made no progress at byte $startByte"
				}
			} finally {
				$resp.Dispose()
			}
		} while ($fs.Length -lt $totalSize)
		if ($fs.Length -ne $totalSize) { throw "blob size mismatch: expected $totalSize, got $($fs.Length)" }
		$sha256.Substring(0, 12) + ': Downloading ' + (GetProgress -Current $fs.Length -Total $totalSize) + '  ' | WriteConsole
	} finally {
		$fs.Close()
	}
	$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
	if ($actual -ne $sha256) {
		[IO.File]::Delete($path)
		throw "blob digest mismatch: expected sha256:$sha256, got sha256:$actual"
	}
	return $path
}
