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

function GetRegistryBaseUrl {
	if ($env:TOOLCHAIN_REGISTRY) { return $env:TOOLCHAIN_REGISTRY.Trim().TrimEnd('/') }
	return 'https://registry-1.docker.io'
}

function GetRegistryIndexUrl {
	if ($env:TOOLCHAIN_INDEX_REGISTRY) { return $env:TOOLCHAIN_INDEX_REGISTRY.Trim().TrimEnd('/') }
	return 'https://index.docker.io'
}

function GetRegistryRepoName {
	if ($env:TOOLCHAIN_REPOSITORY) { return $env:TOOLCHAIN_REPOSITORY }
	return 'allsagetech/toolchains'
}

function GetRegistryUrl([string]$Path) {
  $base = [Uri]::new((GetRegistryBaseUrl).Trim().TrimEnd('/') + "/")
  if (-not $Path.StartsWith("/")) { $Path = "/" + $Path }
  return ([Uri]::new($base, $Path)).AbsoluteUri
}

function GetRegistryPlatformOs {
	if ($env:TOOLCHAIN_OS) { return $env:TOOLCHAIN_OS }
	return 'windows'
}

function GetRegistryPlatformArch {
	if ($env:TOOLCHAIN_ARCH) { return $env:TOOLCHAIN_ARCH }
	return 'amd64'
}

$script:RegistryAuthHeaderCache = @{}

function GetBasicAuthHeader {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Registry auth may be supplied via environment variables; using explicit params keeps the internal API simple.')]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Pass', Justification = 'Registry passwords can be provided as plain strings (e.g., env vars) and are only used to build an Authorization header in-memory.')]
	param(
		[Parameter(Mandatory)][string]$Username,
		[Parameter(Mandatory)][string]$Pass
	)
	$bytes = [Text.Encoding]::UTF8.GetBytes("$Username`:$Pass")
	$b64 = [Convert]::ToBase64String($bytes)
	return "Basic $b64"
}

function ParseAuthHeaderParams {
	param([Parameter(Mandatory)][string]$HeaderValue)
	$kv = @{}
	$parts = $HeaderValue.Split(' ', 2)
	if ($parts.Length -lt 2) { return $kv }
	$rest = $parts[1]
	foreach ($m in [regex]::Matches($rest, '(\w+)=("([^"\\]|\\.)*"|[^,]+)')) {
		$key = $m.Groups[1].Value
		$val = $m.Groups[2].Value.Trim()
		if ($val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Substring(1, $val.Length-2) }
		$kv[$key] = $val
	}
	return $kv
}

function Get-RegistryRetryDelaySeconds {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'The return value is expressed in seconds (an integer). Keeping this name aligns with HTTP Retry-After semantics used by callers.')]
  param(
    [Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Response,
    [int]$DefaultSeconds
  )
  $delay = $DefaultSeconds
  try {
    if ($Response.Headers.RetryAfter) {
      if ($Response.Headers.RetryAfter.Delta) {
        $sec = [int][math]::Ceiling($Response.Headers.RetryAfter.Delta.TotalSeconds)
        if ($sec -gt 0) { $delay = [math]::Max($delay, $sec) }
      } elseif ($Response.Headers.RetryAfter.Date) {
        $sec = [int][math]::Ceiling(($Response.Headers.RetryAfter.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds)
        if ($sec -gt 0) { $delay = [math]::Max($delay, $sec) }
      }
    }
  } catch {
    Write-Verbose "Failed to parse Retry-After header: $($_.Exception.Message)"
  }
  return $delay
}

function GetBearerTokenFromRealm {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Registry auth may be supplied via environment variables; using explicit params keeps the internal API simple.')]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Pass', Justification = 'Registry passwords can be provided as plain strings (e.g., env vars) and are only used to request a bearer token over HTTPS.')]
  param(
    [Parameter(Mandatory)][string]$Realm,
    [string]$Service,
    [string]$Scope,
    [string]$Username,
    [string]$Pass
  )

  $q = @()
  if ($Service) { $q += "service=$([uri]::EscapeDataString($Service))" }
  if ($Scope)   { $q += "scope=$([uri]::EscapeDataString($Scope))" }

  $tokenUrl = if ($q.Count -gt 0) { "${Realm}?$(($q -join '&'))" } else { $Realm }

  if (-not ([Uri]::IsWellFormedUriString($tokenUrl, [UriKind]::Absolute))) {
    throw "Token URL is not absolute: [$tokenUrl] (realm=[$Realm])"
  }

  $headers = @{}
  if ($env:TOOLCHAIN_TOKEN) {
    $headers['Authorization'] = "Bearer $($env:TOOLCHAIN_TOKEN)"
  } elseif ($Username -and $Pass) {
    $headers['Authorization'] = (GetBasicAuthHeader -Username $Username -Pass $Pass)
  }

  $req = HttpRequest -URL $tokenUrl -Headers $headers
  $resp = HttpSend -Req $req
  try {
    $payload = $resp | GetJsonResponse
    $tok = $payload.token
    if (-not $tok) { $tok = $payload.access_token }
    if (-not $tok) { throw "token response did not include 'token' or 'access_token'" }
    return $tok
  } finally {
    $resp.Dispose()
  }
}

function GetRegistryBaseAuthHeader {
  param(
    [Parameter(Mandatory)][string]$Repo,
    [Net.Http.Headers.AuthenticationHeaderValue]$WwwAuthenticate
  )

  $reg = (GetRegistryBaseUrl)
  $cacheKey = "$reg|$Repo"
  if ($script:RegistryAuthHeaderCache.ContainsKey($cacheKey)) {
    return $script:RegistryAuthHeaderCache[$cacheKey]
  }

  if ($env:TOOLCHAIN_TOKEN) {
    $hdr = "Bearer $($env:TOOLCHAIN_TOKEN)"
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  $user = $env:TOOLCHAIN_USERNAME
  $pass = $env:TOOLCHAIN_PASSWORD

  $raw = $WwwAuthenticate.ToString()
  $scheme = $WwwAuthenticate.Scheme

  if ($scheme -ieq 'Basic') {
    if (-not ($user -and $pass)) {
      throw "Registry requires Basic auth. Set TOOLCHAIN_USERNAME and TOOLCHAIN_PASSWORD."
    }
    $hdr = GetBasicAuthHeader -Username $user -Pass $pass
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  if ($scheme -ieq 'Bearer') {
    $params = ParseAuthHeaderParams $raw
    $realm = $params['realm']
    if (-not $realm) { throw "Bearer auth challenge missing realm. Raw: $raw" }

    $service = $params['service']
    $scope = $params['scope']
    if (-not $scope) { $scope = "repository:$Repo:pull" }

    $token = GetBearerTokenFromRealm -Realm $realm -Service $service -Scope $scope -Username $user -Pass $pass
    $hdr = "Bearer $token"
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  throw "Unsupported WWW-Authenticate scheme: $scheme (raw=[$raw])"
}

function GetRegistryIndexAuthHeader {
  param(
    [Parameter(Mandatory)][string]$Repo,
    [Net.Http.Headers.AuthenticationHeaderValue]$WwwAuthenticate
  )

  $reg = (GetRegistryIndexUrl)
  $cacheKey = "$reg|$Repo"
  if ($script:RegistryAuthHeaderCache.ContainsKey($cacheKey)) {
    return $script:RegistryAuthHeaderCache[$cacheKey]
  }

  if ($env:TOOLCHAIN_TOKEN) {
    $hdr = "Bearer $($env:TOOLCHAIN_TOKEN)"
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  $user = $env:TOOLCHAIN_USERNAME
  $pass = $env:TOOLCHAIN_PASSWORD

  $raw = $WwwAuthenticate.ToString()
  $scheme = $WwwAuthenticate.Scheme

  if ($scheme -ieq 'Basic') {
    if (-not ($user -and $pass)) {
      throw "Registry requires Basic auth. Set TOOLCHAIN_USERNAME and TOOLCHAIN_PASSWORD."
    }
    $hdr = GetBasicAuthHeader -Username $user -Pass $pass
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  if ($scheme -ieq 'Bearer') {
    $params = ParseAuthHeaderParams $raw
    $realm = $params['realm']
    if (-not $realm) { throw "Bearer auth challenge missing realm. Raw: $raw" }

    $service = $params['service']
    $scope = $params['scope']
    if (-not $scope) { $scope = "repository:$Repo:pull" }

    $token = GetBearerTokenFromRealm -Realm $realm -Service $service -Scope $scope -Username $user -Pass $pass
    $hdr = "Bearer $token"
    $script:RegistryAuthHeaderCache[$cacheKey] = $hdr
    return $hdr
  }

  throw "Unsupported WWW-Authenticate scheme: $scheme (raw=[$raw])"
}

function InvokeIndexRegistryRequest {
	param(
		[Parameter(Mandatory)][string]$Url,
		[ValidateSet('GET','HEAD')][string]$Method='GET',
		[string]$Accept,
		[string]$Range
	)

	$repo = GetRegistryRepoName
	$cacheKey = "$(GetRegistryIndexUrl)|$repo"

	for ($attempt = 1; $attempt -le 6; $attempt++) {
		$authHeader = $null
		if ($script:RegistryAuthHeaderCache.ContainsKey($cacheKey)) {
			$authHeader = $script:RegistryAuthHeaderCache[$cacheKey]
		}

					$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req

		if ($resp.StatusCode -eq [Net.HttpStatusCode]::Unauthorized -and $resp.Headers.WwwAuthenticate) {
			$challenge = $resp.Headers.WwwAuthenticate | Select-Object -First 1
			$resp.Dispose()
			$authHeader = GetRegistryIndexAuthHeader -Repo $repo -WwwAuthenticate $challenge
			$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req
		}

		$code = [int]$resp.StatusCode
		if ($attempt -lt 6 -and ($code -eq 408 -or $code -eq 429 -or ($code -ge 500 -and $code -le 599))) {
			$base = [math]::Min(60, 2 * [math]::Pow(2, ($attempt - 1)))
			$delay = Get-RegistryRetryDelaySeconds -Response $resp -DefaultSeconds $base
			Write-ToolchainInfo "Registry request retry ($attempt/6) in $delay sec: $Url ($code)"
			$resp.Dispose()
			Start-Sleep -Seconds $delay
			continue
		}

		return $resp
	}
}

function InvokeRegistryBaseRequest {
	param(
		[Parameter(Mandatory)][string]$Url,
		[ValidateSet('GET','HEAD')][string]$Method='GET',
		[string]$Accept,
		[string]$Range
	)

	$repo = GetRegistryRepoName
	$cacheKey = "$(GetRegistryBaseUrl)|$repo"

	for ($attempt = 1; $attempt -le 6; $attempt++) {
		$authHeader = $null
		if ($script:RegistryAuthHeaderCache.ContainsKey($cacheKey)) {
			$authHeader = $script:RegistryAuthHeaderCache[$cacheKey]
		}

					$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req

		if ($resp.StatusCode -eq [Net.HttpStatusCode]::Unauthorized -and $resp.Headers.WwwAuthenticate) {
			$challenge = $resp.Headers.WwwAuthenticate | Select-Object -First 1
			$resp.Dispose()
			$authHeader = GetRegistryBaseAuthHeader -Repo $repo -WwwAuthenticate $challenge
			$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req
		}

		$code = [int]$resp.StatusCode
		if ($attempt -lt 6 -and ($code -eq 408 -or $code -eq 429 -or ($code -ge 500 -and $code -le 599))) {
			$base = [math]::Min(60, 2 * [math]::Pow(2, ($attempt - 1)))
			$delay = Get-RegistryRetryDelaySeconds -Response $resp -DefaultSeconds $base
			Write-ToolchainInfo "Registry request retry ($attempt/6) in $delay sec: $Url ($code)"
			$resp.Dispose()
			Start-Sleep -Seconds $delay
			continue
		}

		return $resp
	}
}

function GetTagsList {
	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		return [PSCustomObject]@{ Name = $repoPath; Tags = (Get-ChildItem $repoPath -Directory -Name) }
	}

	$api = "/v2/$(GetRegistryRepoName)/tags/list"
	$n = 999
	$last = $null
	$allTags = $null
	while ($true) {
		$ub = [UriBuilder]::new((GetRegistryIndexUrl).Trim().TrimEnd('/'))
		$ub.Path = $api.TrimStart('/')
		$ub.Query = "n=$n" + $(if ($last) { "&last=$([uri]::EscapeDataString($last))" } else { "" })

		$endpoint = $ub.Uri.AbsoluteUri
		$currentTags = InvokeIndexRegistryRequest -Url $endpoint -Accept 'application/json' | GetJsonResponse

		if ($allTags) {
			$allTags.tags += $currentTags.tags
		} else {
			$allTags = $currentTags
		}
		if ($currentTags.tags.Length -lt $n) {
			return $allTags
		}
		$last = $currentTags.tags[$currentTags.tags.Length - 1]
	}
}

function GetManifest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref,
		[ValidateSet('GET', 'HEAD')]
		[string]$Method = 'GET'
	)

	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		$file = Get-Item -LiteralPath (Join-Path "$repoPath\$Ref" 'manifest.json') -ErrorAction SilentlyContinue
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
		$candidate = $manifests | Select-Object -First 1
	}
	return $candidate
}

function GetManifestJson {
	param(
		[Parameter(Mandatory)][string]$Ref
	)
	$resp = GetManifest -Ref $Ref -Method GET
	try {
		if (-not $resp.IsSuccessStatusCode) {
			throw "cannot fetch manifest for ${Ref}: $($resp.ReasonPhrase)"
		}
		return $resp | GetJsonResponse
	} finally {
		$resp.Dispose()
	}
}

function GetResolvedManifestResponse {
	param(
		[Parameter(Mandatory)][string]$Ref,
		[ValidateSet('GET','HEAD')][string]$Method='GET'
	)

	if ($Method -eq 'HEAD') {
		return (GetManifest -Ref $Ref -Method HEAD)
	}

	$manifest = GetManifestJson -Ref $Ref
	$choice = ResolveManifestToSinglePlatform -Manifest $manifest

	if ($choice.digest) {
		return (GetManifest -Ref $choice.digest -Method GET)
	}

	return (GetManifest -Ref $Ref -Method GET)
}

function GetJsonFromResponse {
  param([Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Resp)
  $s = $Resp.Content.ReadAsStringAsync().Result
  return ($s | ConvertFrom-Json)
}

function GetResolvedManifestJson {
  param([Parameter(Mandatory)][string]$Ref)

  $resp = GetResolvedManifestResponse -Ref $Ref -Method GET
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
  param([Parameter(Mandatory)][string]$Ref)

  $manifest = GetResolvedManifestJson -Ref $Ref
  if (-not $manifest.config -or -not $manifest.config.digest) {
    return $null
  }

  $cfgDigest = [string]$manifest.config.digest
  $api = "/v2/$(GetRegistryRepoName)/blobs/$cfgDigest"
  $url = GetRegistryUrl $api

  $resp = InvokeRegistryBaseRequest -Url $url -Method GET -Accept 'application/json'
  try {
    if (-not $resp.IsSuccessStatusCode) {
      throw "cannot fetch image config blob ${cfgDigest}: $($resp.ReasonPhrase)"
    }
    return (GetJsonFromResponse -Resp $resp)
  } finally {
    $resp.Dispose()
  }
}

function GetToolchainDefinitionFromLabels {
  param(
    [Parameter(Mandatory)][string]$Ref,
    [Parameter(Mandatory)][string]$RootPath
  )

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
    try { $want = [int]$spec } catch { $want = 0 }
    $supported = 1
    if ($want -gt $supported) {
      throw "package specVersion $want is newer than this Toolchain supports ($supported). Update Toolchain."
    }
  }

  $tlcLabel = $labels.'io.allsagetech.toolchain.tlc'
  if (-not $tlcLabel) { $tlcLabel = $labels.'toolchain.tlc' }

  if ($tlcLabel) {
    $json = [string]$tlcLabel
    $json = $json.Replace('${.}', $RootPath)
    $def = ($json | ConvertFrom-Json | ConvertTo-HashTable)
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
    $tlcFile = Join-Path $RootPath $rel

    if (-not (Test-Path $tlcFile)) {
      throw "toolchain definition file not found at '$tlcFile' (label: $tlcPathLabel)"
    }

    if ($tlcSha256Label) {
      $expected = ([string]$tlcSha256Label).Trim().ToLower()
      $actual   = (Get-FileHash -Algorithm SHA256 -Path $tlcFile).Hash.ToLower()
      if ($actual -ne $expected) {
        throw "toolchain definition sha256 mismatch for '$tlcFile': expected $expected, got $actual"
      }
    }

    $json = (Get-Content -Path $tlcFile -Raw)
    $json = $json.Replace('${.}', $RootPath)
    $def = ($json | ConvertFrom-Json | ConvertTo-HashTable)
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
	$repoPath = (GetToolchainRepo)
	if ($repoPath) {
		$file = Get-ChildItem $repoPath -Depth 1 -Recurse "$($Ref.Substring('sha256:'.Length)).tar.gz"
		if (-not $file -or -not $file.Exists -or $file.Length -le $StartByte) {
			return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::NotFound)
		}
		$fs = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
		$fs.Seek($StartByte, [IO.SeekOrigin]::Begin) | Out-Null
		$response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$response.Headers.Add('Docker-Content-Digest', "sha256:$((Get-FileHash $file.FullName).Hash.ToLower())")
		$response.Content = [Net.Http.StreamContent]::new($fs)
		$response.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/octet-stream')
		$response.Content.Headers.ContentRange = [Net.Http.Headers.ContentRangeHeaderValue]::new($StartByte, $file.Length - 1, $file.Length)
		return $response
	}

	$api = "/v2/$(GetRegistryRepoName)/blobs/$Ref"
	$url = GetRegistryUrl $api
	return InvokeRegistryBaseRequest -Url $url -Accept 'application/octet-stream' -Range "bytes=$StartByte-$($StartByte + 536870911)"
}

function GetDigestForRef {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref
	)
	return $Ref | GetManifest -Method HEAD | GetDigest
}

function GetDigest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)
	$values = $null
	if ($Resp.Headers.TryGetValues('Docker-Content-Digest', [ref]$values)) {
		return $values
	}
	if ($Resp.Headers.TryGetValues('docker-content-digest', [ref]$values)) {
		return $values
	}
	foreach ($k in $Resp.Headers.Keys) {
		if ($k -ieq 'Docker-Content-Digest') {
			[void]$Resp.Headers.TryGetValues($k, [ref]$values)
			return $values
		}
	}
	throw "Missing Docker-Content-Digest header in registry response."
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
		$layerResp = GetManifest -Ref $choice.digest -Method GET
		try {
			$manifest = $layerResp | GetJsonResponse
		} finally {
			$layerResp.Dispose()
		}
	}

	$layers = $manifest.layers
	$packageLayers = [System.Collections.Generic.List[PSObject]]::new()
	for ($i = 0; $i -lt $layers.Length; $i++) {
		$mt = $layers[$i].mediaType
		$isLayer = ($mt -eq 'application/vnd.docker.image.rootfs.diff.tar.gzip') -or ($mt -eq 'application/vnd.oci.image.layer.v1.tar+gzip')
		if ($isLayer) { $packageLayers.Add($layers[$i]) }
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
		[String]$Output
	)
	$sha256 = $Digest.Substring('sha256:'.Length)
	$path = "$(if ($Output) { Resolve-Path $Output } else { GetPwrTempPath })\$sha256.tar.gz"
	if ((Test-Path $path) -and (Get-FileHash $path).Hash -eq $sha256) {
		return $path
	}
	MakeDirIfNotExist (Split-Path $path) | Out-Null
	$fs = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate)
	$fs.Seek(0, [IO.SeekOrigin]::End) | Out-Null
	try {
		do {
			$resp = GetBlob -Ref $Digest -StartByte $fs.Length
			try {
				if (-not $resp.IsSuccessStatusCode) {
					throw "cannot download blob $($Digest): $($resp.ReasonPhrase)"
				}
				$size = if ($resp.Content.Headers.ContentRange.HasLength) { $resp.Content.Headers.ContentRange.Length } else { $resp.Content.Headers.ContentLength + $fs.Length }
				$task = $resp.Content.CopyToAsync($fs)
				while (-not $task.IsCompleted) {
					$sha256.Substring(0, 12) + ': Downloading ' + (GetProgress -Current $fs.Length -Total $size) + '  ' | WriteConsole
					Start-Sleep -Milliseconds 125
				}
			} finally {
				$resp.Dispose()
			}
		} while ($fs.Length -lt $size)
		$sha256.Substring(0, 12) + ': Downloading ' + (GetProgress -Current $fs.Length -Total $size) + '  ' | WriteConsole
	} finally {
		$fs.Close()
	}
	return $path
}