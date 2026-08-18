<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\registry-credentials.ps1

function GetRegistryBaseUrl {
	if ($env:TOOLCHAIN_REGISTRY) { return $env:TOOLCHAIN_REGISTRY.Trim().TrimEnd('/') }
	return 'https://registry-1.docker.io'
}

function GetRegistryIndexUrl {
	if ($env:TOOLCHAIN_INDEX_REGISTRY) { return $env:TOOLCHAIN_INDEX_REGISTRY.Trim().TrimEnd('/') }
	return GetRegistryBaseUrl
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

function Test-DockerHubRegistryUrl {
	param(
		[Parameter(Mandatory)][string]$Url
	)

	try {
		$hostName = ([Uri]::new($Url)).Host
		return $hostName -in @('index.docker.io', 'registry-1.docker.io')
	} catch {
		return $false
	}
}

function GetRegistryPlatformOs {
	if ($env:TOOLCHAIN_OS) { return $env:TOOLCHAIN_OS }
	if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { return 'windows' }
	if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)) { return 'linux' }
	if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::OSX)) { return 'darwin' }
	throw 'could not determine the current operating-system platform; set TOOLCHAIN_OS explicitly'
}

function ConvertTo-ToolchainRuntimeArchitecture {
	param(
		[AllowNull()]$Architecture
	)
	$text = [string]$Architecture
	if ([string]::IsNullOrWhiteSpace($text)) { return $null }
	switch -Regex ($text.Trim()) {
		'^(X64|AMD64|X86_64)$' { return 'amd64' }
		'^(ARM64|AARCH64)$' { return 'arm64' }
		'^(X86|I[3-6]86)$' { return '386' }
		'^(ARM|ARMV[5-8].*)$' { return 'arm' }
	}
	return $null
}

function Get-ToolchainRuntimeArchitecture {
	$candidates = @()
	try {
		# Older Windows PowerShell/.NET combinations can expose this property as
		# null. Never invoke instance methods on it; use native environment values
		# as the compatibility fallback.
		$candidates += [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
	} catch {
		Write-Debug "RuntimeInformation architecture detection failed: $($_.Exception.Message)"
	}
	$candidates += @(
		[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432', [EnvironmentVariableTarget]::Process),
		[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', [EnvironmentVariableTarget]::Process)
	)

	foreach ($candidate in $candidates) {
		$resolved = ConvertTo-ToolchainRuntimeArchitecture -Architecture $candidate
		if ($resolved) { return $resolved }
	}

	$uname = Get-Command 'uname' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
	if ($uname -and $uname.Source) {
		try {
			$nativeArchitecture = & $uname.Source '-m' 2>$null | Select-Object -First 1
			$resolved = ConvertTo-ToolchainRuntimeArchitecture -Architecture $nativeArchitecture
			if ($resolved) { return $resolved }
		} catch {
			Write-Debug "uname architecture detection failed: $($_.Exception.Message)"
		}
	}

	throw 'could not determine the current processor architecture'
}

function GetRegistryPlatformArch {
	if ($env:TOOLCHAIN_ARCH) { return $env:TOOLCHAIN_ARCH }
	return Get-ToolchainRuntimeArchitecture
}

function ConvertTo-CanonicalSha256Digest {
	param([Parameter(Mandatory, ValueFromPipeline)][string]$Digest)
	if ($Digest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
		throw "invalid sha256 digest: $Digest"
	}
	return 'sha256:' + $Matches[1].ToLowerInvariant()
}

function Get-ToolchainBytesSha256Digest {
	param([Parameter(Mandatory)][byte[]]$Bytes)
	$sha = [Security.Cryptography.SHA256]::Create()
	try {
		$hash = $sha.ComputeHash($Bytes)
	} finally {
		$sha.Dispose()
	}
	return 'sha256:' + [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
}

function Read-ToolchainBoundedResponseBytes {
	param(
		[Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Response,
		[Parameter(Mandatory)][long]$MaximumBytes,
		[Nullable[long]]$ExpectedSize,
		[string]$Context = 'response body'
	)
	if (-not $Response.Content) { throw "$Context is missing" }
	if ($Response.Content.Headers.ContentLength -and $Response.Content.Headers.ContentLength -gt $MaximumBytes) {
		throw "$Context exceeds limit of $MaximumBytes bytes"
	}

	$inputStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
	$output = [IO.MemoryStream]::new()
	$buffer = New-Object byte[] 65536
	try {
		while ($true) {
			$read = $inputStream.Read($buffer, 0, $buffer.Length)
			if ($read -eq 0) { break }
			if (($output.Length + $read) -gt $MaximumBytes) {
				throw "$Context exceeds limit of $MaximumBytes bytes"
			}
			$output.Write($buffer, 0, $read)
		}
		if ($null -ne $ExpectedSize -and $output.Length -ne [long]$ExpectedSize) {
			throw "$Context size mismatch: expected $([long]$ExpectedSize), got $($output.Length)"
		}
		return $output.ToArray()
	} finally {
		$output.Dispose()
		$inputStream.Dispose()
	}
}

function Get-ToolchainResponseDigestHeader {
	param([Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Response)
	$values = $null
	if (-not $Response.Headers.TryGetValues('Docker-Content-Digest', [ref]$values)) {
		return $null
	}
	$all = @($values)
	if ($all.Count -ne 1) { throw 'registry returned multiple Docker-Content-Digest headers' }
	return ([string]$all[0] | ConvertTo-CanonicalSha256Digest)
}

function Set-ToolchainBufferedResponseContent {
	param(
		[Parameter(Mandatory)][Net.Http.HttpResponseMessage]$Response,
		[Parameter(Mandatory)][byte[]]$Bytes
	)
	$mediaType = $null
	if ($Response.Content -and $Response.Content.Headers.ContentType) {
		$mediaType = $Response.Content.Headers.ContentType.MediaType
	}
	if ($Response.Content) { $Response.Content.Dispose() }
	$Response.Content = [Net.Http.ByteArrayContent]::new($Bytes)
	if ($mediaType) {
		$Response.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new($mediaType)
	}
}

function Assert-ToolchainDescriptor {
	param(
		[Parameter(Mandatory)][object]$Descriptor,
		[Parameter(Mandatory)][string]$Context,
		[Parameter(Mandatory)][long]$MaximumSize
	)
	if (-not $Descriptor.digest) { throw "$Context is missing digest" }
	$digest = [string]$Descriptor.digest | ConvertTo-CanonicalSha256Digest
	$size = 0L
	if ($null -eq $Descriptor.size -or -not [long]::TryParse([string]$Descriptor.size, [ref]$size) -or $size -lt 0) {
		throw "$Context has invalid size '$($Descriptor.size)'"
	}
	if ($size -gt $MaximumSize) { throw "$Context exceeds size limit of $MaximumSize bytes" }
	return [PSCustomObject]@{ Digest = $digest; Size = $size; MediaType = [string]$Descriptor.mediaType }
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

function GetDockerHubBearerAuthHeader {
	param(
		[Parameter(Mandatory)][string]$Repo,
		[Parameter(Mandatory)][string]$RegistryUrl
	)

	$cacheKey = "$RegistryUrl|$Repo"
	if ($script:RegistryAuthHeaderCache.ContainsKey($cacheKey)) {
		return $script:RegistryAuthHeaderCache[$cacheKey]
	}

	if ($env:TOOLCHAIN_TOKEN) {
		$hdr = "Bearer $($env:TOOLCHAIN_TOKEN)"
		$script:RegistryAuthHeaderCache[$cacheKey] = $hdr
		return $hdr
	}
	$credential = Get-ToolchainRegistryCredential -RegistryUrl $RegistryUrl
	if ($credential -and $credential.IdentityToken) {
		$hdr = "Bearer $($credential.IdentityToken)"
		$script:RegistryAuthHeaderCache[$cacheKey] = $hdr
		return $hdr
	}

	$token = GetBearerTokenFromRealm `
		-Realm 'https://auth.docker.io/token' `
		-Service 'registry.docker.io' `
		-Scope "repository:${Repo}:pull" `
		-Username $(if ($credential) { $credential.Username } else { $null }) `
		-Pass $(if ($credential) { $credential.Secret } else { $null })
	$hdr = "Bearer $token"
	$script:RegistryAuthHeaderCache[$cacheKey] = $hdr
	return $hdr
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

	$credential = Get-ToolchainRegistryCredential -RegistryUrl $reg
	$user = if ($credential) { [string]$credential.Username } else { $null }
	$pass = if ($credential) { [string]$credential.Secret } else { $null }
	if ($credential -and $credential.IdentityToken) {
		$hdr = "Bearer $($credential.IdentityToken)"
		$script:RegistryAuthHeaderCache[$cacheKey] = $hdr
		return $hdr
	}

  $raw = $WwwAuthenticate.ToString()
  $scheme = $WwwAuthenticate.Scheme

  if ($scheme -ieq 'Basic') {
    if (-not ($user -and $pass)) {
		throw 'Registry requires Basic auth. Set Toolchain credentials or configure a Docker/Podman credential helper.'
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
    if (-not $scope) { $scope = "repository:${Repo}:pull" }

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

	$credential = Get-ToolchainRegistryCredential -RegistryUrl $reg
	$user = if ($credential) { [string]$credential.Username } else { $null }
	$pass = if ($credential) { [string]$credential.Secret } else { $null }
	if ($credential -and $credential.IdentityToken) {
		$hdr = "Bearer $($credential.IdentityToken)"
		$script:RegistryAuthHeaderCache[$cacheKey] = $hdr
		return $hdr
	}

  $raw = $WwwAuthenticate.ToString()
  $scheme = $WwwAuthenticate.Scheme

  if ($scheme -ieq 'Basic') {
    if (-not ($user -and $pass)) {
		throw 'Registry requires Basic auth. Set Toolchain credentials or configure a Docker/Podman credential helper.'
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
    if (-not $scope) { $scope = "repository:${Repo}:pull" }

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
		} elseif (Test-DockerHubRegistryUrl -Url (GetRegistryIndexUrl)) {
			$authHeader = GetDockerHubBearerAuthHeader -Repo $repo -RegistryUrl (GetRegistryIndexUrl)
		}

					$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req

		if ($resp.StatusCode -eq [Net.HttpStatusCode]::Unauthorized -and $resp.Headers.WwwAuthenticate) {
			$challenge = $resp.Headers.WwwAuthenticate | Select-Object -First 1
			$resp.Dispose()
			$null = $script:RegistryAuthHeaderCache.Remove($cacheKey)
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
		} elseif (Test-DockerHubRegistryUrl -Url (GetRegistryBaseUrl)) {
			$authHeader = GetDockerHubBearerAuthHeader -Repo $repo -RegistryUrl (GetRegistryBaseUrl)
		}

					$reqParams = @{ URL = $Url; Method = $Method; Accept = $Accept; AuthHeader = $authHeader }
			if ($Range) { $reqParams.Range = $Range }
			$req = HttpRequest @reqParams
			$resp = HttpSend -Req $req

		if ($resp.StatusCode -eq [Net.HttpStatusCode]::Unauthorized -and $resp.Headers.WwwAuthenticate) {
			$challenge = $resp.Headers.WwwAuthenticate | Select-Object -First 1
			$resp.Dispose()
			$null = $script:RegistryAuthHeaderCache.Remove($cacheKey)
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
