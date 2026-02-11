<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

Add-Type -AssemblyName System.Net.Http

function HttpRequest {
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param (
		[Parameter(Mandatory)]
		[string]$URL,
		[ValidateSet('GET', 'HEAD')]
		[string]$Method = 'GET',
		[string]$AuthHeader,
		[hashtable]$Headers = @{},
		[string]$Accept,
		[Parameter(ParameterSetName = 'RangeHeader')]
		[string]$Range,
		[Parameter(ParameterSetName = 'RangeParts')]
		[long]$RangeFrom,
		[Parameter(ParameterSetName = 'RangeParts')]
		[Nullable[long]]$RangeTo
	)
	Write-Debug "HttpRequest URL=[$URL]"
	$uri = [Uri]::new([string]$URL, [UriKind]::Absolute)
	$req = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $uri)

	if ($AuthHeader) {
		if ($AuthHeader -match '^([^\s]+)\s+(.+)$') {
			$req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new($Matches[1], $Matches[2])
		} else {
			$req.Headers.TryAddWithoutValidation('Authorization', $AuthHeader) | Out-Null
		}
	}
	if ($Headers) {
		foreach ($k in $Headers.Keys) {
			$req.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k]) | Out-Null
		}
	}
	if ($Accept) {
		foreach ($a in $Accept -split '\s*,\s*') {
			if ($a) { $req.Headers.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::Parse($a)) }
		}
	}
	if ($PSCmdlet.ParameterSetName -eq 'RangeParts') {
		$rangeHeader = [System.Net.Http.Headers.RangeHeaderValue]::new()
		$rangeHeader.Unit = 'bytes'
		$rangeHeader.Ranges.Add([System.Net.Http.Headers.RangeItemHeaderValue]::new($RangeFrom, $RangeTo))
		$req.Headers.Range = $rangeHeader
	} elseif ($Range) {
		$req.Headers.TryAddWithoutValidation('Range', $Range) | Out-Null
	}
	return $req
}

function Get-ToolchainHttpClient {
	param(
		[switch]$NoRedirect
	)

	$timeoutSeconds = $null
	if ($env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS) {
		$tmp = 0
		if (-not [int]::TryParse([string]$env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS, [ref]$tmp) -or $tmp -le 0) {
			throw "Invalid TOOLCHAIN_HTTP_TIMEOUT_SECONDS='$($env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS)'"
		}
		$timeoutSeconds = $tmp
	}
	if ($NoRedirect) {
		if (-not $script:HttpClientNoRedirect) {
			$handler = [Net.Http.HttpClientHandler]::new()
			if ($env:TOOLCHAIN_TLS_INSECURE -in '1','true','TRUE','yes','YES') {
				$handler.ServerCertificateCustomValidationCallback = { param($cbSender, $cbCert, $cbChain, $cbErrors) $null = $cbSender; $null = $cbCert; $null = $cbChain; $null = $cbErrors; return $true }
			}
			$handler.AllowAutoRedirect = $false
			if ($env:TOOLCHAIN_HTTP_DISABLE_PROXY -in '1','true','TRUE','yes','YES') {
				$handler.UseProxy = $false
				} elseif ($env:TOOLCHAIN_PROXY) {
					$proxy = [System.Net.WebProxy]::new([string]$env:TOOLCHAIN_PROXY)
					if ($env:TOOLCHAIN_PROXY_USERNAME) {
						$proxy.Credentials = [System.Net.NetworkCredential]::new([string]$env:TOOLCHAIN_PROXY_USERNAME, [string]$env:TOOLCHAIN_PROXY_PASSWORD)
					}
					$handler.Proxy = $proxy
					$handler.UseProxy = $true
			}
				$script:HttpClientNoRedirect = [Net.Http.HttpClient]::new($handler)
				if ($timeoutSeconds) {
					$script:HttpClientNoRedirect.Timeout = [TimeSpan]::FromSeconds($timeoutSeconds)
				}
		}
		return $script:HttpClientNoRedirect
	}

	if (-not $script:HttpClient) {
		$handler = [Net.Http.HttpClientHandler]::new()
		if ($env:TOOLCHAIN_TLS_INSECURE -in '1','true','TRUE','yes','YES') {
			$handler.ServerCertificateCustomValidationCallback = { param($cbSender, $cbCert, $cbChain, $cbErrors) $null = $cbSender; $null = $cbCert; $null = $cbChain; $null = $cbErrors; return $true }
		}
		if ($env:TOOLCHAIN_HTTP_DISABLE_PROXY -in '1','true','TRUE','yes','YES') {
			$handler.UseProxy = $false
			} elseif ($env:TOOLCHAIN_PROXY) {
				$proxy = [System.Net.WebProxy]::new([string]$env:TOOLCHAIN_PROXY)
				if ($env:TOOLCHAIN_PROXY_USERNAME) {
					$proxy.Credentials = [System.Net.NetworkCredential]::new([string]$env:TOOLCHAIN_PROXY_USERNAME, [string]$env:TOOLCHAIN_PROXY_PASSWORD)
				}
				$handler.Proxy = $proxy
				$handler.UseProxy = $true
		}
			$script:HttpClient = [Net.Http.HttpClient]::new($handler)
			if ($timeoutSeconds) {
				$script:HttpClient.Timeout = [TimeSpan]::FromSeconds($timeoutSeconds)
			}
	}
	return $script:HttpClient
}

function HttpSend {
	param(
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpRequestMessage]$Req,
		[switch]$NoRedirect
	)
	$cli = Get-ToolchainHttpClient -NoRedirect:$NoRedirect
	try {
		return $cli.SendAsync($Req, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
	} catch {
		$url = if ($Req -and $Req.RequestUri) { $Req.RequestUri.AbsoluteUri } else { '<unknown url>' }
		throw "failed to download $($url): $_"
	}
}


function GetJsonResponse {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp
	)
	if (($resp.Content.Headers.ContentType.MediaType -ne 'application/json') -and -not $resp.Content.Headers.ContentType.MediaType.EndsWith('+json')) {
		throw "want application/json, got $($resp.Content.Headers.ContentType.MediaType)"
	}
	return $Resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
}
