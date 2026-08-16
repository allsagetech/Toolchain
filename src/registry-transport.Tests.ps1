<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. (Join-Path $PSScriptRoot 'registry.ps1')
}

Describe 'Registry transport primitives' {
	BeforeEach {
		$script:oldRegistry = $env:TOOLCHAIN_REGISTRY
		$script:oldIndexRegistry = $env:TOOLCHAIN_INDEX_REGISTRY
		$script:oldRepository = $env:TOOLCHAIN_REPOSITORY
		$script:oldOs = $env:TOOLCHAIN_OS
		$script:oldArch = $env:TOOLCHAIN_ARCH
		$script:oldToken = $env:TOOLCHAIN_TOKEN
		$script:oldUsername = $env:TOOLCHAIN_USERNAME
		$script:oldPassword = $env:TOOLCHAIN_PASSWORD
		Remove-Item Env:TOOLCHAIN_REGISTRY,Env:TOOLCHAIN_INDEX_REGISTRY,Env:TOOLCHAIN_REPOSITORY,Env:TOOLCHAIN_OS,Env:TOOLCHAIN_ARCH,Env:TOOLCHAIN_TOKEN,Env:TOOLCHAIN_USERNAME,Env:TOOLCHAIN_PASSWORD -ErrorAction SilentlyContinue
		$script:RegistryAuthHeaderCache = @{}
	}

	AfterEach {
		$env:TOOLCHAIN_REGISTRY = $script:oldRegistry
		$env:TOOLCHAIN_INDEX_REGISTRY = $script:oldIndexRegistry
		$env:TOOLCHAIN_REPOSITORY = $script:oldRepository
		$env:TOOLCHAIN_OS = $script:oldOs
		$env:TOOLCHAIN_ARCH = $script:oldArch
		$env:TOOLCHAIN_TOKEN = $script:oldToken
		$env:TOOLCHAIN_USERNAME = $script:oldUsername
		$env:TOOLCHAIN_PASSWORD = $script:oldPassword
	}

	It 'normalizes configured endpoints and platform values' {
		$env:TOOLCHAIN_REGISTRY = ' https://registry.example.test/root/ '
		$env:TOOLCHAIN_INDEX_REGISTRY = ' https://index.example.test/ '
		$env:TOOLCHAIN_REPOSITORY = 'owner/repo'
		$env:TOOLCHAIN_OS = 'linux'
		$env:TOOLCHAIN_ARCH = 'arm64'
		GetRegistryBaseUrl | Should -Be 'https://registry.example.test/root'
		GetRegistryIndexUrl | Should -Be 'https://index.example.test'
		GetRegistryRepoName | Should -Be 'owner/repo'
		GetRegistryPlatformOs | Should -Be 'linux'
		GetRegistryPlatformArch | Should -Be 'arm64'
		GetRegistryUrl -Path 'v2/owner/repo' | Should -Be 'https://registry.example.test/v2/owner/repo'
		Test-DockerHubRegistryUrl -Url 'not a uri' | Should -BeFalse
	}

	It 'bounds response bodies and validates expected size' {
		$declaredTooLarge = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$declaredTooLarge.Content = [Net.Http.ByteArrayContent]::new([byte[]](1,2,3,4,5,6))
		{ Read-ToolchainBoundedResponseBytes -Response $declaredTooLarge -MaximumBytes 5 } | Should -Throw '*exceeds limit*'

		$streamedTooLarge = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$streamedTooLarge.Content = [Net.Http.StreamContent]::new([IO.MemoryStream]::new([byte[]](1,2,3,4,5,6)))
		{ Read-ToolchainBoundedResponseBytes -Response $streamedTooLarge -MaximumBytes 5 } | Should -Throw '*exceeds limit*'

		$mismatch = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$mismatch.Content = [Net.Http.ByteArrayContent]::new([byte[]](1,2,3))
		{ Read-ToolchainBoundedResponseBytes -Response $mismatch -MaximumBytes 10 -ExpectedSize 4 } | Should -Throw '*size mismatch*'

		$valid = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$valid.Content = [Net.Http.ByteArrayContent]::new([byte[]](1,2,3))
		@(Read-ToolchainBoundedResponseBytes -Response $valid -MaximumBytes 3 -ExpectedSize 3) | Should -Be @(1,2,3)
	}

	It 'reads digest headers and preserves media type while buffering' {
		$none = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		Get-ToolchainResponseDigestHeader -Response $none | Should -BeNullOrEmpty

		$multiple = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$multiple.Headers.TryAddWithoutValidation('Docker-Content-Digest', @('sha256:' + ('a' * 64), 'sha256:' + ('b' * 64))) | Out-Null
		{ Get-ToolchainResponseDigestHeader -Response $multiple } | Should -Throw

		$response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$response.Content = [Net.Http.StringContent]::new('{}')
		$response.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/vnd.oci.image.manifest.v1+json')
		Set-ToolchainBufferedResponseContent -Response $response -Bytes ([Text.Encoding]::UTF8.GetBytes('{"ok":true}'))
		$response.Content.Headers.ContentType.MediaType | Should -Be 'application/vnd.oci.image.manifest.v1+json'
		$response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | Should -Be '{"ok":true}'
	}

	It 'validates complete descriptors' {
		{ Assert-ToolchainDescriptor -Descriptor ([pscustomobject]@{ size=1 }) -Context layer -MaximumSize 10 } | Should -Throw '*missing digest*'
		{ Assert-ToolchainDescriptor -Descriptor ([pscustomobject]@{ digest=('sha256:' + ('a' * 64)); size='bad' }) -Context layer -MaximumSize 10 } | Should -Throw '*invalid size*'
		{ Assert-ToolchainDescriptor -Descriptor ([pscustomobject]@{ digest=('sha256:' + ('a' * 64)); size=11 }) -Context layer -MaximumSize 10 } | Should -Throw '*exceeds size limit*'
		$result = Assert-ToolchainDescriptor -Descriptor ([pscustomobject]@{ digest=('sha256:' + ('A' * 64)); size=10; mediaType='application/test' }) -Context layer -MaximumSize 10
		$result.Digest | Should -Be ('sha256:' + ('a' * 64))
		$result.Size | Should -Be 10
		$result.MediaType | Should -Be 'application/test'
	}

	It 'encodes basic authentication and parses challenges' {
		GetBasicAuthHeader -Username user -Pass 'p:a ss' | Should -Be ('Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('user:p:a ss')))
		(ParseAuthHeaderParams -HeaderValue 'Basic').Count | Should -Be 0
		$params = ParseAuthHeaderParams -HeaderValue 'Bearer realm="https://auth.example/token",service="registry.example",scope="repository:owner/repo:pull"'
		$params.realm | Should -Be 'https://auth.example/token'
		$params.service | Should -Be 'registry.example'
		$params.scope | Should -Be 'repository:owner/repo:pull'
	}

	It 'honors Retry-After delta and date values' {
		$deltaResponse = [Net.Http.HttpResponseMessage]::new()
		$deltaResponse.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds(7))
		Get-RegistryRetryDelaySeconds -Response $deltaResponse -DefaultSeconds 2 | Should -Be 7

		$dateResponse = [Net.Http.HttpResponseMessage]::new()
		$dateResponse.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([DateTimeOffset]::UtcNow.AddSeconds(10))
		Get-RegistryRetryDelaySeconds -Response $dateResponse -DefaultSeconds 2 | Should -BeGreaterOrEqual 8
	}
}

Describe 'Registry transport authentication' {
	BeforeEach {
		$script:RegistryAuthHeaderCache = @{}
		Remove-Item Env:TOOLCHAIN_TOKEN,Env:TOOLCHAIN_USERNAME,Env:TOOLCHAIN_PASSWORD -ErrorAction SilentlyContinue
		Mock GetRegistryBaseUrl { 'https://registry.example.test' }
		Mock GetRegistryIndexUrl { 'https://index.example.test' }
	}

	It 'rejects non-absolute token realms' {
		{ GetBearerTokenFromRealm -Realm '/relative' } | Should -Throw '*not absolute*'
	}

	It 'accepts access_token and disposes the response' {
		$script:disposed = $false
		Mock HttpRequest { [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $URL) }
		Mock HttpSend {
			$response = [pscustomobject]@{}
			$response | Add-Member ScriptMethod Dispose { $script:disposed = $true }
			return $response
		}
		Mock GetJsonResponse { [pscustomobject]@{ access_token='abc' } }
		GetBearerTokenFromRealm -Realm 'https://auth.example/token' -Service svc -Scope scope | Should -Be 'abc'
		$script:disposed | Should -BeTrue
	}

	It 'fails closed when token responses contain no token' {
		Mock HttpRequest { [Net.Http.HttpRequestMessage]::new() }
		Mock HttpSend { [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK) }
		Mock GetJsonResponse { [pscustomobject]@{} }
		{ GetBearerTokenFromRealm -Realm 'https://auth.example/token' } | Should -Throw '*did not include*'
	}

	It 'handles base Basic, Bearer, cached, token, and unsupported challenges' {
		$basic = [Net.Http.Headers.AuthenticationHeaderValue]::Parse('Basic realm="registry"')
		{ GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $basic } | Should -Throw '*requires Basic auth*'
		$env:TOOLCHAIN_USERNAME = 'user'
		$env:TOOLCHAIN_PASSWORD = 'pass'
		$header = GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $basic
		$header | Should -Match '^Basic '
		GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $basic | Should -Be $header

		$script:RegistryAuthHeaderCache = @{}
		$script:capturedScope = $null
		Mock GetBearerTokenFromRealm {
			$script:capturedScope = $Scope
			'challenge-token'
		}
		$bearer = [Net.Http.Headers.AuthenticationHeaderValue]::Parse('Bearer realm="https://auth.example/token",service="registry.example"')
		GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $bearer | Should -Be 'Bearer challenge-token'
		Should -Invoke GetBearerTokenFromRealm -Times 1 -Exactly
		$script:capturedScope | Should -Be 'repository:owner/repo:pull'

		$script:RegistryAuthHeaderCache = @{}
		$env:TOOLCHAIN_TOKEN = 'configured-token'
		GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $bearer | Should -Be 'Bearer configured-token'

		$script:RegistryAuthHeaderCache = @{}
		Remove-Item Env:TOOLCHAIN_TOKEN -ErrorAction SilentlyContinue
		$digest = [Net.Http.Headers.AuthenticationHeaderValue]::Parse('Digest realm="registry"')
		{ GetRegistryBaseAuthHeader -Repo owner/repo -WwwAuthenticate $digest } | Should -Throw '*Unsupported*'
	}

	It 'applies equivalent authentication rules to the index endpoint' {
		$env:TOOLCHAIN_TOKEN = 'index-token'
		$challenge = [Net.Http.Headers.AuthenticationHeaderValue]::Parse('Bearer realm="https://auth.example/token"')
		GetRegistryIndexAuthHeader -Repo owner/repo -WwwAuthenticate $challenge | Should -Be 'Bearer index-token'
		GetRegistryIndexAuthHeader -Repo owner/repo -WwwAuthenticate $challenge | Should -Be 'Bearer index-token'
	}

	It 'retries transient base-registry failures without losing range parameters' {
		$script:calls = 0
		$script:ranges = @()
		Mock GetRegistryRepoName { 'owner/repo' }
		Mock Test-DockerHubRegistryUrl { $false }
		Mock HttpRequest {
			$script:ranges += $Range
			[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $URL)
		}
		Mock HttpSend {
			$script:calls++
			if ($script:calls -eq 1) { return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::ServiceUnavailable) }
			return [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		}
		Mock Get-RegistryRetryDelaySeconds { 0 }
		Mock Start-Sleep { }
		Mock Write-ToolchainInfo { }

		$response = InvokeRegistryBaseRequest -Url 'https://registry.example.test/v2/x' -Range 'bytes=5-'
		try { $response.StatusCode | Should -Be ([Net.HttpStatusCode]::OK) } finally { $response.Dispose() }
		$script:calls | Should -Be 2
		$script:ranges | Should -Be @('bytes=5-','bytes=5-')
		Should -Invoke Start-Sleep -Times 1 -Exactly
	}
}
