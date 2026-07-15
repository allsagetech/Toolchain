<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
	$script:oldCatalogCacheTtl = $env:TOOLCHAIN_CATALOG_CACHE_TTL
	$env:TOOLCHAIN_CATALOG_CACHE_TTL = '00:00:00'
}

AfterAll {
	$env:TOOLCHAIN_CATALOG_CACHE_TTL = $script:oldCatalogCacheTtl
}

Describe 'Remote catalog cache' {
	BeforeEach {
		$env:TOOLCHAIN_CATALOG_CACHE_TTL = '00:15:00'
		$env:TOOLCHAIN_REGISTRY = 'https://registry.example.test'
		$env:TOOLCHAIN_INDEX_REGISTRY = 'https://registry.example.test'
		$env:TOOLCHAIN_REPOSITORY = 'acme/toolchains'
		Mock GetToolchainRepo { return $null }
		Mock GetPwrDBPath { return (Join-Path $TestDrive 'cache') }
		Mock Assert-ToolchainRegistryPolicyAllowed { }
		Mock GetRegistryTagsList { return [pscustomobject]@{ Name='acme/toolchains'; Tags=@('pkg-1.0.0') } }
	}

	AfterEach {
		$env:TOOLCHAIN_CATALOG_CACHE_TTL = '00:00:00'
		Remove-Item Env:TOOLCHAIN_REGISTRY,Env:TOOLCHAIN_INDEX_REGISTRY,Env:TOOLCHAIN_REPOSITORY -ErrorAction Ignore
	}

	It 'reuses a fresh matching catalog and supports explicit refresh' {
		(GetTagsList).Tags | Should -Contain 'pkg-1.0.0'
		(GetTagsList).Tags | Should -Contain 'pkg-1.0.0'
		Should -Invoke -CommandName GetRegistryTagsList -Exactly -Times 1
		(GetTagsList -Refresh).Tags | Should -Contain 'pkg-1.0.0'
		Should -Invoke -CommandName GetRegistryTagsList -Exactly -Times 2
	}

	It 'uses stale matching data when the registry is temporarily unavailable' {
		(GetTagsList).Tags | Should -Contain 'pkg-1.0.0'
		$path = Get-ToolchainCatalogCachePath
		$document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
		$document.createdAt = [datetime]::UtcNow.AddHours(-1).ToString('o')
		[IO.File]::WriteAllText($path, ($document | ConvertTo-Json -Depth 5))
		Mock GetRegistryTagsList { throw 'temporary outage' }
		(GetTagsList).Tags | Should -Contain 'pkg-1.0.0'
	}
}

Describe "Registry config defaults" {
	BeforeAll {
		$script:hadRegistry = Test-Path Env:TOOLCHAIN_REGISTRY
		$script:hadNamespace = Test-Path Env:TOOLCHAIN_NAMESPACE
		$script:hadAuth = Test-Path Env:TOOLCHAIN_AUTH
			$script:hadRepository = Test-Path Env:TOOLCHAIN_REPOSITORY
		if ($script:hadRegistry) { $script:oldRegistry = $env:TOOLCHAIN_REGISTRY }
		if ($script:hadNamespace) { $script:oldNamespace = $env:TOOLCHAIN_NAMESPACE }
		if ($script:hadAuth) { $script:oldAuth = $env:TOOLCHAIN_AUTH }

			if ($script:hadRepository) { $script:oldRepository = $env:TOOLCHAIN_REPOSITORY }
		Remove-Item Env:TOOLCHAIN_REGISTRY -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_NAMESPACE -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_AUTH -ErrorAction Ignore
			Remove-Item Env:TOOLCHAIN_REPOSITORY -ErrorAction Ignore
	}

	AfterAll {
		if ($script:hadRegistry) { $env:TOOLCHAIN_REGISTRY = $script:oldRegistry } else { Remove-Item Env:TOOLCHAIN_REGISTRY -ErrorAction Ignore }
		if ($script:hadNamespace) { $env:TOOLCHAIN_NAMESPACE = $script:oldNamespace } else { Remove-Item Env:TOOLCHAIN_NAMESPACE -ErrorAction Ignore }
		if ($script:hadAuth) { $env:TOOLCHAIN_AUTH = $script:oldAuth } else { Remove-Item Env:TOOLCHAIN_AUTH -ErrorAction Ignore }
			if ($script:hadRepository) { $env:TOOLCHAIN_REPOSITORY = $script:oldRepository } else { Remove-Item Env:TOOLCHAIN_REPOSITORY -ErrorAction Ignore }
	}

	It "Defaults to allsagetech/toolchains on Docker Hub" {
		GetRegistryRepoName | Should -Be 'allsagetech/toolchains'
		(GetRegistryBaseUrl) | Should -Be 'https://registry-1.docker.io'
		(GetRegistryIndexUrl) | Should -Be 'https://registry-1.docker.io'
	}
	It "Defaults to Windows/amd64 platform" {
		(GetRegistryPlatformOs) | Should -Be 'windows'
		(GetRegistryPlatformArch) | Should -Be 'amd64'
	}
}

Describe "Challenge-based auth (Bearer) in InvokeRegistryRequest" {
	BeforeAll {
		Mock GetToolchainRepo { return $null }

		$script:call = 0
		Mock HttpSend {
			param([Net.Http.HttpRequestMessage]$Req)
			$script:call++

			$uri = $Req.RequestUri.OriginalString

			if ($script:call -eq 1) {
				$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Unauthorized)
				$resp.Headers.WwwAuthenticate.Add([System.Net.Http.Headers.AuthenticationHeaderValue]::Parse('Bearer realm="https://tokens.example.test/token",service="registry.example.test",scope="repository:allsagetech/toolchains:pull"'))
				return $resp
			}

			if ($script:call -eq 2) {
				$uri | Should -Match 'tokens\.example\.test/token'
				$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
				$resp.Content = [Net.Http.StringContent]::new((ConvertTo-Json @{ token = 'abc123' }))
				$resp.Content.Headers.ContentType.MediaType = 'application/json'
				return $resp
			}

			if ($script:call -eq 3) {
				$uri | Should -Match '/v2/allsagetech/toolchains/tags/list'
				$Req.Headers.Authorization.Scheme | Should -Be 'Bearer'
				$Req.Headers.Authorization.Parameter | Should -Be 'abc123'
				$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
				$resp.Content = [Net.Http.StringContent]::new((ConvertTo-Json @{ name='allsagetech/toolchains'; tags=@('pkg-1.0.0') }))
				$resp.Content.Headers.ContentType.MediaType = 'application/json'
				return $resp
			}

			throw "unexpected call: $script:call uri=$uri"
		}

		$env:TOOLCHAIN_REGISTRY = $null
		$env:TOOLCHAIN_INDEX_REGISTRY = 'https://registry.example.test'
		$env:TOOLCHAIN_REPOSITORY = $null
		$env:TOOLCHAIN_TOKEN = $null
		$env:TOOLCHAIN_USERNAME = $null
		$env:TOOLCHAIN_PASSWORD = $null
	}

	It "Gets tags after Bearer challenge" {
		$t = GetTagsList
		$t.tags | Should -Contain 'pkg-1.0.0'
	}
}

Describe "Docker Hub pre-auth" {
	BeforeEach {
		$script:RegistryAuthHeaderCache = @{}
		$env:TOOLCHAIN_REGISTRY = $null
		$env:TOOLCHAIN_INDEX_REGISTRY = $null
		$env:TOOLCHAIN_REPOSITORY = $null
		$env:TOOLCHAIN_TOKEN = $null
		$env:TOOLCHAIN_USERNAME = $null
		$env:TOOLCHAIN_PASSWORD = $null
	}

	It "recognizes Docker Hub registry endpoints" {
		Test-DockerHubRegistryUrl -Url 'https://index.docker.io' | Should -BeTrue
		Test-DockerHubRegistryUrl -Url 'https://registry-1.docker.io' | Should -BeTrue
		Test-DockerHubRegistryUrl -Url 'https://registry.example.test' | Should -BeFalse
	}

	It "sends a bearer token on the first Docker Hub tag-list request" {
		Mock GetToolchainRepo { return $null }
		Mock GetBearerTokenFromRealm {
			$Repo | Should -Be 'allsagetech/toolchains'
			$Realm | Should -Be 'https://auth.docker.io/token'
			$Service | Should -Be 'registry.docker.io'
			$Scope | Should -Be 'repository:allsagetech/toolchains:pull'
			return 'preauth-token'
		}
		Mock HttpSend {
			param([Net.Http.HttpRequestMessage]$Req)
			$Req.Headers.Authorization.Scheme | Should -Be 'Bearer'
			$Req.Headers.Authorization.Parameter | Should -Be 'preauth-token'
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.StringContent]::new((ConvertTo-Json @{ name='repo'; tags=@('pkg-1.0.0') }))
			$resp.Content.Headers.ContentType.MediaType = 'application/json'
			return $resp
		}

		$t = GetTagsList
		$t.tags | Should -Contain 'pkg-1.0.0'
		Should -Invoke -CommandName GetBearerTokenFromRealm -Exactly -Times 1
	}
}

Describe "Platform resolution prefers Windows manifest" {
	BeforeAll {
		$env:TOOLCHAIN_OS = $null
		$env:TOOLCHAIN_ARCH = $null
	}

	It "Selects windows/amd64 from manifest list" {
		$ml = @{
			schemaVersion = 2
			mediaType = 'application/vnd.docker.distribution.manifest.list.v2+json'
			manifests = @(
				@{ digest='sha256:linux'; platform=@{ os='linux'; architecture='amd64' } },
				@{ digest='sha256:win'; platform=@{ os='windows'; architecture='amd64' } }
			)
		}
		$choice = ResolveManifestToSinglePlatform -Manifest $ml
		$choice.digest | Should -Be 'sha256:win'
	}

	It 'fails when the requested platform is absent instead of selecting an arbitrary image' {
		$ml = @{
			schemaVersion = 2
			manifests = @(
				@{ digest=('sha256:' + ('1' * 64)); size=1; platform=@{ os='linux'; architecture='amd64' } },
				@{ digest=('sha256:' + ('2' * 64)); size=1; platform=@{ os='linux'; architecture='arm64' } }
			)
		}
		{ ResolveManifestToSinglePlatform -Manifest $ml } | Should -Throw '*requested platform windows/amd64*linux/amd64*linux/arm64*'
	}
}

Describe "Response disposal in registry helpers" {
	It "Disposes manifest response in GetDigestForRef" {
		$script:disposed = $false
		$resp = [pscustomobject]@{}
		$resp | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $script:disposed = $true } -Force
		Mock GetManifest { $resp }
		Mock GetDigest { 'sha256:abc' }

		(GetDigestForRef -Ref 'somepkg:latest') | Should -Be 'sha256:abc'
		$script:disposed | Should -BeTrue
	}

	It "Disposes tag-list response in GetTagsList" {
		$script:disposed = $false
		$resp = [pscustomobject]@{}
		$resp | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $script:disposed = $true } -Force
		Mock GetToolchainRepo { return $null }
		Mock InvokeIndexRegistryRequest { $resp }
		Mock GetJsonResponse { [pscustomobject]@{ name='repo'; tags=@('pkg-1.0.0') } }

		$t = GetTagsList
		$t.tags | Should -Contain 'pkg-1.0.0'
		$script:disposed | Should -BeTrue
	}

	It "Disposes tag-list response when parsing throws" {
		$script:disposed = $false
		$resp = [pscustomobject]@{}
		$resp | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $script:disposed = $true } -Force
		Mock GetToolchainRepo { return $null }
		Mock InvokeIndexRegistryRequest { $resp }
		Mock GetJsonResponse { throw 'bad json' }

		{ GetTagsList } | Should -Throw
		$script:disposed | Should -BeTrue
	}

	It "Treats a null registry tags array as an empty list" {
		Mock GetToolchainRepo { return $null }
		Mock InvokeIndexRegistryRequest {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.StringContent]::new((ConvertTo-Json @{ name='repo'; tags=$null }))
			$resp.Content.Headers.ContentType.MediaType = 'application/json'
			return $resp
		}

		$t = GetTagsList
		@($t.tags).Count | Should -Be 0
	}

	It "Falls back to Docker Hub tags API when registry tag list is forbidden" {
		Mock GetToolchainRepo { return $null }
		Mock InvokeIndexRegistryRequest {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Forbidden)
			$resp.Content = [Net.Http.StringContent]::new('forbidden')
			$resp.Content.Headers.ContentType = $null
			return $resp
		}
		Mock GetDockerHubRepositoryTagsList {
			return [pscustomobject]@{ name='repo'; tags=@('fallback-1.0.0') }
		}

		$t = GetTagsList
		$t.tags | Should -Contain 'fallback-1.0.0'
		Should -Invoke -CommandName GetDockerHubRepositoryTagsList -Exactly -Times 1
	}

	It "Reads paged Docker Hub repository tag results" {
		$script:hubCalls = 0
		Mock HttpSend {
			$script:hubCalls += 1
			$Req.Headers.UserAgent.ToString() | Should -Match '^Mozilla/5\.0 .+ Chrome/[0-9]+'
			if ($script:hubCalls -eq 1) {
				$Req.RequestUri.AbsolutePath | Should -Be '/v2/namespaces/allsagetech/repositories/toolchains/tags'
			}
			$payload = if ($script:hubCalls -eq 1) {
				@{ results=@(@{ name='first-1.0.0' }); next='https://hub.docker.com/v2/namespaces/allsagetech/repositories/toolchains/tags?page=2' }
			} else {
				@{ results=@(@{ name='second-1.0.0' }); next=$null }
			}
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.StringContent]::new(($payload | ConvertTo-Json -Depth 5))
			$resp.Content.Headers.ContentType.MediaType = 'application/json'
			return $resp
		}

		$t = GetDockerHubRepositoryTagsList
		$t.name | Should -Be 'allsagetech/toolchains'
		$t.tags | Should -Contain 'first-1.0.0'
		$t.tags | Should -Contain 'second-1.0.0'
		$script:hubCalls | Should -Be 2
	}

	It "Rejects unsafe Docker Hub pagination URLs" {
		Mock HttpSend {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.StringContent]::new((ConvertTo-Json @{ results=@(@{ name='first-1.0.0' }); next='https://example.invalid/steal' }))
			$resp.Content.Headers.ContentType.MediaType = 'application/json'
			return $resp
		}

		{ GetDockerHubRepositoryTagsList } | Should -Throw '*unsafe URL*'
	}
}

Describe "Offline blob lookup" {
	It "Selects a single blob when duplicate digest files exist in offline package folders" {
		$repo = Join-Path $TestDrive 'repo'
		$pkgA = Join-Path $repo 'codex-0.1.0'
		$pkgB = Join-Path $repo 'git-0.1.0'
		New-Item -ItemType Directory -Path $pkgA, $pkgB -Force | Out-Null

		$digestHex = 'a' * 64
		$blobName = "${digestHex}.tar.gz"
		$blobA = Join-Path $pkgA $blobName
		$blobB = Join-Path $pkgB $blobName
		[IO.File]::WriteAllBytes($blobA, [byte[]](1, 2, 3, 4))
		[IO.File]::WriteAllBytes($blobB, [byte[]](5, 6, 7, 8))

		Mock GetToolchainRepo { return $repo }

		$resp = GetBlob -Ref ("sha256:${digestHex}") -StartByte 0
		try {
			$resp.IsSuccessStatusCode | Should -BeTrue
			$bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
			$bytes.Length | Should -Be 4
		} finally {
			$resp.Dispose()
		}
	}
}

Describe 'OCI integrity boundaries' {
	BeforeEach {
		Mock WriteConsole {}
		Mock GetToolchainRepo { return $null }
	}

	It 'rejects a manifest body that does not match its immutable digest' {
		$expectedBytes = [Text.Encoding]::UTF8.GetBytes('{"schemaVersion":2,"layers":[]}')
		$expected = Get-ToolchainBytesSha256Digest -Bytes $expectedBytes
		Mock GetManifest {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Headers.TryAddWithoutValidation('Docker-Content-Digest', $expected) | Out-Null
			$resp.Content = [Net.Http.StringContent]::new('{"schemaVersion":2,"layers":[{"evil":true}]}')
			return $resp
		}

		{ GetVerifiedManifestResponse -Ref $expected } | Should -Throw '*manifest digest* mismatch*'
	}

	It 'normalizes valid digest headers and rejects non-canonical algorithms or lengths' {
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		try {
			$resp.Headers.TryAddWithoutValidation('Docker-Content-Digest', ('sha256:' + ('A' * 64))) | Out-Null
			($resp | GetDigest) | Should -Be ('sha256:' + ('a' * 64))
		} finally { $resp.Dispose() }

		{ 'sha512:' + ('a' * 64) | ConvertTo-CanonicalSha256Digest } | Should -Throw '*invalid sha256 digest*'
		{ 'sha256:abc' | ConvertTo-CanonicalSha256Digest } | Should -Throw '*invalid sha256 digest*'
	}

	It 'rejects an image config body that does not match its descriptor' {
		$good = [Text.Encoding]::UTF8.GetBytes('{"config":{}}')
		$expected = Get-ToolchainBytesSha256Digest -Bytes $good
		Mock GetResolvedManifestJson {
			return [pscustomobject]@{ config = [pscustomobject]@{ digest=$expected; size=$good.Length; mediaType='application/vnd.oci.image.config.v1+json' } }
		}
		Mock GetBlob {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.ByteArrayContent]::new([Text.Encoding]::UTF8.GetBytes('{"config":[]}'))
			return $resp
		}

		{ GetImageConfigJsonFromRef -Ref ('sha256:' + ('c' * 64)) } | Should -Throw '*image config digest mismatch*'
	}

	It 'rejects non-canonical layer descriptors before downloading blobs' {
		$manifest = '{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:short","size":10}]}'
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		try {
			$resp.Content = [Net.Http.StringContent]::new($manifest)
			$resp.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
			{ $resp | GetPackageLayers } | Should -Throw '*invalid sha256 digest*'
		} finally { $resp.Dispose() }
	}

	It 'deletes a completed blob whose bytes do not match the layer digest' {
		$temp = Join-Path $TestDrive 'blob-digest'
		New-Item -ItemType Directory -Path $temp | Out-Null
		$good = [Text.Encoding]::UTF8.GetBytes('good')
		$digest = Get-ToolchainBytesSha256Digest -Bytes $good
		Mock GetPwrTempPath { $temp }
		Mock GetBlob {
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.ByteArrayContent]::new([Text.Encoding]::UTF8.GetBytes('evil'))
			return $resp
		}

		{ SaveBlob -Digest $digest -ExpectedSize 4 } | Should -Throw '*blob digest mismatch*'
		Test-Path -LiteralPath (Join-Path $temp ($digest.Substring(7) + '.tar.gz')) | Should -BeFalse
	}

	It 'restarts safely when a server ignores a resume Range request' {
		$temp = Join-Path $TestDrive 'blob-resume'
		New-Item -ItemType Directory -Path $temp | Out-Null
		$bytes = [Text.Encoding]::UTF8.GetBytes('good')
		$digest = Get-ToolchainBytesSha256Digest -Bytes $bytes
		$path = Join-Path $temp ($digest.Substring(7) + '.tar.gz')
		[IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes('go'))
		Mock GetPwrTempPath { $temp }
		$script:starts = @()
		Mock GetBlob {
			$script:starts += $StartByte
			$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
			$resp.Content = [Net.Http.ByteArrayContent]::new($bytes)
			return $resp
		}

		(SaveBlob -Digest $digest -ExpectedSize 4) | Should -Be $path
		$script:starts | Should -Be @(2, 0)
		(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() | Should -Be $digest.Substring(7)
	}

	It 'denies a disallowed registry before any HTTP request is sent' {
		Mock GetToolchainPolicy { @{ allowedRegistries = @('allowed.example') } }
		Mock GetRegistryBaseUrl { 'https://denied.example' }
		Mock GetRegistryRepoName { 'owner/repo' }
		Mock HttpSend { throw 'must not contact registry' }

		{ GetManifest -Ref 'pkg:latest' } | Should -Throw '*policy denied*registry not allowed*'
		Should -Invoke -CommandName HttpSend -Exactly -Times 0
	}
}

Describe 'Definition label integrity' {
	BeforeEach {
		Mock GetToolchainRepo { return $null }
	}

	It 'fails closed for unsupported or malformed specVersion labels' {
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.specVersion'='2' } } } }
		{ GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('d' * 64)) -RootPath $TestDrive } | Should -Throw '*newer than this Toolchain supports*'

		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.specVersion'='garbage' } } } }
		{ GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('d' * 64)) -RootPath $TestDrive } | Should -Throw '*invalid specVersion*'
	}

	It 'rejects a definition label path that escapes the package root' {
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.tlcPath'='../outside.tlc' } } } }
		{ GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('e' * 64)) -RootPath $TestDrive } | Should -Throw '*unsafe toolchain definition path*'
	}

	It 'rejects a definition label path that traverses an in-root junction' {
		$rootPath = Join-Path $TestDrive 'label-root'
		$outside = Join-Path $TestDrive 'label-outside'
		New-Item -ItemType Directory -Path $rootPath, $outside -Force | Out-Null
		'{"env":{"ESCAPE":"no"}}' | Set-Content -LiteralPath (Join-Path $outside 'definition.tlc') -NoNewline
		$linkType = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
		New-Item -ItemType $linkType -Path (Join-Path $rootPath 'metadata') -Target $outside | Out-Null
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{ 'io.allsagetech.toolchain.tlcPath'='metadata/definition.tlc' } } } }

		{ GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('e' * 64)) -RootPath $rootPath } | Should -Throw '*traverses a link or reparse point*'
	}

	It 'expands a Windows package root safely in an inline JSON label' {
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{
			'io.allsagetech.toolchain.specVersion'='1'
			'io.allsagetech.toolchain.tlc'='{"env":{"BIN":"${.}/bin"}}'
		} } } }

		$definition = GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('1' * 64)) -RootPath $TestDrive
		$definition.env.BIN | Should -Be "$TestDrive/bin"
	}

	It 'accepts a safe in-root definition path with the matching sha256' {
		$definitionPath = Join-Path $TestDrive 'metadata\package.tlc'
		New-Item -ItemType Directory -Path (Split-Path $definitionPath) -Force | Out-Null
		'{"env":{"SAFE":"yes","PATH":"${.}/bin"}}' | Set-Content -LiteralPath $definitionPath -NoNewline
		$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $definitionPath).Hash.ToLowerInvariant()
		Mock GetImageConfigJsonFromRef { [pscustomobject]@{ config = [pscustomobject]@{ Labels = [pscustomobject]@{
			'io.allsagetech.toolchain.specVersion'='1'
			'io.allsagetech.toolchain.tlcPath'='metadata/package.tlc'
			'io.allsagetech.toolchain.tlcSha256'=$hash
		} } } }

		$definition = GetToolchainDefinitionFromLabels -Ref ('sha256:' + ('f' * 64)) -RootPath $TestDrive
		$definition.env.SAFE | Should -Be 'yes'
		$definition.env.PATH | Should -Be "$TestDrive/bin"
	}
}
