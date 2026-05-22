<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
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
			$payload = if ($script:hubCalls -eq 1) {
				@{ results=@(@{ name='first-1.0.0' }); next='https://hub.docker.com/next' }
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
