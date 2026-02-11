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
