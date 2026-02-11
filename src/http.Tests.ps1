<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')

	function New-MockHttpClient {
		param([scriptblock]$SendAsyncImpl)
			$o = New-Object PSObject
			$o | Add-Member -MemberType NoteProperty -Name SendAsyncImpl -Value $SendAsyncImpl -Force
		$o | Add-Member -MemberType ScriptMethod -Name SendAsync -Value {
			param($Req, $Opt, $Token)
					if (-not ($this.SendAsyncImpl -is [scriptblock])) {
						throw "MockHttpClient.SendAsyncImpl is not invokable (type=$($this.SendAsyncImpl.GetType().FullName))"
					}
					return $this.SendAsyncImpl.Invoke($Req, $Opt, $Token)
		} -Force
		return $o
	}
}

Describe 'HttpRequest' {
	It 'sets headers, accept, range, and auth' {
		$req = HttpRequest -URL 'https://example.com/a' -Method GET -Accept 'application/json' -Headers @{ 'X-Test' = '1' } -RangeFrom 0 -RangeTo 9 -AuthHeader 'Bearer t'
		$req.Method.Method | Should -Be 'GET'
		$req.Headers.Accept.ToString() | Should -Match 'application/json'
		$req.Headers.GetValues('X-Test')[0] | Should -Be '1'
		$req.Headers.Authorization.ToString() | Should -Be 'Bearer t'
		$req.Headers.Range.ToString() | Should -Be 'bytes=0-9'
	}

	It 'omits range upper bound when RangeTo is not specified' {
		$req = HttpRequest -URL 'https://example.com/a' -Method GET -RangeFrom 5
		$req.Headers.Range.ToString() | Should -Be 'bytes=5-'
	}
}

Describe 'Get-ToolchainHttpClient' {
	BeforeEach {
		$script:HttpClient = $null
		$script:HttpClientNoRedirect = $null
		Remove-Item env:TOOLCHAIN_PROXY -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_PROXY_USERNAME -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_PROXY_PASSWORD -ErrorAction SilentlyContinue
		Remove-Item env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS -ErrorAction SilentlyContinue
	}

	It 'creates separate cached clients for redirect/no-redirect and honors timeout' {
		$env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS = '5'
		$cli1 = Get-ToolchainHttpClient
		$cli2 = Get-ToolchainHttpClient
		$cli1 | Should -Be $cli2

		$cli3 = Get-ToolchainHttpClient -NoRedirect
		$cli4 = Get-ToolchainHttpClient -NoRedirect
		$cli3 | Should -Be $cli4
		$cli3 | Should -Not -Be $cli1
	}

	It 'throws for invalid timeout env var' {
		$env:TOOLCHAIN_HTTP_TIMEOUT_SECONDS = 'nope'
		{ Get-ToolchainHttpClient } | Should -Throw '*Invalid TOOLCHAIN_HTTP_TIMEOUT_SECONDS*'
	}

	It 'creates a proxy when TOOLCHAIN_PROXY is set' {
		$env:TOOLCHAIN_PROXY = 'http://proxy.example:8080'
		$env:TOOLCHAIN_PROXY_USERNAME = 'u'
		$env:TOOLCHAIN_PROXY_PASSWORD = 'p'
		$cli = Get-ToolchainHttpClient
		$cli | Should -Not -BeNullOrEmpty
	}
}

Describe 'HttpSend' {
	It 'returns response from SendAsync' {
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$mockCli = New-MockHttpClient {
			param($Req,$Opt,$Token)
			return [System.Threading.Tasks.Task[Net.Http.HttpResponseMessage]]::FromResult($resp)
		}
		Mock Get-ToolchainHttpClient { $mockCli }
		$out = (HttpRequest -URL 'https://example.com') | HttpSend
		$out.StatusCode | Should -Be ([Net.HttpStatusCode]::OK)
	}

	It 'wraps SendAsync exceptions with request URL' {
		$mockCli = New-MockHttpClient {
			param($Req,$Opt,$Token)
			throw 'boom'
		}
		Mock Get-ToolchainHttpClient { $mockCli }
		{ (HttpRequest -URL 'https://example.com') | HttpSend } | Should -Throw '*failed to download https://example.com*'
	}
}

Describe 'GetJsonResponse' {
	It 'parses application/json' {
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$resp.Content = [Net.Http.StringContent]::new('{"A": "B"}')
		$resp.Content.Headers.ContentType.MediaType = 'application/json'
		(GetJsonResponse -Resp $resp).A | Should -Be 'B'
	}

	It 'parses application/*+json' {
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$resp.Content = [Net.Http.StringContent]::new('{"A": 1}')
		$resp.Content.Headers.ContentType.MediaType = 'application/vnd.oci.image.index.v1+json'
		(GetJsonResponse -Resp $resp).A | Should -Be 1
	}

	It 'throws when content is not JSON' {
		$resp = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
		$resp.Content = [Net.Http.StringContent]::new('any')
		$resp.Content.Headers.ContentType.MediaType = 'text/plain'
		{ GetJsonResponse -Resp $resp } | Should -Throw
	}
}
