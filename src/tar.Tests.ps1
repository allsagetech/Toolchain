<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe "FromOctalString" {
	It "parses tar-padded numeric fields" {
		FromOctalString ("000777 " + [char]0) | Should -Be 511
		FromOctalString ("00000000000 " + [char]0) | Should -Be 0
	}
}

Describe "Untargz" {
	BeforeAll {
		$script:root = (Resolve-Path "$PSScriptRoot\..\test").Path
		$script:tgz = "$root\a9258b98bfc2c8ed0af1a6e7ee55e604286820c7bf81768ed0da34d5ed87d483.tar.gz"
		$script:ToolchainPath = "$root\toolchain"
		Mock ResolvePackagePath {
			return "$ToolchainPath\0123456789abc"
		}
		Mock WriteConsole {}
		Mock WritePeriodicConsole {}
	}
	AfterAll {
		[IO.Directory]::Delete("\\?\$ToolchainPath", $true)
	}
	It "Extracts" {
		$tgz | ExtractTarGz -Digest '1234567890ab'
		$pkg = ResolvePackagePath '_'
		Get-Content "$pkg\file.txt" -Raw | Should -Be 'A'
		Get-Content "$pkg\empty.txt" -Raw | Should -Be $null
		[IO.File]::ReadAllText("\\?\$pkg\nested\Some-Really-Long-Folder-Name----------------------------------------------------------------------------------------------------\Some-Really-Long-Folder-Name-----------------------------------------------------\a.txt") | Should -Be 'xyz'
	}

	It "Extracts OCI paths without Files prefix" {
		$work = Join-Path $root ("oci-" + [Guid]::NewGuid().ToString('N'))
		$layer = Join-Path $work 'layer'
		$etcDir = Join-Path $layer 'etc'
		New-Item -ItemType Directory -Path $etcDir -Force | Out-Null
		'{"env":{"PATH":"${.}/bin"}}' | Set-Content -LiteralPath (Join-Path $layer '.tlc') -NoNewline
		'ok' | Set-Content -LiteralPath (Join-Path $etcDir 'marker.txt') -NoNewline

		$tgzPath = Join-Path $work 'layer.tar.gz'
		try {
			tar -czf $tgzPath -C $layer . | Out-Null
			$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tgzPath).Hash.ToLower()
			$hashedTgz = Join-Path $work "$hash.tar.gz"
			Move-Item -LiteralPath $tgzPath -Destination $hashedTgz -Force

			$hashedTgz | ExtractTarGz -Digest '1234567890ab'
			$pkg = ResolvePackagePath '_'
			Test-Path -LiteralPath (Join-Path $pkg '.tlc') | Should -BeTrue
			(Get-Content -LiteralPath (Join-Path $pkg '.tlc') -Raw) | Should -Match '"env"'
			(Get-Content -LiteralPath (Join-Path $pkg 'etc\marker.txt') -Raw) | Should -Be 'ok'
		} finally {
			if (Test-Path -LiteralPath $work) {
				Remove-Item -LiteralPath $work -Recurse -Force
			}
		}
	}
}
