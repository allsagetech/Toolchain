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
		$script:root = (Resolve-Path (Join-Path $PSScriptRoot '..\test')).Path
		$script:tgz = Join-Path $root 'a9258b98bfc2c8ed0af1a6e7ee55e604286820c7bf81768ed0da34d5ed87d483.tar.gz'
		$script:ToolchainPath = Join-Path $root 'toolchain'
		$script:isWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
		Mock ResolvePackagePath {
			return (Join-Path $ToolchainPath '0123456789abc')
		}
		Mock WriteConsole {}
		Mock WritePeriodicConsole {}

		function Set-TarAsciiField([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Value) {
			$bytes = [Text.Encoding]::ASCII.GetBytes($Value)
			[Array]::Copy($bytes, 0, $Header, $Offset, [Math]::Min($bytes.Length, $Length))
		}

		function New-TestTarGz([string]$Directory, [object[]]$Entries, [switch]$OmitEndMarker, [switch]$TruncateEntryData) {
			New-Item -ItemType Directory -Path $Directory -Force | Out-Null
			$tar = [IO.MemoryStream]::new()
			try {
				foreach ($entry in $Entries) {
					$data = if ($null -ne $entry.Data) { [Text.Encoding]::UTF8.GetBytes([string]$entry.Data) } else { [byte[]]@() }
					$declaredSize = if ($null -ne $entry.Size) { [long]$entry.Size } else { [long]$data.Length }
					$header = New-Object byte[] 512
					Set-TarAsciiField $header 0 100 ([string]$entry.Name)
					Set-TarAsciiField $header 100 8 '0000777'
					Set-TarAsciiField $header 108 8 '0000000'
					Set-TarAsciiField $header 116 8 '0000000'
					Set-TarAsciiField $header 124 12 (([Convert]::ToString($declaredSize, 8)).PadLeft(11, '0') + [char]0)
					Set-TarAsciiField $header 136 12 ('00000000000' + [char]0)
					for ($i = 148; $i -lt 156; $i++) { $header[$i] = 32 }
					$type = if ($entry.Type) { [string]$entry.Type } else { '0' }
					$header[156] = [Text.Encoding]::ASCII.GetBytes($type)[0]
					if ($entry.Link) { Set-TarAsciiField $header 157 100 ([string]$entry.Link) }
					Set-TarAsciiField $header 257 6 ('ustar' + [char]0)
					$sum = 0
					foreach ($b in $header) { $sum += $b }
					Set-TarAsciiField $header 148 8 (([Convert]::ToString($sum, 8)).PadLeft(6, '0') + [char]0 + ' ')
					$tar.Write($header, 0, $header.Length)
					if ($data.Length -gt 0) { $tar.Write($data, 0, $data.Length) }
					if (-not $TruncateEntryData) {
						$padding = (512 - ($declaredSize % 512)) % 512
						if ($padding -gt 0) { $tar.Write((New-Object byte[] $padding), 0, $padding) }
					}
				}
				if (-not $OmitEndMarker) { $tar.Write((New-Object byte[] 1024), 0, 1024) }
				$rawPath = Join-Path $Directory 'layer.tar.gz'
				$file = [IO.File]::Open($rawPath, [IO.FileMode]::Create)
				try {
					$gzip = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionMode]::Compress)
					try {
						$bytes = $tar.ToArray()
						$gzip.Write($bytes, 0, $bytes.Length)
					} finally { $gzip.Dispose() }
				} finally { $file.Dispose() }
				$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToLowerInvariant()
				$hashedPath = Join-Path $Directory "$hash.tar.gz"
				Move-Item -LiteralPath $rawPath -Destination $hashedPath -Force
				return $hashedPath
			} finally { $tar.Dispose() }
		}
	}
	AfterAll {
		if (Test-Path -LiteralPath $ToolchainPath) {
			$deletePath = if ($isWindowsPlatform) { "\\?\$ToolchainPath" } else { $ToolchainPath }
			[IO.Directory]::Delete($deletePath, $true)
		}
	}
	It "Extracts" {
		$tgz | ExtractTarGz -Digest '1234567890ab'
		$pkg = ResolvePackagePath '_'
		Get-Content (Join-Path $pkg 'file.txt') -Raw | Should -Be 'A'
		Get-Content (Join-Path $pkg 'empty.txt') -Raw | Should -Be $null
		$longParent = Join-Path (Join-Path (Join-Path $pkg 'nested') 'Some-Really-Long-Folder-Name----------------------------------------------------------------------------------------------------') 'Some-Really-Long-Folder-Name-----------------------------------------------------'
		$longFile = Join-Path $longParent 'a.txt'
		$readPath = if ($isWindowsPlatform) { "\\?\$longFile" } else { $longFile }
		[IO.File]::ReadAllText($readPath) | Should -Be 'xyz'
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
			(Get-Content -LiteralPath (Join-Path (Join-Path $pkg 'etc') 'marker.txt') -Raw) | Should -Be 'ok'
		} finally {
			if (Test-Path -LiteralPath $work) {
				Remove-Item -LiteralPath $work -Recurse -Force
			}
		}
	}

	It 'rejects a symlink target that escapes the package root' {
		$work = Join-Path $root ("bad-link-" + [Guid]::NewGuid().ToString('N'))
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(@{ Name='pivot'; Type='2'; Link='../escape.txt' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('1' * 64)) } | Should -Throw '*link target escapes root*'
			Test-Path -LiteralPath (Join-Path $ToolchainPath 'escape.txt') | Should -BeFalse
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'does not write through a pre-existing junction inside the package root' {
		$work = Join-Path $root ("junction-" + [Guid]::NewGuid().ToString('N'))
		$pkg = ResolvePackagePath '_'
		$outside = Join-Path $work 'outside'
		$pivot = Join-Path $pkg 'pivot'
		try {
			New-Item -ItemType Directory -Path $pkg, $outside -Force | Out-Null
			$linkType = if ($isWindowsPlatform) { 'Junction' } else { 'SymbolicLink' }
			New-Item -ItemType $linkType -Path $pivot -Target $outside | Out-Null
			$archive = New-TestTarGz -Directory (Join-Path $work 'archive') -Entries @(@{ Name='pivot/escaped.txt'; Type='0'; Data='escape' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('5' * 64)) } | Should -Throw '*traverses a link or reparse point*'
			Test-Path -LiteralPath (Join-Path $outside 'escaped.txt') | Should -BeFalse
		} finally {
			Remove-Item -LiteralPath $pivot -Force -ErrorAction SilentlyContinue
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'does not extract through a package root that is itself a junction' {
		$work = Join-Path $root ("root-junction-" + [Guid]::NewGuid().ToString('N'))
		$outside = Join-Path $work 'outside'
		$junctionRoot = Join-Path $work 'package-root'
		try {
			New-Item -ItemType Directory -Path $outside -Force | Out-Null
			$linkType = if ($isWindowsPlatform) { 'Junction' } else { 'SymbolicLink' }
			New-Item -ItemType $linkType -Path $junctionRoot -Target $outside | Out-Null
			Mock ResolvePackagePath { $junctionRoot }
			$archive = New-TestTarGz -Directory (Join-Path $work 'archive') -Entries @(@{ Name='escaped.txt'; Type='0'; Data='escape' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('6' * 64)) } | Should -Throw '*root path is a link or reparse point*'
			Test-Path -LiteralPath (Join-Path $outside 'escaped.txt') | Should -BeFalse
		} finally {
			if (Test-Path -LiteralPath $junctionRoot) {
				if ($PSVersionTable.PSEdition -eq 'Desktop') {
					[IO.Directory]::Delete($junctionRoot)
				} else {
					Remove-Item -LiteralPath $junctionRoot -Force -ErrorAction SilentlyContinue
				}
			}
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'rejects OCI whiteouts instead of silently producing an incorrect layer merge' {
		$work = Join-Path $root ("whiteout-" + [Guid]::NewGuid().ToString('N'))
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(@{ Name='Files/bin/.wh.deleted.exe'; Type='3' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('4' * 64)) } | Should -Throw '*OCI whiteout entries are not supported*'
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'rejects truncated entry data without padding the destination with zeros' {
		$work = Join-Path $root ("truncated-" + [Guid]::NewGuid().ToString('N'))
		$pkg = ResolvePackagePath '_'
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(@{ Name='truncated.bin'; Type='0'; Size=10; Data='xx' }) -OmitEndMarker -TruncateEntryData
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('2' * 64)) } | Should -Throw '*truncated tar input*'
			$dest = Join-Path $pkg 'truncated.bin'
			if (Test-Path -LiteralPath $dest) { (Get-Item -LiteralPath $dest).Length | Should -Be 0 }
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'enforces the extracted-byte quota before writing an oversized entry' {
		$work = Join-Path $root ("oversized-" + [Guid]::NewGuid().ToString('N'))
		$oldLimit = $env:TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES
		try {
			$env:TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES = '3'
			$archive = New-TestTarGz -Directory $work -Entries @(@{ Name='too-big.bin'; Type='0'; Data='four' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('3' * 64)) } | Should -Throw '*exceeds extraction limit*'
			Test-Path -LiteralPath (Join-Path (ResolvePackagePath '_') 'too-big.bin') | Should -BeFalse
		} finally {
			$env:TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES = $oldLimit
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}
}
