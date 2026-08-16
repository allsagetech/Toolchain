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

		function Remove-TestDirectoryLink([string]$Path) {
			if (-not (Test-Path -LiteralPath $Path)) { return }
			if ($PSVersionTable.PSEdition -eq 'Desktop') {
				[IO.Directory]::Delete($Path)
			} else {
				Remove-Item -LiteralPath $Path -Force
			}
		}

		function New-TestTarGz([string]$Directory, [object[]]$Entries, [switch]$OmitEndMarker, [switch]$TruncateEntryData) {
			New-Item -ItemType Directory -Path $Directory -Force | Out-Null
			$tar = [IO.MemoryStream]::new()
			try {
				foreach ($entry in $Entries) {
					$data = if ($null -ne $entry.Data) { [Text.Encoding]::UTF8.GetBytes([string]$entry.Data) } else { [byte[]]@() }
					$declaredSize = if ($null -ne $entry.Size) { [long]$entry.Size } else { [long]$data.Length }
					$mode = if ($null -ne $entry.Mode) { [int]$entry.Mode } else { 420 }
					$header = New-Object byte[] 512
					Set-TarAsciiField $header 0 100 ([string]$entry.Name)
					Set-TarAsciiField $header 100 8 (([Convert]::ToString($mode, 8)).PadLeft(7, '0') + [char]0)
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

	It 'preserves Unix execute permissions from regular-file headers' {
		if ($isWindowsPlatform) { return }
		$work = Join-Path $root ("unix-mode-" + [Guid]::NewGuid().ToString('N'))
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(
				@{ Name='bin/toolchain-mode-test'; Type='0'; Mode=493; Data="#!/bin/sh`nexit 0`n" }
			)
			$archive | ExtractTarGz -Digest ('sha256:' + ('e' * 64))
			$executable = Join-Path (Join-Path (ResolvePackagePath '_') 'bin') 'toolchain-mode-test'
			& $executable
			$LASTEXITCODE | Should -Be 0
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'extracts hard links emitted by the platform tar command' {
		$work = Join-Path $root ("native-hard-link-" + [Guid]::NewGuid().ToString('N'))
		$layer = Join-Path $work 'layer'
		$pkg = ResolvePackagePath '_'
		try {
			New-Item -ItemType Directory -Path $layer -Force | Out-Null
			Set-Content -LiteralPath (Join-Path $layer 'native-target.txt') -Value 'native' -NoNewline
			New-Item -ItemType HardLink -Path (Join-Path $layer 'native-alias.txt') -Target (Join-Path $layer 'native-target.txt') | Out-Null
			$tgzPath = Join-Path $work 'layer.tar.gz'
			tar -czf $tgzPath -C $layer . | Out-Null
			$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tgzPath).Hash.ToLowerInvariant()
			$archive = Join-Path $work "$hash.tar.gz"
			Move-Item -LiteralPath $tgzPath -Destination $archive -Force

			$archive | ExtractTarGz -Digest ('sha256:' + ('d' * 64))
			$target = Join-Path $pkg 'native-target.txt'
			$alias = Join-Path $pkg 'native-alias.txt'
			[IO.File]::AppendAllText($target, '-updated')
			Get-Content -LiteralPath $alias -Raw | Should -Be 'native-updated'
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'extracts forward OCI hard links as true hard links' {
		$work = Join-Path $root ("hard-link-" + [Guid]::NewGuid().ToString('N'))
		$pkg = ResolvePackagePath '_'
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(
				@{ Name='Files/hardlinks/chained.txt'; Type='1'; Link='Files/hardlinks/alias.txt' },
				@{ Name='Files/hardlinks/alias.txt'; Type='1'; Link='Files/hardlinks/target.txt' },
				@{ Name='Files/hardlinks/second.txt'; Type='1'; Link='Files/hardlinks/target.txt' },
				@{ Name='Files/hardlinks/target.txt'; Type='0'; Data='shared' }
			)
			$archive | ExtractTarGz -Digest ('sha256:' + ('7' * 64))
			$target = Join-Path (Join-Path $pkg 'hardlinks') 'target.txt'
			$alias = Join-Path (Join-Path $pkg 'hardlinks') 'alias.txt'
			$second = Join-Path (Join-Path $pkg 'hardlinks') 'second.txt'
			$chained = Join-Path (Join-Path $pkg 'hardlinks') 'chained.txt'
			Get-Content -LiteralPath $alias, $second, $chained -Raw | Should -Be @('shared', 'shared', 'shared')
			[IO.File]::AppendAllText($target, '-updated')
			Get-Content -LiteralPath $alias, $second, $chained -Raw | Should -Be @('shared-updated', 'shared-updated', 'shared-updated')
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'preserves archive ordering when hard links and regular files replace paths' {
		$work = Join-Path $root ("hard-link-order-" + [Guid]::NewGuid().ToString('N'))
		$pkg = ResolvePackagePath '_'
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(
				@{ Name='ordering/target.txt'; Type='0'; Data='old-target' },
				@{ Name='ordering/nested/alias.txt'; Type='0'; Data='placeholder' },
				@{ Name='ordering/nested/alias.txt'; Type='1'; Link='ordering/target.txt' },
				@{ Name='ordering/target.txt'; Type='0'; Data='new-target' },
				@{ Name='ordering//superseded.txt'; Type='1'; Link='ordering/future.txt' },
				@{ Name='ordering/superseded.txt'; Type='0'; Data='regular-wins' },
				@{ Name='ordering/future.txt'; Type='0'; Data='future' }
			)
			$archive | ExtractTarGz -Digest ('sha256:' + ('9' * 64))
			$ordering = Join-Path $pkg 'ordering'
			Get-Content -LiteralPath (Join-Path (Join-Path $ordering 'nested') 'alias.txt') -Raw | Should -Be 'old-target'
			Get-Content -LiteralPath (Join-Path $ordering 'target.txt') -Raw | Should -Be 'new-target'
			Get-Content -LiteralPath (Join-Path $ordering 'superseded.txt') -Raw | Should -Be 'regular-wins'
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'rejects a hard link target that escapes the package root' {
		$work = Join-Path $root ("bad-hard-link-" + [Guid]::NewGuid().ToString('N'))
		try {
			$archive = New-TestTarGz -Directory $work -Entries @(@{ Name='hardlinks/alias.txt'; Type='1'; Link='../escape.txt' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('8' * 64)) } | Should -Throw '*hard link target*'
			Test-Path -LiteralPath (Join-Path $ToolchainPath 'escape.txt') | Should -BeFalse
		} finally {
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
		}
	}

	It 'rejects invalid hard link entries and unresolved targets' {
		$cases = @(
			@{ Name='blank-target'; Entries=@(@{ Name='hardlinks/blank.txt'; Type='1' }); Pattern='*hard link target*' },
			@{ Name='root-target'; Entries=@(@{ Name='hardlinks/root.txt'; Type='1'; Link='Files/' }); Pattern='*hard link target*' },
			@{ Name='absolute-target'; Entries=@(@{ Name='hardlinks/absolute.txt'; Type='1'; Link='/outside.txt' }); Pattern='*hard link target*' },
			@{ Name='drive-target'; Entries=@(@{ Name='hardlinks/drive.txt'; Type='1'; Link='C:\outside.txt' }); Pattern='*hard link target*' },
			@{ Name='unc-target'; Entries=@(@{ Name='hardlinks/unc.txt'; Type='1'; Link='\\server\share\outside.txt' }); Pattern='*hard link target*' },
			@{ Name='mixed-traversal'; Entries=@(@{ Name='hardlinks/mixed.txt'; Type='1'; Link='safe\..\..\outside.txt' }); Pattern='*hard link target*' },
			@{ Name='root-path'; Entries=@(@{ Name='Files'; Type='1'; Link='target.txt' }); Pattern='*invalid tar hard link path*' },
			@{ Name='nonzero-size'; Entries=@(@{ Name='hardlinks/data.txt'; Type='1'; Link='target.txt'; Data='x' }); Pattern='*expected zero size*' },
			@{ Name='self-link'; Entries=@(@{ Name='hardlinks/self.txt'; Type='1'; Link='hardlinks/self.txt' }); Pattern='*refers to itself*' },
			@{ Name='missing-target'; Entries=@(@{ Name='hardlinks/missing.txt'; Type='1'; Link='hardlinks/not-there.txt' }); Pattern='*was not extracted*' },
			@{ Name='cycle'; Entries=@(@{ Name='hardlinks/a.txt'; Type='1'; Link='hardlinks/b.txt' }, @{ Name='hardlinks/b.txt'; Type='1'; Link='hardlinks/a.txt' }); Pattern='*was not extracted*' },
			@{ Name='directory-target'; Entries=@(@{ Name='hardlinks/directory'; Type='5' }, @{ Name='hardlinks/to-directory.txt'; Type='1'; Link='hardlinks/directory' }); Pattern='*not a regular file*' },
			@{ Name='directory-destination'; Entries=@(@{ Name='hardlinks/target.txt'; Type='0'; Data='target' }, @{ Name='hardlinks/destination'; Type='5' }, @{ Name='hardlinks/destination'; Type='1'; Link='hardlinks/target.txt' }); Pattern='*destination*directory*' }
		)
		foreach ($case in $cases) {
			$work = Join-Path $root ("bad-hard-link-$($case.Name)-" + [Guid]::NewGuid().ToString('N'))
			try {
				$archive = New-TestTarGz -Directory $work -Entries $case.Entries
				{ $archive | ExtractTarGz -Digest ('sha256:' + ('a' * 64)) } | Should -Throw $case.Pattern
			} finally {
				Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
			}
		}
	}

	It 'rejects a hard link target through a pre-existing reparse point' {
		$work = Join-Path $root ("hard-link-junction-" + [Guid]::NewGuid().ToString('N'))
		$pkg = ResolvePackagePath '_'
		$outside = Join-Path $work 'outside'
		$pivot = Join-Path $pkg 'pivot'
		try {
			New-Item -ItemType Directory -Path $pkg, $outside -Force | Out-Null
			Set-Content -LiteralPath (Join-Path $outside 'outside.txt') -Value 'outside' -NoNewline
			$linkType = if ($isWindowsPlatform) { 'Junction' } else { 'SymbolicLink' }
			New-Item -ItemType $linkType -Path $pivot -Target $outside | Out-Null
			$archive = New-TestTarGz -Directory (Join-Path $work 'archive') -Entries @(@{ Name='reparse-hardlinks/alias.txt'; Type='1'; Link='pivot/outside.txt' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('b' * 64)) } | Should -Throw '*hard link target*reparse point*'
			Test-Path -LiteralPath (Join-Path (Join-Path $pkg 'reparse-hardlinks') 'alias.txt') | Should -BeFalse

			Set-Content -LiteralPath (Join-Path $pkg 'safe-hard-link-target.txt') -Value 'safe' -NoNewline
			$archive = New-TestTarGz -Directory (Join-Path $work 'destination-archive') -Entries @(@{ Name='pivot/alias.txt'; Type='1'; Link='safe-hard-link-target.txt' })
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('c' * 64)) } | Should -Throw '*unsafe tar path*reparse point*'
			Test-Path -LiteralPath (Join-Path $outside 'alias.txt') | Should -BeFalse
		} finally {
			try {
				Remove-TestDirectoryLink -Path $pivot
			} finally {
				Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
			}
		}
	}

	It 'limits unresolved hard links independently of the archive entry limit' {
		$work = Join-Path $root ("hard-link-limit-" + [Guid]::NewGuid().ToString('N'))
		$oldLimit = $env:TOOLCHAIN_MAX_PENDING_HARD_LINKS
		try {
			$env:TOOLCHAIN_MAX_PENDING_HARD_LINKS = '1'
			$archive = New-TestTarGz -Directory $work -Entries @(
				@{ Name='limited/one.txt'; Type='1'; Link='limited/missing-one.txt' },
				@{ Name='limited/two.txt'; Type='1'; Link='limited/missing-two.txt' }
			)
			{ $archive | ExtractTarGz -Digest ('sha256:' + ('e' * 64)) } | Should -Throw '*TOOLCHAIN_MAX_PENDING_HARD_LINKS*'
		} finally {
			$env:TOOLCHAIN_MAX_PENDING_HARD_LINKS = $oldLimit
			Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
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
			try {
				Remove-TestDirectoryLink -Path $pivot
			} finally {
				Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
			}
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
