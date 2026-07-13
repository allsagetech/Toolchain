<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\config.ps1
. $PSScriptRoot\progress.ps1

function FromOctalString {
	param (
		[Parameter(ValueFromPipeline)]
		[string]$ASCII
	)
	if (-not $ASCII) {
		return $null
	}
	$normalized = $ASCII.Replace([string][char]0, '').Trim()
	if (-not $normalized) {
		return $null
	}
	return [Convert]::ToInt64($normalized, 8)
}

function ParseTarHeader {
	param (
		[Parameter(Mandatory)]
		[byte[]]$Buffer
	)
	return @{
		Filename = [Text.Encoding]::ASCII.GetString($Buffer[0..99]).Trim(0)
		Mode = [Text.Encoding]::ASCII.GetString($Buffer[100..107]).Trim(0) | FromOctalString
		OwnerID = [Text.Encoding]::ASCII.GetString($Buffer[108..115]).Trim(0) | FromOctalString
		GroupID = [Text.Encoding]::ASCII.GetString($Buffer[116..123]).Trim(0) | FromOctalString
		Size = [Text.Encoding]::ASCII.GetString($Buffer[124..135]).Trim(0) | FromOctalString
		Modified = [Text.Encoding]::ASCII.GetString($Buffer[136..147]).Trim(0) | FromOctalString
		Checksum = [Text.Encoding]::ASCII.GetString($Buffer[148..155])
		Type = [Text.Encoding]::ASCII.GetString($Buffer[156..156]).Trim(0)
		Link = [Text.Encoding]::ASCII.GetString($Buffer[157..256]).Trim(0)
		UStar = [Text.Encoding]::ASCII.GetString($Buffer[257..262]).Trim(0)
		UStarVersion = [Text.Encoding]::ASCII.GetString($Buffer[263..264]).Trim(0)
		Owner = [Text.Encoding]::ASCII.GetString($Buffer[265..296]).Trim(0)
		Group = [Text.Encoding]::ASCII.GetString($Buffer[297..328]).Trim(0)
		DeviceMajor = [Text.Encoding]::ASCII.GetString($Buffer[329..336]).Trim(0)
		DeviceMinor = [Text.Encoding]::ASCII.GetString($Buffer[337..344]).Trim(0)
		FilenamePrefix = [Text.Encoding]::ASCII.GetString($Buffer[345..499]).Trim(0)
	}
}

function ParsePaxHeader {
	param (
		[Parameter(Mandatory)]
		[IO.Compression.GZipStream]$Source,
		[Parameter(Mandatory)]
		[Collections.Hashtable]$Header
	)
	if ($Header.Size -gt 1048576) {
		throw "pax header too large ($($Header.Size) bytes)"
	}
	$buf = New-Object byte[] $Header.Size
	[Util]::GzipReadExact($Source, $buf, [int]$Header.Size, 'pax header')
	$content = [Text.Encoding]::UTF8.GetString($buf)
	$xhdr = @{}
	foreach ($line in $content -split "`n") {
		if ($line -match '([0-9]+) ([^=]+)=(.+)') {
			$xhdr += @{
				"$($Matches[2])" = $Matches[3]
			}
		}
	}
	return $xhdr
}

function Get-ToolchainArchiveLimit {
	param(
		[Parameter(Mandatory)][string]$EnvironmentName,
		[Parameter(Mandatory)][long]$Default
	)
	$value = [Environment]::GetEnvironmentVariable($EnvironmentName, [EnvironmentVariableTarget]::Process)
	if (-not $value) { return $Default }
	$parsed = 0L
	if (-not [long]::TryParse([string]$value, [ref]$parsed) -or $parsed -le 0) {
		throw "invalid ${EnvironmentName}='$value' (expected a positive integer)"
	}
	return $parsed
}

function ExtractTarGz {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Path,
		[Parameter(Mandatory)]
		[string]$Digest
	)
	$tgz = $Path | Split-Path -Leaf
	$layerId = $tgz.Replace('.tar.gz', '')
	if ($layerId -notmatch '^[0-9a-fA-F]{64}$' -or $layerId -ine (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash) {
		[IO.File]::Delete($Path)
		throw "removed $Path because it had corrupted data"
	}
	$maxLayerBytes = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_LAYER_BYTES' -Default 8589934592
	if ((Get-Item -LiteralPath $Path).Length -gt $maxLayerBytes) {
		throw "compressed layer exceeds TOOLCHAIN_MAX_LAYER_BYTES ($maxLayerBytes bytes)"
	}
	$fs = [IO.File]::OpenRead($Path)
	try {
		$gz = [IO.Compression.GZipStream]::new($fs, [IO.Compression.CompressionMode]::Decompress)
		try {
			$gz | ExtractTar -Digest $Digest -LayerId $layerId
		} finally {
			$gz.Dispose()
		}
	} finally {
		$fs.Dispose()
	}
}


class Util {
	static [int] GzipRead([IO.Compression.GZipStream]$Source, [byte[]]$Buffer, [int]$Size) {
		$read = 0
		while ($true) {
			$n = $Source.Read($buffer, $read, $Size - $read)
			$read += $n
			if ($n -eq 0) {
				break
			} elseif ($read -ge $size) {
				break
			}
		}
		return $read
	}

	static [void] GzipReadExact([IO.Compression.GZipStream]$Source, [byte[]]$Buffer, [int]$Size, [string]$Context) {
		$read = [Util]::GzipRead($Source, $Buffer, $Size)
		if ($read -ne $Size) {
			throw "truncated tar input while reading $Context (expected $Size bytes, got $read)"
		}
	}
}

function ExtractTar {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[IO.Compression.GZipStream]$Source,
		[Parameter(Mandatory)]
		[string]$Digest,
		[Parameter(Mandatory)]
		[string]$LayerId
	)

	$isWindowsPlatform = $false
	if ($PSVersionTable.PSEdition -eq 'Desktop') {
		$isWindowsPlatform = $true
	} elseif (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
		$isWindowsPlatform = [bool]$IsWindows
	}

	function Get-PlatformPath {
		param([string]$Path)
		if ($isWindowsPlatform -and $Path -and $Path.Length -ge 248) {
			return "\\?\$Path"
		}
		return $Path
	}

	$root = ResolvePackagePath -Digest $Digest
	MakeDirIfNotExist -Path $root | Out-Null

	$rootFull = [IO.Path]::GetFullPath($root)
	if (-not $rootFull.EndsWith([IO.Path]::DirectorySeparatorChar)) {
		$rootFull += [IO.Path]::DirectorySeparatorChar
	}

	$buffer = New-Object byte[] 512
	$ioBuf  = New-Object byte[] 65536
	$xhdr = $null
	$gnuLongPath = $null
	$gnuLongLink = $null
	$entryCount = 0L
	$totalExtracted = 0L
	$pathComparison = if ($isWindowsPlatform) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
	$pathComparer = if ($isWindowsPlatform) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
	$pendingHardLinksByTarget = [Collections.Generic.Dictionary[string,Collections.Generic.List[object]]]::new($pathComparer)
	$latestEntryForPath = [Collections.Generic.Dictionary[string,long]]::new($pathComparer)
	$hardLinkState = @{ PendingCount = 0L }
	$maxEntries = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_ARCHIVE_ENTRIES' -Default 1000000
	$maxPendingHardLinks = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_PENDING_HARD_LINKS' -Default 10000
	$maxExtracted = Get-ToolchainArchiveLimit -EnvironmentName 'TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES' -Default 34359738368
	$sawEndMarker = $false

	function Skip-Byte([int64]$count) {
		$remaining = $count
		while ($remaining -gt 0) {
			$n = [int][Math]::Min([int64]$ioBuf.Length, [int64]$remaining)
			[Util]::GzipReadExact($Source, $ioBuf, $n, 'entry data')
			$remaining -= $n
		}
	}

	function Get-SafeDest([string]$relativePath) {
		if (-not $relativePath) { return $null }
		try {
			return Resolve-ToolchainChildPath -Root $rootFull -RelativePath $relativePath -RejectReparsePoints -RejectRootReparsePoint
		} catch {
			throw "unsafe tar path '$relativePath': $($_.Exception.Message)"
		}
	}

	function Get-SafeLinkTarget([string]$dest, [string]$linkTarget) {
		if ([string]::IsNullOrWhiteSpace($linkTarget) -or [IO.Path]::IsPathRooted($linkTarget) -or $linkTarget -match '^[\\/]' -or $linkTarget -match ':') {
			throw "unsafe tar link target '$linkTarget'"
		}
		$parent = Split-Path $dest -Parent
		$combined = [IO.Path]::GetFullPath((Join-Path $parent $linkTarget))
		if (-not $combined.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
			throw "tar link target escapes root: '$linkTarget'"
		}
		return $combined
	}

	function Parse-GnuLongString([int64]$sizeBytes) {
		if ($sizeBytes -gt 1048576) {
			throw "gnu long header too large ($sizeBytes bytes)"
		}
		if ($sizeBytes -le 0) {
			return ''
		}
		$buf = New-Object byte[] $sizeBytes
		[Util]::GzipReadExact($Source, $buf, [int]$sizeBytes, 'GNU long header')
		$str = [Text.Encoding]::UTF8.GetString($buf)
		return $str.Trim([char]0).TrimEnd("`r", "`n")
	}

	function Get-LayerRelativePath([string]$tarPath) {
		if (-not $tarPath) { return $null }
		$path = $tarPath.Trim()
		if ($path.StartsWith('./')) {
			$path = $path.Substring(2)
		}
		if (-not $path -or $path -eq '.') {
			return $null
		}
		if ($path -eq 'Files' -or $path -eq 'Files/') {
			return $null
		}
		if ($path.StartsWith('Files/')) {
			$path = $path.Substring('Files/'.Length)
		}
		if ($path.EndsWith('/')) {
			$path = $path.Substring(0, $path.Length - 1)
		}
		if (-not $path) {
			return $null
		}
		return $path.Replace('/', [IO.Path]::DirectorySeparatorChar)
	}

	function Get-HardLinkTargetRelativePath([string]$linkTarget) {
		if ([string]::IsNullOrWhiteSpace($linkTarget)) {
			throw "unsafe tar hard link target '$linkTarget'"
		}
		$targetRelativePath = Get-LayerRelativePath -tarPath $linkTarget
		if (-not $targetRelativePath) {
			throw "unsafe tar hard link target '$linkTarget'"
		}
		try {
			$null = Get-SafeDest -relativePath $targetRelativePath
		} catch {
			throw "unsafe tar hard link target '$linkTarget': $($_.Exception.Message)"
		}
		return $targetRelativePath
	}

	function Add-UnresolvedHardLink($link) {
		if ($hardLinkState.PendingCount -ge $maxPendingHardLinks) {
			throw "tar archive exceeds TOOLCHAIN_MAX_PENDING_HARD_LINKS ($maxPendingHardLinks unresolved links)"
		}
		if (-not $pendingHardLinksByTarget.ContainsKey($link.TargetKey)) {
			$pendingHardLinksByTarget[$link.TargetKey] = [Collections.Generic.List[object]]::new()
		}
		$pendingHardLinksByTarget[$link.TargetKey].Add($link)
		$hardLinkState.PendingCount += 1
	}

	function Try-CreatePendingHardLink($link) {
		if ($link.Complete) { return $false }
		if (-not $latestEntryForPath.ContainsKey($link.DestinationKey) -or
			$latestEntryForPath[$link.DestinationKey] -ne $link.Sequence) {
			$link.Complete = $true
			return $false
		}

		$dest = Get-SafeDest -relativePath $link.DestinationRelativePath
		try {
			$target = Get-SafeDest -relativePath $link.TargetRelativePath
		} catch {
			throw "unsafe tar hard link target '$($link.ArchiveTarget)': $($_.Exception.Message)"
		}
		if ([string]::Equals($dest, $target, $pathComparison)) {
			throw "tar hard link target '$($link.ArchiveTarget)' refers to itself"
		}

		$targetItem = Get-Item -LiteralPath (Get-PlatformPath $target) -Force -ErrorAction SilentlyContinue
		if (-not $targetItem) { return $false }
		if ($targetItem.PSIsContainer) {
			throw "tar hard link target '$($link.ArchiveTarget)' is not a regular file"
		}
		if ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
			throw "tar hard link target '$($link.ArchiveTarget)' is a link or reparse point"
		}

		$parent = Split-Path $dest -Parent
		if ($parent) {
			New-Item -Path (Get-PlatformPath $parent) -ItemType Directory -Force -ErrorAction Stop | Out-Null
		}
		# Revalidate after creating the parent so a pre-existing or raced
		# reparse point cannot redirect either side of the hard link.
		$dest = Get-SafeDest -relativePath $link.DestinationRelativePath
		try {
			$target = Get-SafeDest -relativePath $link.TargetRelativePath
		} catch {
			throw "unsafe tar hard link target '$($link.ArchiveTarget)': $($_.Exception.Message)"
		}
		$targetItem = Get-Item -LiteralPath (Get-PlatformPath $target) -Force -ErrorAction SilentlyContinue
		if (-not $targetItem -or $targetItem.PSIsContainer -or
			($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
			throw "tar hard link target '$($link.ArchiveTarget)' is not a safe regular file"
		}

		try {
			New-Item -Path (Get-PlatformPath $dest) -ItemType HardLink -Target (Get-PlatformPath $target) -ErrorAction Stop | Out-Null
		} catch {
			throw "failed to create tar hard link '$($link.ArchivePath)' to '$($link.ArchiveTarget)': $($_.Exception.Message)"
		}
		$link.Complete = $true
		if ($latestEntryForPath.ContainsKey($link.DestinationKey) -and
			$latestEntryForPath[$link.DestinationKey] -eq $link.Sequence) {
			$null = $latestEntryForPath.Remove($link.DestinationKey)
		}
		return $true
	}

	function Resolve-PendingHardLinks([string[]]$AvailablePathKeys = @(), [switch]$Final) {
		$queue = [Collections.Generic.Queue[string]]::new()
		$queued = [Collections.Generic.HashSet[string]]::new($pathComparer)
		$seedPaths = @($AvailablePathKeys)
		if ($Final) { $seedPaths += @($pendingHardLinksByTarget.Keys) }
		foreach ($path in $seedPaths) {
			if ($path -and $queued.Add($path)) { $queue.Enqueue($path) }
		}

		while ($queue.Count -gt 0) {
			$availablePath = $queue.Dequeue()
			$null = $queued.Remove($availablePath)
			if (-not $pendingHardLinksByTarget.ContainsKey($availablePath)) { continue }

			$links = $pendingHardLinksByTarget[$availablePath]
			$null = $pendingHardLinksByTarget.Remove($availablePath)
			$hardLinkState.PendingCount -= $links.Count
			foreach ($link in $links) {
				if ($link.Complete) { continue }
				$created = Try-CreatePendingHardLink -link $link
				if ($created) {
					if ($queued.Add($link.DestinationKey)) {
						$queue.Enqueue($link.DestinationKey)
					}
				} elseif (-not $link.Complete) {
					Add-UnresolvedHardLink -link $link
				}
			}
		}

		if ($Final) {
			$unresolved = $null
			foreach ($links in $pendingHardLinksByTarget.Values) {
				if ($links.Count -gt 0) {
					$unresolved = $links[0]
					break
				}
			}
			if ($unresolved) {
				$link = $unresolved
				throw "tar hard link target '$($link.ArchiveTarget)' for '$($link.ArchivePath)' was not extracted"
			}
		}
	}

	try {
		while ($true) {
			{ $LayerId.Substring(0, 12) + ': Extracting ' + (GetProgress -Current $Source.BaseStream.Position -Total $Source.BaseStream.Length) + '   ' } | WritePeriodicConsole

			$headerBytes = [Util]::GzipRead($Source, $buffer, 512)
			if ($headerBytes -eq 0) { break }
			if ($headerBytes -ne 512) {
				throw "truncated tar input while reading header (expected 512 bytes, got $headerBytes)"
			}
			$allZero = $true
			foreach ($b in $buffer) {
				if ($b -ne 0) { $allZero = $false; break }
			}
			if ($allZero) {
				$secondEndBlock = New-Object byte[] 512
				[Util]::GzipReadExact($Source, $secondEndBlock, 512, 'second tar end marker')
				foreach ($b in $secondEndBlock) {
					if ($b -ne 0) { throw 'invalid tar end marker' }
				}
				$sawEndMarker = $true
				break
			}

			$entryCount += 1
			if ($entryCount -gt $maxEntries) {
				throw "tar archive exceeds TOOLCHAIN_MAX_ARCHIVE_ENTRIES ($maxEntries entries)"
			}

			$hdr = ParseTarHeader $buffer
			$size = if ($xhdr -and $xhdr.Size) { [int64]$xhdr.Size } else { [int64]$hdr.Size }
			if ($size -lt 0 -or $size -gt $maxExtracted) {
				throw "tar entry size $size exceeds extraction limit $maxExtracted"
			}
			$filename = if ($gnuLongPath) {
				[string]$gnuLongPath
			} elseif ($xhdr -and $xhdr.Path) {
				[string]$xhdr.Path
			} else {
				$headerName = [string]$hdr.Filename
				if ($hdr.FilenamePrefix) {
					$prefix = [string]$hdr.FilenamePrefix
					$headerName = if ($prefix.EndsWith('/')) { "$prefix$headerName" } else { "$prefix/$headerName" }
				}
				$headerName
			}
			$relativePath = Get-LayerRelativePath -tarPath $filename
			if ($relativePath) {
				$leafName = Split-Path $relativePath -Leaf
				if ($leafName -like '.wh.*') {
					throw "OCI whiteout entries are not supported: '$filename'"
				}
			}
			$pathKey = $null
			if ($relativePath -and $hdr.Type -in [char]0, [char]48, [char]49, [char]50, [char]53, [char]55) {
				$pathKey = Get-SafeDest -relativePath $relativePath
				if ($hdr.Type -eq [char]49 -or $latestEntryForPath.ContainsKey($pathKey)) {
					$latestEntryForPath[$pathKey] = $entryCount
				}
			}

			if ($hdr.Type -eq [char]76 -or $hdr.Type -eq [char]75) {
				$longVal = Parse-GnuLongString -sizeBytes $size
				if ($hdr.Type -eq [char]76) {
					$gnuLongPath = $longVal
				} else {
					$gnuLongLink = $longVal
				}
				$xhdr = $null
			} elseif ($hdr.Type -eq [char]53 -and $relativePath) {
				$dest = Get-SafeDest $relativePath
				New-Item -Path (Get-PlatformPath $dest) -ItemType Directory -Force -ErrorAction Ignore | Out-Null
				$xhdr = $null
			} elseif ($hdr.Type -in [char]103, [char]120) {
				$xhdr = ParsePaxHeader -Source $Source -Header $hdr
			} elseif ($hdr.Type -eq [char]50) {
				$dest = Get-SafeDest $relativePath
				if ($null -eq $dest) {
					$xhdr = $null
				} else {
					$linkTarget = if ($gnuLongLink) {
						[string]$gnuLongLink
					} elseif ($xhdr -and $xhdr.Linkpath) {
						[string]$xhdr.Linkpath
					} else {
						[string]$hdr.Link
					}
					if ($linkTarget) {
						$safeLinkTarget = Get-SafeLinkTarget -dest $dest -linkTarget $linkTarget
						$parent = Split-Path $dest -Parent
						if ($parent) {
							New-Item -Path (Get-PlatformPath $parent) -ItemType Directory -Force -ErrorAction Ignore | Out-Null
						}
						if (Test-Path -LiteralPath $dest) {
							Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
						}
						if ($isWindowsPlatform) {
							try {
								New-Item -Path (Get-PlatformPath $dest) -ItemType SymbolicLink -Target (Get-PlatformPath $safeLinkTarget) -Force -ErrorAction Stop | Out-Null
							} catch {
								Write-Debug "Skipping symlink '$relativePath' on Windows: $($_.Exception.Message)"
							}
						} else {
							New-Item -Path (Get-PlatformPath $dest) -ItemType SymbolicLink -Target $safeLinkTarget -Force | Out-Null
						}
					}
					$xhdr = $null
				}
			} elseif ($hdr.Type -eq [char]49) {
				if (-not $relativePath) {
					throw "invalid tar hard link path '$filename'"
				}
				if ($size -ne 0) {
					throw "invalid tar hard link entry '$filename': expected zero size, got $size"
				}
				$linkTarget = if ($gnuLongLink) {
					[string]$gnuLongLink
				} elseif ($xhdr -and $xhdr.Linkpath) {
					[string]$xhdr.Linkpath
				} else {
					[string]$hdr.Link
				}
				$targetRelativePath = Get-HardLinkTargetRelativePath -linkTarget $linkTarget
				$targetKey = Get-SafeDest -relativePath $targetRelativePath
				$dest = Get-SafeDest -relativePath $relativePath
				$existingDest = Get-Item -LiteralPath (Get-PlatformPath $dest) -Force -ErrorAction SilentlyContinue
				if ($existingDest) {
					if ($existingDest.PSIsContainer) {
						throw "tar hard link destination '$filename' is a directory"
					}
					Remove-Item -LiteralPath (Get-PlatformPath $dest) -Force -ErrorAction Stop
				}
				$dest = Get-SafeDest -relativePath $relativePath
				$link = [pscustomobject]@{
					ArchivePath = $filename
					ArchiveTarget = $linkTarget
					DestinationRelativePath = $relativePath
					TargetRelativePath = $targetRelativePath
					DestinationKey = $pathKey
					TargetKey = $targetKey
					Sequence = $entryCount
					Complete = $false
				}
				if (Try-CreatePendingHardLink -link $link) {
					Resolve-PendingHardLinks -AvailablePathKeys @($pathKey)
				} elseif (-not $link.Complete) {
					Add-UnresolvedHardLink -link $link
				}
				$xhdr = $null
			} elseif ($hdr.Type -in [char]0, [char]48, [char]55) {
				$dest = Get-SafeDest $relativePath
				$totalExtracted += $size
				if ($totalExtracted -gt $maxExtracted) {
					throw "tar archive exceeds TOOLCHAIN_MAX_EXTRACTED_LAYER_BYTES ($maxExtracted bytes)"
				}
				if ($null -eq $dest) {
					Skip-Byte $size
					$xhdr = $null
				} else {
					$parent = Split-Path $dest -Parent
					if ($parent) {
						New-Item -Path (Get-PlatformPath $parent) -ItemType Directory -Force -ErrorAction Ignore | Out-Null
					}

					$existingDest = Get-Item -LiteralPath (Get-PlatformPath $dest) -Force -ErrorAction SilentlyContinue
					if ($existingDest) {
						if ($existingDest.PSIsContainer) {
							throw "tar entry '$filename' cannot replace a directory"
						}
						Remove-Item -LiteralPath (Get-PlatformPath $dest) -Force -ErrorAction Stop
					}
					$dest = Get-SafeDest $relativePath
					try {
						$fs = [IO.File]::Open((Get-PlatformPath $dest), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
					} catch {
						throw "failed to open tar entry '$filename' (type '$($hdr.Type)', relative '$relativePath', size $size) at '$dest': $($_.Exception.Message)"
					}
					try {
						$remaining = $size
						while ($remaining -gt 0) {
							$n = [int][Math]::Min([int64]$ioBuf.Length, [int64]$remaining)
							[Util]::GzipReadExact($Source, $ioBuf, $n, "tar entry '$filename'")
							$fs.Write($ioBuf, 0, $n)
							$remaining -= $n
						}
					} finally {
						$fs.Dispose()
					}
					$xhdr = $null
				}
			} else {
				if ($size -gt 0) { Skip-Byte $size }
				$xhdr = $null
			}

			if ($hdr.Type -ne [char]76 -and $hdr.Type -ne [char]75) {
				$gnuLongPath = $null
				$gnuLongLink = $null
			}

			$leftover = $size % 512
			if ($leftover -gt 0) {
				Skip-Byte (512 - $leftover)
			}
			if ($relativePath -and $hdr.Type -in [char]0, [char]48, [char]50, [char]53, [char]55) {
				Resolve-PendingHardLinks -AvailablePathKeys @($pathKey)
			}
		}
	} finally {}
	if (-not $sawEndMarker) {
		throw 'truncated tar input: missing end marker'
	}
	Resolve-PendingHardLinks -Final

	$LayerId.Substring(0, 12) + ': Extracting ' + (GetProgress -Current $Source.BaseStream.Length -Total $Source.BaseStream.Length) + '   ' | WriteConsole
}

