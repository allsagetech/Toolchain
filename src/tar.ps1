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
	return [Convert]::ToInt64($ASCII, 8)
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
	[void]([Util]::GzipRead($Source, $buf, $Header.Size))
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

function ExtractTarGz {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Path,
		[Parameter(Mandatory)]
		[string]$Digest
	)
	$tgz = $Path | Split-Path -Leaf
	$layerId = $tgz.Replace('.tar.gz', '')
	if ($layerId -ne (Get-FileHash $Path).Hash) {
		[IO.File]::Delete($Path)
		throw "removed $Path because it had corrupted data"
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

	$root = ResolvePackagePath -Digest $Digest
	MakeDirIfNotExist -Path $root | Out-Null

	$rootFull = [IO.Path]::GetFullPath($root)
	if (-not $rootFull.EndsWith([IO.Path]::DirectorySeparatorChar)) {
		$rootFull += [IO.Path]::DirectorySeparatorChar
	}

	$buffer = New-Object byte[] 512
	$ioBuf  = New-Object byte[] 65536
	$xhdr = $null

	function Skip-Byte([int64]$count) {
		$remaining = $count
		while ($remaining -gt 0) {
			$n = [int][Math]::Min($ioBuf.Length, $remaining)
			[void]([Util]::GzipRead($Source, $ioBuf, $n))
			$remaining -= $n
		}
	}

	function Get-SafeDest([string]$relativePath) {
		if (-not $relativePath) { return $null }

		if ($relativePath -match '^[\/]' -or $relativePath -match '^[A-Za-z]:' ) {
			throw "suspicious tar path '$relativePath'"
		}
		$segments = $relativePath -split '[\/]' | Where-Object { $_ -ne '' }
		if ($segments -contains '..') { throw "suspicious tar path '$relativePath'" }

		$dest = [IO.Path]::GetFullPath((Join-Path $rootFull $relativePath))
		if (-not $dest.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
			throw "tar path escapes root: '$relativePath'"
		}
		return $dest
	}

	try {
		while ($true) {
			{ $LayerId.Substring(0, 12) + ': Extracting ' + (GetProgress -Current $Source.BaseStream.Position -Total $Source.BaseStream.Length) + '   ' } | WritePeriodicConsole

			if ([Util]::GzipRead($Source, $buffer, 512) -eq 0) { break }

			$hdr = ParseTarHeader $buffer
			$size = if ($xhdr -and $xhdr.Size) { [int64]$xhdr.Size } else { [int64]$hdr.Size }
			$filename = if ($xhdr -and $xhdr.Path) { [string]$xhdr.Path } else { [string]$hdr.Filename }

			$file = ($filename -split '/' | Select-Object -Skip 1) -join '\'

			if ($hdr.Type -eq [char]53 -and $file -ne '') {
				$dest = Get-SafeDest $file
				New-Item -Path ("\\?\$dest") -ItemType Directory -Force -ErrorAction Ignore | Out-Null
				$xhdr = $null
			} elseif ($hdr.Type -in [char]103, [char]120) {
				$xhdr = ParsePaxHeader -Source $Source -Header $hdr
			} elseif ($hdr.Type -in [char]0, [char]48, [char]55 -and $filename.StartsWith('Files')) {
				$dest = Get-SafeDest $file
				if ($null -eq $dest) {
					Skip-Byte $size
					$xhdr = $null
				} else {
					$parent = Split-Path $dest -Parent
					if ($parent) {
						New-Item -Path ("\\?\$parent") -ItemType Directory -Force -ErrorAction Ignore | Out-Null
					}

					$fs = [IO.File]::Open("\\?\$dest", [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
					try {
						$remaining = $size
						while ($remaining -gt 0) {
							$n = [int][Math]::Min($ioBuf.Length, $remaining)
							[void]([Util]::GzipRead($Source, $ioBuf, $n))
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

			$leftover = $size % 512
			if ($leftover -gt 0) {
				Skip-Byte (512 - $leftover)
			}
		}
	} finally {}

	$LayerId.Substring(0, 12) + ': Extracting ' + (GetProgress -Current $Source.BaseStream.Length -Total $Source.BaseStream.Length) + '   ' | WriteConsole
}

