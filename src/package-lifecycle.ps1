<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

function InstallPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	$digest = $Pkg.Digest
	$name = $Pkg.Package
	$tag = $Pkg.Tag | AsTagString
	$locks = @()
	$mLock, $err = [Db]::TryLock(('metadatadb', $digest))
	if ($err) {
		throw "package '$digest' is in use by another toolchain process"
	}
	$locks += $mLock
	$pLock, $err = [Db]::TryLock(('pkgdb', $name, $tag))
	if ($err) {
		$locks.Revert()
		throw "package '${name}:$tag' is in use by another toolchain process"
	}
	$locks += $pLock
	$p = $pLock.Get()
	$m = $mLock.Get() | ConvertTo-HashTable
	$status = if ($null -eq $p) {
		if ($null -eq $m) {
			'new'
		} else {
			'tag'
		}
	} elseif ($digest -ne $p) {
		if ($null -eq $m) {
			'newer'
		} else {
			'ref'
		}
	} else {
		'uptodate'
	}
	$pLock.Put($digest)
	switch ($status) {
		{$_ -in 'new', 'newer'} {
			$mLock.Put(@{
				RefCount = 1
				Version = $Pkg.Version
				Size = $Pkg.Size
				Updated = [datetime]::UtcNow.ToString()
			})
		}
		{$_ -in 'newer', 'ref'} {
			$moLock, $err = [Db]::TryLock(('metadatadb', $p))
			if ($err) {
				$locks.Revert()
				throw "package '$p' is in use by another toolchain process"
			}
			$locks += $moLock
			$mo = $moLock.Get() | ConvertTo-HashTable
			$mo.RefCount -= 1
			if ($mo.RefCount -eq 0) {
				$poLock, $err = [Db]::TryLock(('pkgdb', $name, $p))
				if ($err) {
					$locks.Revert()
					throw "package '$p' is in use by another toolchain process"
				}
				$locks += $poLock
				$poLock.Put($null)
				$mo.Orphaned = [datetime]::UtcNow.ToString('u')
			}
			$moLock.Put($mo)
		}
		{$_ -in 'tag', 'ref'} {
			if ([Db]::ContainsKey(('pkgdb', $name, $digest))) {
				$dLock, $err = [Db]::TryLock(('pkgdb', $name, $digest))
				if ($err) {
					$locks.Revert()
					throw "package '$digest' is in use by another toolchain process"
				}
				$locks += $dLock
				$dLock.Remove()
			}
			if ($m.RefCount -eq 0 -and $m.Orphaned) {
				$m.Remove('Orphaned')
			}
			$m.RefCount += 1
			$m.Updated = [datetime]::UtcNow.ToString()
			$mLock.Put($m)
		}
		'uptodate' {
			$m.Updated = [datetime]::UtcNow.ToString()
			$mLock.Put($m)
		}
	}
	return $locks, $status
}

function PullPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg,
		[string]$Output,
		[switch]$Sign
	)
	$tagStr = $Pkg.Tag | AsTagString
	$repoPath = GetToolchainRepo
	$regBase = if ($repoPath) { $null } else { GetRegistryBaseUrl }
	$repoName = if ($repoPath) { $null } else { GetRegistryRepoName }
	if (-not $repoPath) {
		Assert-ToolchainRegistryPolicyAllowed -Action $(if ($Output) { 'save' } else { 'pull' }) -RegistryBaseUrl $regBase -Repository $repoName
	}

	$dockerRef = $Pkg | ResolveDockerRef
	$manifest = $null
	try {
		$manifest = GetVerifiedManifestResponse -Ref $dockerRef
		$manifest | DebugRateLimit
		$digest = $manifest | GetDigest
		Write-ToolchainInfo "Pulling $($Pkg.Package):$($pkg.Tag | AsTagString)"
		Write-ToolchainInfo "Digest: $($digest)"

		if (-not $Pkg.Version -and -not $repoPath) {
			$cfg = GetImageConfigJsonFromRef -Ref $digest -ExpectedManifestDigest $digest
			$labels = $null
			if ($cfg -and $cfg.config -and $cfg.config.Labels) { $labels = $cfg.config.Labels }
			elseif ($cfg -and $cfg.Labels) { $labels = $cfg.Labels }
			if ($labels) {
				$ver = $labels.'io.allsagetech.toolchain.packageVersion'
				if (-not $ver) { $ver = $labels.'toolchain.packageVersion' }
				if ($ver) { $Pkg.Version = [string]$ver }
			}
		}

		Assert-ToolchainPolicyAllowed -Action $(if ($Output) { 'save' } else { 'pull' }) -Package $Pkg.Package -Version $Pkg.Version -Tag $tagStr -Digest $digest -RegistryBaseUrl $regBase -Repository $repoName

		if (-not $repoPath) {
			try {
				$registryHost = ([Uri]::new($regBase)).Host
			} catch {
				$registryHost = $regBase
			}
			$signatureDigests = @($digest)
			$rootManifest = $manifest | GetJsonResponse
			$platformChoice = ResolveManifestToSinglePlatform -Manifest $rootManifest
			if ($platformChoice.digest) {
				$platformDigest = [string]$platformChoice.digest | ConvertTo-CanonicalSha256Digest
				if ($platformDigest -notin $signatureDigests) { $signatureDigests += $platformDigest }
			}
			foreach ($signatureDigest in $signatureDigests) {
				$repoDigestRef = "${registryHost}/${repoName}@${signatureDigest}"
				Invoke-ToolchainCosignVerify -RepoDigestRef $repoDigestRef
			}
		}
		$k = 'metadatadb', $digest
		if ([Db]::ContainsKey($k) -and ($m = [Db]::Get($k)) -and $m.Size -and -not $Output) {
			$size = $m.Size
		} else {
			$size = $manifest | GetSize
			if ($Output) {
				$outputRefPath = Join-Path $Output $dockerRef
				MakeDirIfNotExist $outputRefPath | Out-Null
				$manifestPath = Join-Path (Resolve-Path $outputRefPath).Path 'manifest.json'
				$tempManifestPath = "$manifestPath.$([Guid]::NewGuid().ToString('N')).tmp"
				$backupManifestPath = "$manifestPath.$([Guid]::NewGuid().ToString('N')).bak"
				try {
					$manifestBytes = $manifest.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
					$manifestDigest = Get-ToolchainBytesSha256Digest -Bytes $manifestBytes
					if ($manifestDigest -ne $digest) {
						throw "manifest changed after verification: expected $digest, got $manifestDigest"
					}
					[IO.File]::WriteAllBytes($tempManifestPath, $manifestBytes)
					if (Test-Path -LiteralPath $manifestPath) {
						[IO.File]::Replace($tempManifestPath, $manifestPath, $backupManifestPath)
					} else {
						[IO.File]::Move($tempManifestPath, $manifestPath)
					}
				} finally {
					[IO.File]::Delete($tempManifestPath)
					[IO.File]::Delete($backupManifestPath)
				}
				if ($Sign) {
					$null = New-ToolchainFileCmsSignature -Path $manifestPath -SignaturePath "${manifestPath}.p7s"
				}
				$manifest | SavePackage -Output $outputRefPath
				return @{
					Package = $Pkg.Package
					Tag = $tagStr
					Version = $Pkg.Version
					Digest = $digest
					Size = $size
					Ref = $dockerRef
					SavedAt = [datetime]::UtcNow.ToString('u')
				}
			}
		}

		$Pkg.Digest = $digest
		$Pkg.Size = $size
		$contentPath = $Pkg.Digest | ResolvePackagePath
		$contentMissing = -not (Test-Path -LiteralPath $contentPath -PathType Container)
		$locks, $status = $Pkg | InstallPackage
		try {
			$ref = "$($Pkg.Package):$($Pkg.Tag | AsTagString)"
			if ($status -eq 'uptodate' -and -not $contentMissing) {
				Write-ToolchainInfo "Status: Package is up to date for $ref"
			} else {
				if (($status -in 'new', 'newer') -or $contentMissing) {
					$manifest | SavePackage
				}
				$refpath = $Pkg | ResolvePackageRefPath
				MakeDirIfNotExist (Split-Path $refpath) | Out-Null
				if (Test-Path -LiteralPath $refpath) {
					Remove-Item -LiteralPath $refpath -Recurse -Force
				}
				New-Item -Path $refpath -ItemType (GetToolchainLinkItemType) -Target $contentPath | Out-Null
				$message = if ($contentMissing -and $status -eq 'uptodate') { 'Restored package into full-digest content path' } else { 'Downloaded newer package' }
				Write-ToolchainInfo "Status: $message for $ref"
			}
			$locks.Unlock()
		} finally {
			if ($locks) {
				$locks.Revert()
			}
		}
		return $status
	} finally {
		if ($manifest) {
			$manifest.Dispose()
		}
	}
}

function SavePackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Net.Http.HttpResponseMessage]$Resp,
		[String]$Output
	)
	[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
	SetCursorVisible $false
	try {
		$layers = $Resp | GetPackageLayers
		$digest = if ($Output) { $null } else { $Resp | GetDigest }
		$temp = @()
		try {
			foreach ($layer in $layers) {
				try {
					if ($Output) {
						$layer.Digest | SaveBlob -Output $Output -ExpectedSize $layer.Size
					} else {
						$tmp = $layer.Digest | SaveBlob -ExpectedSize $layer.Size
						$temp += $tmp
						$tmp | ExtractTarGz -Digest $digest
					}
					"$($layer.Digest.Substring('sha256:'.Length).Substring(0, 12)): Pull complete" + ' ' * 60 | WriteConsole
				} finally {
					WriteConsole "`n"
				}
			}
		} catch {
			if (-not $Output -and $digest) {
				$contentPath = ResolvePackagePath -Digest $digest
				$contentItem = Get-Item -LiteralPath $contentPath -Force -ErrorAction SilentlyContinue
				if ($contentItem -and ($contentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
					# Windows PowerShell 5.1's non-recursive Remove-Item throws a
					# NullReferenceException for directory junctions. Directory.Delete
					# removes the junction itself without traversing its target.
					if ($PSVersionTable.PSEdition -eq 'Desktop') {
						[IO.Directory]::Delete($contentPath)
					} else {
						Remove-Item -LiteralPath $contentPath -Force
					}
				} elseif ($contentItem -and $contentItem.PSIsContainer) {
					DeleteDirectory $contentPath
				}
			}
			throw
		} finally {
			foreach ($tmp in $temp) {
				[IO.File]::Delete($tmp)
			}
		}
	} finally {
		SetCursorVisible $true
	}
}

function UninstallPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	$name = $Pkg.Package
	$tag = $Pkg.Tag | AsTagString
	$k = 'pkgdb', $name, $tag
	$locks = @()
	if (-not [Db]::ContainsKey($k)) {
		return $null, $null, "package '${name}:$tag' not installed"
	}
	$pLock, $err = [Db]::TryLock($k)
	if ($err) {
		return $null, $null, "package '${name}:$tag' is in use by another toolchain process"
	}
	$locks += $pLock
	$p = $pLock.Get()
	$pLock.Remove()
	$mLock, $err = [Db]::TryLock(('metadatadb', $p))
	if ($err) {
		$locks.Revert()
		$null, $null, "package '$p' is in use by another toolchain process"
	}
	$locks += $mLock
	$m = $mLock.Get()
	if ($m.refcount -gt 0) {
		$m.refcount -= 1
	}
	if ($m.refcount -eq 0) {
		$mLock.Remove()
		$digest = $p
	} else {
		$mLock.Put($m)
		$digest = $null
	}
	return $locks, $digest, $null
}

function DeleteDirectory {
	param (
		[string]$Dir
	)
	$name = [IO.Path]::GetRandomFileName()
	$tempDir = "$(GetPwrTempPath)\$name"
	[IO.Directory]::CreateDirectory($tempDir) | Out-Null
	try {
		Robocopy.exe $tempDir $Dir /MIR /PURGE | Out-Null
		[IO.Directory]::Delete($Dir)
	} finally {
		[IO.Directory]::Delete($tempDir)
	}
}

function RemovePackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	$locks, $digest, $err = $Pkg | UninstallPackage
	if ($null -ne $err) {
		throw $err
	}
	try {
		Write-ToolchainInfo "Untagged: $($Pkg.Package):$($pkg.Tag | AsTagString)"
		if ($null -ne $digest) {
			$content = $digest | ResolvePackagePath
			if (Test-Path $content -PathType Container) {
				DeleteDirectory $content
			}
			Write-ToolchainInfo "Deleted: $digest"
		}
		$refpath = $Pkg | ResolvePackageRefPath
		if (Test-Path -LiteralPath $refpath) {
			Remove-Item -LiteralPath $refpath -Recurse -Force
		}
		$locks.Unlock()
	} finally {
		if ($locks) {
			$locks.Revert()
		}
	}
}

function UninstallOrphanedPackages {
	param (
		[timespan]$Span
	)
	$now = [datetime]::UtcNow
	$locks = @()
	$metadata = @()
	$ls, $err = [Db]::TryLockAll('metadatadb')
	if ($err) {
		throw $err
	}
	foreach ($lock in $ls) {
		$m = $lock.Get() | ConvertTo-HashTable
		$orphaned = if ($m.orphaned) { $now - [datetime]::Parse($m.orphaned) }
		if ($m.refcount -eq 0 -and $orphaned -ge $Span) {
			$locks += $lock
			$m.digest = $lock.Key[1]
			$metadata += $m
			$lock.Remove()
		} else {
			$lock.Unlock()
		}
	}
	$ls, $err = [Db]::TryLockAll('pkgdb')
	if ($err) {
		if ($locks) {
			$locks.Revert()
		}
		throw $err
	}
	foreach ($lock in $ls) {
		if ($lock.Key[2].StartsWith('sha256:') -and $lock.Key[2] -in $metadata.digest) {
			$locks += $lock
			$lock.Remove()
		} else {
			$lock.Unlock()
		}
	}
	return $locks, $metadata
}

function PrunePackages {
	param (
		[switch]$Auto
	)
	$autoprune = (GetToolchainAutoprune)
	if ($Auto -and -not $autoprune) {
		return
	}
	$span = if ($Auto) { [timespan]::Parse($autoprune) } else { [timespan]::Zero }
	$locks, $pruned = UninstallOrphanedPackages $span
	try {
		$bytes = 0
		foreach ($i in $pruned) {
			$content = $i.Digest | ResolvePackagePath
			Write-ToolchainInfo "Deleted: $($i.Digest)"
			$stats = Get-ChildItem $content -Recurse | Measure-Object -Sum Length
			$bytes += $stats.Sum
			if (Test-Path $content -PathType Container) {
				DeleteDirectory $content
			}
		}
		if ($pruned) {
			Write-ToolchainInfo "Total reclaimed space: $($bytes | AsByteString)"
			$locks.Unlock()
		}
	} finally {
		if ($locks) {
			$locks.Revert()
		}
	}
}

function GetOutofdatePackages {
	param (
		[timespan]$Span
	)
	$now = [datetime]::UtcNow
	$locks, $err = [Db]::TryLockAll('pkgdb')
	if ($err) {
		throw $err
	}
	$pkgs = @()
	try {
		foreach ($lock in $locks) {
			$tag = $lock.Key[2]
			if (-not $tag.StartsWith('sha256:')) {
				$mlock, $err = [Db]::TryLock(('metadatadb', $lock.Get()))
				if ($err) {
					throw $err
				}
				$m = $mlock.Get() | ConvertTo-HashTable
				$since = if ($m.updated) { $now - [datetime]::Parse($m.updated) } else { [timespan]::MaxValue }
				if ($since -ge $Span) {
					$pkgs += "$($lock.Key[1]):$($lock.Key[2])"
				}
				$mlock.Revert()
			}
			$lock.Revert()
		}
	} finally {
		if ($locks) {
			$locks.Revert()
		}
	}
	return $pkgs
}

function Invoke-PullPackageWithRetry {
	param(
		[Parameter(Mandatory)]
		[string]$PackageRef,
		[string]$Output,
		[switch]$Sign,
		[int]$MaxAttempts = 3
	)
	if ($MaxAttempts -lt 1) {
		$MaxAttempts = 1
	}
	for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
		try {
			$pkg = $PackageRef | AsPackage
			$pullParams = @{}
			if ($PSBoundParameters.ContainsKey('Output')) {
				$pullParams.Output = $Output
			}
			if ($PSBoundParameters.ContainsKey('Sign')) {
				$pullParams.Sign = $Sign
			}
			return ($pkg | PullPackage @pullParams)
		} catch {
			$msg = $_.Exception.Message
			$isLockContention = ($msg -match 'is in use by another toolchain process')
			if (-not $isLockContention -or $attempt -ge $MaxAttempts) {
				throw
			}
			$delaySeconds = [math]::Min(5, $attempt)
			Write-ToolchainInfo "Package busy; retrying pull for $PackageRef ($attempt/$MaxAttempts) in $delaySeconds sec"
			Start-Sleep -Seconds $delaySeconds
		}
	}
}

function UpdatePackages {
	param (
		[switch]$Auto,
		[string[]]$Packages
	)
	$autoupdate = (GetToolchainAutoupdate)
	if ($Auto -and -not $autoupdate) {
		return
	}
	$span = if ($Auto) { [timespan]::Parse($autoupdate) } else { [timespan]::MinValue }
	$pkgs = GetOutofdatePackages $span
	if ($Auto -and -not $pkgs) {
		return
	}
	$updated = 0
	$skipped = 0
	$err = $null
	$formal_pkgs = if ($Packages) { $Packages | AsPackage | ForEach-Object { "$($_.Package):$($_.Tag | AsTagString)" } }
	foreach ($pkg in $pkgs) {
		if ($Auto -and $pkg -notin $formal_pkgs) {
			++$skipped
			continue
		}
		try {
			$status = Invoke-PullPackageWithRetry -PackageRef $pkg
			if ($status -ne 'uptodate') {
				++$updated
			}
		} catch {
			if (-not $err) {
				$err = $_
			}
		}
	}
	if ($err) {
		throw $err
	}
	Write-ToolchainInfo "Updated $updated package$(if ($updated -ne 1) { 's' })$(if ($skipped -ne 0) { " (Run update command to check $skipped skipped package$(if ($skipped -ne 1) { 's' })" }))"
}
