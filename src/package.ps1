<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

. $PSScriptRoot\registry.ps1
. $PSScriptRoot\config.ps1
. $PSScriptRoot\progress.ps1
. $PSScriptRoot\log.ps1
. $PSScriptRoot\policy.ps1
. $PSScriptRoot\security.ps1
. $PSScriptRoot\db.ps1

function AsDockerPackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$RegistryTag
	)

	if ($RegistryTag -match '^(.*)-([0-9].+)$') {
		return @{
			Package = $Matches[1]
			Tag     = $Matches[2] | AsTagHashtable
		}
	}

	$repo = (GetRegistryRepoName)
	$pkg  = ($repo -split '/')[-1]

	return @{
		Package = $pkg
		Tag     = $RegistryTag | AsTagHashtable
	}
}

function AsTagHashtable {
	param (
		[Parameter(ValueFromPipeline)]
		[string]$Tag
	)

	if ($Tag -in 'latest', '', $null) {
		return @{ Latest = $true }
	}

	$semverCandidate = $Tag
	if ($semverCandidate -match '^v(.*)$') {
		$semverCandidate = $Matches[1]
	}

	if ($semverCandidate -match '^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:(?:\+|_)([0-9]+))?$') {
		return @{
			Major = $Matches[1]
			Minor = $Matches[2]
			Patch = $Matches[3]
			Build = $Matches[4]
		}
	}

	return @{ Raw = $Tag }
}

function AsTagString {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[collections.Hashtable]$Tag
	)

	if ($true -eq $Tag.Latest) {
		return "latest"
	}

	if ($Tag.ContainsKey('Raw') -and $Tag.Raw) {
		return "$($Tag.Raw)"
	}

	$s = "$($Tag.Major)"
	if ($Tag.Minor) { $s += ".$($Tag.Minor)" }
	if ($Tag.Patch) { $s += ".$($Tag.Patch)" }
	if ($Tag.Build) { $s += "+$($Tag.Build)" }
	return $s
}

function GetDockerPackages {
	$docker = @{}
	foreach ($tag in (GetTagsList).Tags) {
		$pkg = $tag | AsDockerPackage
		$docker.$($pkg.Package) = $docker.$($pkg.Package) + @($pkg.Tag)
	}
	$docker
}

function GetDockerTags {
	$docker = GetDockerPackages
	$o = New-Object PSObject
	foreach ($k in $docker.keys | Sort-Object) {
		$arr = @()
		foreach ($t in $docker.$k) {
			$arr += [Tag]::new(($t | AsTagString))
		}
		$o | Add-Member -MemberType NoteProperty -Name $k -Value ($arr | Sort-Object -Descending)
	}
	$o
}

function AsPackage {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Pkg
    )

    if ($Pkg -match '^([^:@]+)@([^:]+:[^:]+)(?:::?([^:]+))?$') {
        $pkgName = [string]$Matches[1]
        $d = [string]$Matches[2]
        $cfg = if ($Matches[3]) { [string]$Matches[3] } else { 'default' }

        if (-not ($d -match '^[A-Za-z0-9_+.-]+:[0-9a-fA-F]{32,}$')) {
            throw "invalid digest: $d"
        }

        $parts = $d.Split(':', 2)
        $algo = $parts[0]
        $hex = $parts[1]

        $short = $d
        if ($hex -match '^[0-9a-fA-F]{12,}$') {
            $short = "$algo-$($hex.Substring(0,12).ToLower())"
        }

        return @{ 
            Package = $pkgName
            Tag     = @{ Raw = $short }
            Config  = $cfg
            Digest  = $d.ToLower()
        }
    }

    if ($Pkg -match '^([^:]+)(?::([^:]+))?(?:::?([^:]+))?$') {
        return @{ 
            Package = $Matches[1]
            Tag     = $Matches[2] | AsTagHashtable
            Config  = if ($Matches[3]) { $Matches[3] } else { 'default' }
        }
    }
    throw "failed to parse package: $Pkg"
}

function TryEachPackage {
	param (
		[Parameter(Mandatory, Position = 0)]
		[string[]]$Packages,
		[Parameter(Mandatory, Position = 1)]
		[scriptblock]$ScriptBlock,
		[string]$ActionDescription = 'process'
	)
	$results = @()
	$failures = @()
	foreach ($p in $Packages) {
		try {
			$results += $p | &$ScriptBlock
		} catch {
			Write-Error $_ -ErrorAction Continue
			$failures += $p
		}
	}
	if ($failures.Count -gt 0) {
		throw "Failed to $ActionDescription packages: $($failures -join ', ')"
	}
	return $results
}

function ResolvePackageRefPath {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	return "$(GetToolchainPath)\ref\$($Pkg.Package)$(if (-not $Pkg.Tag.Latest) { "-$($Pkg.Tag | AsTagString)" })"
}

function ResolveDockerRef {
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [Collections.Hashtable]$Pkg
  )

  if ($Pkg.ContainsKey('Digest') -and $Pkg.Digest) {
    $dg = [string]$Pkg.Digest
    if (-not $dg.StartsWith('sha256:') -and ($dg -match '^[0-9a-fA-F]{64}$')) {
      $dg = 'sha256:' + $dg.ToLower()
    }
    return $dg
  }
  $docker = GetDockerTags

  $prop = $docker.PSObject.Properties[$Pkg.Package]
  if (-not $prop) {
    throw "no such package: $($Pkg.Package)"
  }

  $tagsObj = GetTagsList
  $allTags = @(
    if ($null -ne $tagsObj.tags) { $tagsObj.tags }
    elseif ($null -ne $tagsObj.Tags) { $tagsObj.Tags }
    else { @() }
  )

  function FindFirstTag([string[]]$Names) {
    foreach ($n in $Names) {
      if ($n -in $allTags) { return $n }
    }
    return $null
  }

  function BuildRemoteRef([string]$Package, [string]$Version, [bool]$Legacy) {
    $v1 = $Version
    $v2 = $Version.Replace('+', '_')
    if ($Legacy) {
      $found = FindFirstTag @("$Package-$v1", "$Package-$v2", "$Package-v$v1", "$Package-v$v2")
      if ($found) { return $found }
      return "$Package-$v2"
    }
    $found = FindFirstTag @($v1, $v2, "v$v1", "v$v2")
    if ($found) { return $found }
    return $v1
  }

  $want = $Pkg.Tag
  $legacy = $false
  if ($allTags | Where-Object { $_ -like "$($Pkg.Package)-*" } | Select-Object -First 1) {
    $legacy = $true
  }
	if ($true -eq $want.Latest) {
		$gotLatest = $prop.Value | Where-Object { -not $_.None -and -not $_.Latest -and $null -ne $_.Major } | Select-Object -First 1
		if (-not $gotLatest) {
			$gotLatest = $prop.Value | Where-Object { $_.Latest } | Select-Object -First 1
		}
		if ($gotLatest) {
			$Pkg.Version = $gotLatest.ToString()
			return BuildRemoteRef $Pkg.Package $Pkg.Version $legacy
		}
	}
  if ($want.ContainsKey('Raw') -and $want.Raw) {
    $raw = [string]$want.Raw
    $found = FindFirstTag @($raw, "v$raw")
    if (-not $found -and $raw -match '^v(.+)$') {
      $found = FindFirstTag @($Matches[1])
    }
    if (-not $found) {
      throw "no such $($Pkg.Package) tag: $raw"
    }
    $Pkg.Version = $found
    return $found
  }

  foreach ($got in $prop.Value) {
    $eq = $true
    if ($null -ne $want.Major) { $eq = $eq -and $want.Major -eq $got.Major }
    if ($null -ne $want.Minor) { $eq = $eq -and $want.Minor -eq $got.Minor }
    if ($null -ne $want.Patch) { $eq = $eq -and $want.Patch -eq $got.Patch }
    if ($null -ne $want.Build) { $eq = $eq -and $want.Build -eq $got.Build }
    if ($eq) {
      $Pkg.Version = $got.ToString()
      return BuildRemoteRef $Pkg.Package $Pkg.Version $legacy
    }
  }

  throw "no such $($Pkg.Package) tag: $($Pkg.Tag | AsTagString)"
}



function GetLocalPackages {
	$pkgs = @()
	$locks, $err = [Db]::TryLockAll('pkgdb')
	if ($err) {
		throw $err
	}
	try {
		foreach ($lock in $locks) {
			$tag = $lock.Key[2]
			$t = [Tag]::new($tag)
			$digest = if ($t.None) { $tag } else { $lock.Get() }
			$m = [Db]::Get(('metadatadb', $digest))
			$pkgs += [LocalPackage]@{
				Package = $lock.Key[1]
				Tag = $t
				Version = $m.Version
				Digest = $digest | AsDigest
				Size = $m.size | AsSize
				Updated = if ($m.updated) { [datetime]::Parse($m.updated) } else { }
				Orphaned = if ($m.orphaned) { [datetime]::Parse($m.orphaned) }
			}
			$lock.Unlock()
		}
	} finally {
		if ($locks) {
			$locks.Revert()
		}
	}
	if (-not $pkgs) {
		$pkgs = ,[LocalPackage]@{}
	}
	return $pkgs
}

function ResolvePackageDigest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[Collections.Hashtable]$Pkg
	)
	if ($pkg.digest) {
		return $pkg.digest
	}
	if ($Pkg.Digest) {
		return $Pkg.Digest
	}
	$k = 'pkgdb', $Pkg.Package, ($Pkg.Tag | AsTagString)
	if ([Db]::ContainsKey($k)) {
		return [Db]::Get($k)
	}
}

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
	$dockerRef = $Pkg | ResolveDockerRef
	$tagStr = $Pkg.Tag | AsTagString
	$digest = $dockerRef | GetDigestForRef
	Write-ToolchainInfo "Pulling $($Pkg.Package):$($pkg.Tag | AsTagString)"
	Write-ToolchainInfo "Digest: $($digest)"

	if (-not $Pkg.Version -and -not (GetToolchainRepo)) {
		try {
			$cfg = GetImageConfigJsonFromRef -Ref $dockerRef
			$labels = $null
			if ($cfg -and $cfg.config -and $cfg.config.Labels) { $labels = $cfg.config.Labels }
			elseif ($cfg -and $cfg.Labels) { $labels = $cfg.Labels }
			if ($labels) {
				$ver = $labels.'io.allsagetech.toolchain.packageVersion'
				if (-not $ver) { $ver = $labels.'toolchain.packageVersion' }
				if ($ver) { $Pkg.Version = [string]$ver }
			}
		} catch {
			Write-Debug "failed to read packageVersion label for ${dockerRef}: $($_.Exception.Message)"
		}
	}

	$repoPath = GetToolchainRepo
	$regBase = if ($repoPath) { $null } else { GetRegistryBaseUrl }
	$repoName = if ($repoPath) { $null } else { GetRegistryRepoName }
	Assert-ToolchainPolicyAllowed -Action $(if ($Output) { 'save' } else { 'pull' }) -Package $Pkg.Package -Version $Pkg.Version -Tag $tagStr -Digest $digest -RegistryBaseUrl $regBase -Repository $repoName

	if (-not $repoPath) {
		try {
			$registryHost = ([Uri]::new($regBase)).Host
		} catch {
			$registryHost = $regBase
		}
		$repoDigestRef = "${registryHost}/${repoName}@${digest}"
		Invoke-ToolchainCosignVerify -RepoDigestRef $repoDigestRef
	}
	$k = 'metadatadb', $digest
	if ([Db]::ContainsKey($k) -and ($m = [Db]::Get($k)) -and $m.Size -and -not $Output) {
		$size = $m.Size
	} else {
		$manifest = $dockerRef | GetManifest
		$manifest | DebugRateLimit
		$size = $manifest | GetSize
		if ($Output) {
			MakeDirIfNotExist "$Output\$dockerRef" | Out-Null
			$manifestPath = "$(Resolve-Path "$Output\$dockerRef")\manifest.json"
			$fs = [IO.File]::Open($manifestPath, [IO.FileMode]::Create)
			try {
				$task = $manifest.Content.CopyToAsync($fs)
				while (-not $task.IsCompleted) {
					Start-Sleep -Milliseconds 125
				}
			} finally {
				$fs.Close()
			}
			if ($Sign) {
				$null = New-ToolchainFileCmsSignature -Path $manifestPath -SignaturePath "${manifestPath}.p7s"
			}
			$manifest | SavePackage -Output "$Output\$dockerRef"
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
	$locks, $status = $Pkg | InstallPackage
	try {
		$ref = "$($Pkg.Package):$($Pkg.Tag | AsTagString)"
		if ($status -eq 'uptodate') {
			Write-ToolchainInfo "Status: Package is up to date for $ref"
		} else {
			if ($status -in 'new', 'newer') {
				$manifest | SavePackage
			}
			$refpath = $Pkg | ResolvePackageRefPath
			MakeDirIfNotExist (Split-Path $refpath) | Out-Null
			if (Test-Path -Path $refpath -PathType Container) {
				[IO.Directory]::Delete($refpath)
			}
			New-Item $refpath -ItemType Junction -Target ($Pkg.Digest | ResolvePackagePath) | Out-Null
			Write-ToolchainInfo "Status: Downloaded newer package for $ref"
		}
		$locks.Unlock()
	} finally {
		if ($locks) {
			$locks.Revert()
		}
	}
	return $status
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
		foreach ($layer in $layers) {
			try {
				if ($Output) {
					$layer.Digest | SaveBlob -Output $Output
				} else {
					$temp += $layer.Digest | SaveBlob | ExtractTarGz -Digest $digest
				}
				"$($layer.Digest.Substring('sha256:'.Length).Substring(0, 12)): Pull complete" + ' ' * 60 | WriteConsole
			} finally {
				WriteConsole "`n"
			}
		}
		foreach ($tmp in $temp) {
			[IO.File]::Delete($tmp)
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
		if (Test-Path -Path $refpath -PathType Container) {
			[IO.Directory]::Delete($refpath)
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
	$formal_pkgs = if ($Packages) { $Packages | AsPackage | ForEach-Object { "$($_.Package):$($_.Tag | AsTagString)" } }
	foreach ($pkg in $pkgs) {
		if ($Auto -and $pkg -notin $formal_pkgs) {
			++$skipped
			continue
		}
		try {
			$status = $pkg | AsPackage | PullPackage
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

class Digest {
	[string]$Sha256

	Digest([string]$sha256) {
		$this.Sha256 = $sha256
	}

	[string] ToString() {
		return "$($this.Sha256.Substring('sha256:'.Length).Substring(0, 12))"
	}
}

function AsDigest {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Digest
	)
	return [Digest]::new($Digest)
}

class Tag : IComparable {
	[string]$Raw
	[object]$Major
	[object]$Minor
	[object]$Patch
	[object]$Build
	hidden [bool]$None
	hidden [bool]$Latest

	Tag([string]$tag) {
		if ($tag -eq '<none>' -or $tag.StartsWith('sha256:')) {
			$this.None = $true
			return
		}
		if ($tag -in 'latest', '') {
			$this.Latest = $true
			return
		}

		$semverCandidate = $tag
		if ($semverCandidate -match '^v(.*)$') {
			$semverCandidate = $Matches[1]
		}

		if ($semverCandidate -match '^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:(?:\+|_)([0-9]+))?$') {
			$this.Major = $Matches[1]
			$this.Minor = $Matches[2]
			$this.Patch = $Matches[3]
			$this.Build = $Matches[4]
			return
		}

		$this.Raw = $tag
	}

	[int] CompareTo([object]$Obj) {
		if ($null -eq $Obj) { return 1 }

		if ($Obj -isnot $this.GetType()) {
			try {
				$Obj = [Tag]::new([string]$Obj)
			}
			catch {
				throw "cannot compare Tag to $($Obj.GetType())"
			}
		}

		if ($this.Latest -or $Obj.Latest) {
			return $this.Latest - $Obj.Latest
		}
		if ($this.None -or $Obj.None) {
			return $Obj.None - $this.None
		}

		$thisIsRaw = -not [string]::IsNullOrEmpty($this.Raw)
		$otherIsRaw = -not [string]::IsNullOrEmpty($Obj.Raw)

		if ($thisIsRaw -and -not $otherIsRaw) { return -1 }
		if (-not $thisIsRaw -and $otherIsRaw) { return 1 }

		if ($thisIsRaw -and $otherIsRaw) {
			return [string]::Compare($this.Raw, $Obj.Raw, $true)
		}

		if ($this.Major -ne $Obj.Major) { return $this.Major - $Obj.Major }
		elseif ($this.Minor -ne $Obj.Minor) { return $this.Minor - $Obj.Minor }
		elseif ($this.Patch -ne $Obj.Patch) { return $this.Patch - $Obj.Patch }
		else { return $this.Build - $Obj.Build }
	}

	[string] ToString() {
		if ($this.None) { return '' }
		if (-not [string]::IsNullOrEmpty($this.Raw)) { return $this.Raw }
		if ($null -eq $this.Major) { return 'latest' }

		$s = "$($this.Major)"
		if ($this.Minor) { $s += ".$($this.Minor)" }
		if ($this.Patch) { $s += ".$($this.Patch)" }
		if ($this.Build) { $s += "+$($this.Build)" }
		return $s
	}

}

function ResolvePackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref
	)
	if ($Ref.StartsWith('file:///')) {
		$root = $Ref.Substring('file:///'.Length)
		$i = $root.IndexOf('<')
		$cfg = 'default'
		if ($i -ne -1) {
			$cfg = $root.Substring($i + 1).Trim()
			if (-not $cfg) { $cfg = 'default' }
			$root = $root.Substring(0, $i).Trim()
		}
		$name = Split-Path -Path $root -Leaf
		if (-not $name) { $name = $root }
		return @{
			Package = $name
			Digest = $Ref
			Tag = @{ Latest = $true }
			Config = $cfg
		}
	}
	$pkg = $Ref | AsPackage
	$digest = $pkg | ResolvePackageDigest
	$pullpolicy = (GetToolchainPullPolicy)
	switch ($pullpolicy) {
		'IfNotPresent' {
			if (-not $digest) {
				$pkg | PullPackage | Out-Null
				$pkg.digest = $pkg | ResolvePackageDigest
			}
		}
		'Never' {
			if (-not $digest) {
				throw "cannot find package $($pkg.Package):$($pkg.Tag | AsTagString)"
			}
		}
		'Always' {
			$pkg | PullPackage | Out-Null
			$pkg.digest = $pkg | ResolvePackageDigest
		}
		default {
			throw "ToolchainPullPolicy '$pullpolicy' is not valid"
		}
	}
	return $pkg
}

class Size : IComparable {
	[long]$Bytes
	hidden [string]$ByteString

	Size([long]$Bytes, [string]$ByteString) {
		$this.Bytes = $Bytes
		$this.ByteString = $ByteString
	}

	[int] CompareTo([object]$Obj) {
		return $this.Bytes.CompareTo($Obj.Bytes)
	}

	[string] ToString() {
		return $this.ByteString
	}
}

function AsSize {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[long]$Bytes
	)
	return [Size]::new($Bytes, ($Bytes | AsByteString))
}

class LocalPackage {
	[object]$Package
	[Tag]$Tag
	[string]$Version
	[Digest]$Digest
	[Size]$Size
	[object]$Updated
	[object]$Orphaned
}
