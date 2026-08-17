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

. $PSScriptRoot\remote-catalog.ps1

function AsPackage {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Pkg
    )

    if ($Pkg -match '^([^:@]+)@([^:]+:[^:]+)(?:::?([^:]+))?$') {
        $pkgName = [string]$Matches[1]
        $d = [string]$Matches[2]
        $cfg = if ($Matches[3]) { [string]$Matches[3] } else { 'default' }

        if (-not ($d -match '^sha256:[0-9a-fA-F]{64}$')) {
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
	$refName = "$($Pkg.Package)$(if (-not $Pkg.Tag.Latest) { "-$($Pkg.Tag | AsTagString)" })"
	return (Join-Path (Join-Path (GetToolchainPath) 'ref') $refName)
}

function GetToolchainLinkItemType {
	$isWindowsPlatform = $false
	if ($PSVersionTable.PSEdition -eq 'Desktop') {
		$isWindowsPlatform = $true
	} elseif (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
		$isWindowsPlatform = [bool]$IsWindows
	}

	if ($isWindowsPlatform) {
		return 'Junction'
	}

	return 'SymbolicLink'
}

function ResolveDockerRef {
  param (
    [Parameter(Mandatory, ValueFromPipeline)]
    [Collections.Hashtable]$Pkg
  )

  if ($Pkg.ContainsKey('Digest') -and $Pkg.Digest) {
    $dg = [string]$Pkg.Digest
	if ($dg -match '^[0-9a-fA-F]{64}$') { $dg = 'sha256:' + $dg }
	return ($dg | ConvertTo-CanonicalSha256Digest)
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
	if ((Get-Command Test-ToolchainConstraintExpression -ErrorAction SilentlyContinue) -and (Test-ToolchainConstraintExpression -Value $raw)) {
		$selectedVersion = Select-ToolchainPackageVersion -Name $Pkg.Package -Constraints @($raw) -Catalog $docker
		$Pkg.Version = $selectedVersion
		return BuildRemoteRef $Pkg.Package $selectedVersion $legacy
	}
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

class Digest {
	[string]$Sha256

	Digest([string]$sha256) {
		$this.Sha256 = $sha256
	}

	[string] ToString() {
		return "$($this.Sha256.Substring('sha256:'.Length).Substring(0, 12))"
	}
}

. $PSScriptRoot\package-lifecycle.ps1

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

function ParseLocalPackageRef {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref
	)
	if (-not $Ref.StartsWith('file:///')) {
		throw "not a local package reference: $Ref"
	}
	$raw = $Ref.Substring('file:///'.Length).Trim()
	if (-not $raw) {
		throw "invalid local package reference: missing path in '$Ref'"
	}
	$cfg = 'default'
	$root = $raw
	$i = $raw.IndexOf('<')
	if ($i -ne -1) {
		$root = $raw.Substring(0, $i).Trim()
		$cfgRaw = $raw.Substring($i + 1).Trim()
		if ($cfgRaw.EndsWith('>')) {
			$cfgRaw = $cfgRaw.Substring(0, $cfgRaw.Length - 1).Trim()
		}
		if ($cfgRaw) {
			$cfg = $cfgRaw
		}
	}
	if (-not $root) {
		throw "invalid local package reference: missing path in '$Ref'"
	}
	try {
		$root = [Uri]::UnescapeDataString($root)
	} catch {
		Write-Debug "Leaving invalid URI escapes unchanged in local package reference '$Ref': $($_.Exception.Message)"
	}
	return @{
		Root = $root
		Config = $cfg
	}
}

function ResolvePackage {
	param (
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Ref
	)
	if ($Ref.StartsWith('file:///')) {
		$local = $Ref | ParseLocalPackageRef
		$root = $local.Root
		$cfg = $local.Config
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
