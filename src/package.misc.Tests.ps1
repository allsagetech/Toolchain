<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\config.ps1"
	. "$PSScriptRoot\log.ps1"
	. "$PSScriptRoot\progress.ps1"
	. "$PSScriptRoot\registry.ps1"
	. "$PSScriptRoot\package.ps1"
}

Describe 'Tag parsing and ordering' {
	It 'parses latest, none, semver, and raw tags' {
		$tLatest = [Tag]::new('latest')
		$tLatest.Latest | Should -BeTrue
		$tNone = [Tag]::new('<none>')
		$tNone.None | Should -BeTrue
		$tSemver = [Tag]::new('v1.2.3_4')
		$tSemver.Major | Should -Be '1'
		$tSemver.Build | Should -Be '4'
		$tRaw = [Tag]::new('dev')
		$tRaw.Raw | Should -Be 'dev'
	}

	It 'compares tags including non-Tag objects and errors' {
		([Tag]::new('latest').CompareTo([Tag]::new('1.0.0')) -gt 0) | Should -BeTrue
		([Tag]::new('1.0.0').CompareTo([Tag]::new('2.0.1')) -lt 0) | Should -BeTrue

		$tn = 'BadToString' + [Guid]::NewGuid().ToString('N')
		$cs = @"
public class $tn {
  public override string ToString() { throw new System.Exception("bad"); }
}
"@
Add-Type -TypeDefinition $cs
		$bad = New-Object $tn
		{ [Tag]::new('1.0.0').CompareTo($bad) } | Should -Throw 'cannot compare Tag*'
	}
}

Describe 'Tag conversion helpers' {
	It 'creates tag hashtables and strings' {
		($null | AsTagHashtable).Latest | Should -BeTrue
		('latest' | AsTagHashtable).Latest | Should -BeTrue
		('1.2.3_4' | AsTagHashtable).Build | Should -Be '4'
		(@{ Major='1'; Minor='2'; Patch='3'; Build='4' } | AsTagString) | Should -Be '1.2.3+4'
		(@{ Latest=$true } | AsTagString) | Should -Be 'latest'
		(@{ Raw='dev' } | AsTagString) | Should -Be 'dev'
	}
}

Describe 'Docker package tag mapping' {
	BeforeEach {
		$env:TOOLCHAIN_REPOSITORY = 'example/toolchain'
	}


	AfterEach {
		Remove-Item Env:TOOLCHAIN_REPOSITORY -ErrorAction Ignore
	}
	It 'parses docker tag names into packages' {
		('toolchain-1.2.3' | AsDockerPackage).Tag.Major | Should -Be '1'
		('toolchain' | AsDockerPackage).Package | Should -Be 'toolchain'
	}

	It 'builds package/tag maps from tag lists' {
		Mock GetTagsList { @{ Tags = @('toolchain-1.0.0','toolchain-2.0.1','other-1.0.0') } }
		$pkgs = GetDockerPackages
		$pkgs.toolchain.Count | Should -Be 2
		$tags = GetDockerTags
		$tags.toolchain[0].ToString() | Should -Be '2.0.1'
	}
}

Describe 'AsPackage parsing' {
	It 'parses digested and tagged packages' {
		$p = ('foo@sha256:' + ('a'*64) + '::cfg') | AsPackage
		$p.Package | Should -Be 'foo'
		$p.Digest | Should -Match '^sha256:'
		$p.Tag.Raw | Should -Match '^sha256-'
		$p.Config | Should -Be 'cfg'

		$p2 = 'foo:1.2.3' | AsPackage
		$p2.Tag.Major | Should -Be '1'
		$p2.Config | Should -Be 'default'
	}

	It 'rejects invalid digests' {
		{ 'foo@sha256:zz::cfg' | AsPackage } | Should -Throw '*invalid digest*'
	}
}

Describe 'ResolvePackageRefPath and digest helpers' {
	BeforeEach {
		$global:ToolchainPath = 'C:\toolchain'
	}

	It 'renders ref paths for latest and non-latest' {
		$pLatest = @{ Package='foo'; Tag=@{ Latest=$true } }
		($pLatest | ResolvePackageRefPath) | Should -Be 'C:\toolchain\ref\foo'
		$pVer = @{ Package='foo'; Tag=@{ Major='1'; Minor='2'; Patch='3' } }
		($pVer | ResolvePackageRefPath) | Should -Match 'ref\\foo-1\.2\.3'
	}

	It 'wraps digests and sizes' {
		$d = ('sha256:' + ('b'*64)) | AsDigest
		$d.ToString() | Should -Be (('b'*12))
		$s = (2048 | AsSize)
		$s.Bytes | Should -Be 2048
		$s.ToString() | Should -Match 'kB'
	}
}

Describe 'ResolveDockerRef selection logic' {
	It 'normalizes bare sha256 hex digests' {
		$p = @{ Package='foo'; Tag=@{ Latest=$true }; Digest=('a'*64) }
		($p | ResolveDockerRef) | Should -Be ('sha256:' + ('a'*64))
	}

	It 'throws for unknown packages' {
		Mock GetDockerTags { New-Object PSObject }
		Mock GetTagsList { @{ Tags = @() } }
		{ (@{ Package='nope'; Tag=@{ Latest=$true } } | ResolveDockerRef) } | Should -Throw '*no such package*'
	}

	It 'resolves latest, raw, semver, and legacy tag styles' {
		$o = New-Object PSObject
		$o | Add-Member -MemberType NoteProperty -Name 'toolchain' -Value @([Tag]::new('latest'), [Tag]::new('2.0.1'), [Tag]::new('1.0.0'))
		Mock GetDockerTags { $o }
		Mock GetTagsList { @{ Tags = @('toolchain-2.0.1','toolchain-1.0.0','toolchain-latest') } }

		$pLatest = @{ Package='toolchain'; Tag=@{ Latest=$true } }
		($pLatest | ResolveDockerRef) | Should -Be 'toolchain-2.0.1'

		$pRaw = @{ Package='toolchain'; Tag=@{ Raw='toolchain-1.0.0' } }
		($pRaw | ResolveDockerRef) | Should -Be 'toolchain-1.0.0'

		$pSem = @{ Package='toolchain'; Tag=@{ Major='1' } }
		($pSem | ResolveDockerRef) | Should -Be 'toolchain-1.0.0'

		{ (@{ Package='toolchain'; Tag=@{ Raw='missing' } } | ResolveDockerRef) } | Should -Throw '*no such toolchain tag*'
		{ (@{ Package='toolchain'; Tag=@{ Major='9' } } | ResolveDockerRef) } | Should -Throw '*no such toolchain tag*'
	}
}

Describe 'DeleteDirectory' {
	It 'deletes a directory tree using robocopy strategy' {
		$dir = Join-Path $env:TEMP ('del-' + [Guid]::NewGuid().ToString())
		New-Item -ItemType Directory -Path $dir | Out-Null
		New-Item -ItemType File -Path (Join-Path $dir 'a.txt') -Value 'x' | Out-Null
		DeleteDirectory $dir
		(Test-Path -LiteralPath $dir) | Should -BeFalse
	}
}
