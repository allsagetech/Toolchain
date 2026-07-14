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
		$env:TOOLCHAIN_MODEL_PACKAGES = $null
	}


	AfterEach {
		Remove-Item Env:TOOLCHAIN_REPOSITORY -ErrorAction Ignore
		Remove-Item Env:TOOLCHAIN_MODEL_PACKAGES -ErrorAction Ignore
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

	It 'excludes Cosign and package-kind metadata from installable packages' {
		$digitSignature = 'sha256-1' + ('a' * 63) + '.sig'
		$letterSignature = 'sha256-a' + ('b' * 63) + '.sig'
		Mock GetTagsList { @{ Tags = @(
			'git-2.0.0',
			$digitSignature,
			$letterSignature,
			('sha256-' + ('c' * 64) + '.att'),
			('sha256-' + ('d' * 64) + '.sbom'),
			'tlc-kind-model-v1-100-1--qwen3-0.6b'
		) } }

		$pkgs = GetDockerPackages
		@($pkgs.Keys) | Should -Be @('git')
		$pkgs.ContainsKey('sha256') | Should -BeFalse
		$pkgs.ContainsKey('toolchain') | Should -BeFalse
	}

	It 'separates tooling and model views without removing models from resolution' {
		Mock GetTagsList { @{ Tags = @(
			'git-2.0.0',
			'qwen3-0.6b-2025.7.26_346',
			'tlc-kind-model-v1-100-1--qwen3-0.6b'
		) } }

		$tools = GetDockerPackages -Kind Tooling
		$models = GetDockerPackages -Kind Model
		$all = GetDockerPackages -Kind All
		@($tools.Keys) | Should -Be @('git')
		@($models.Keys) | Should -Be @('qwen3-0.6b')
		@($all.Keys | Sort-Object) | Should -Be @('git', 'qwen3-0.6b')

		# GetDockerTags defaults to the complete installable catalog because the
		# package resolver uses it for pull/load/save operations.
		$resolvedCatalog = GetDockerTags
		$resolvedCatalog.PSObject.Properties.Name | Should -Contain 'qwen3-0.6b'

		# The default list display is tooling-only without removing model
		# properties that existing PowerShell automation may access.
		$listCatalog = GetDockerTags -ToolingDefaultDisplay
		$listCatalog.PSObject.Properties.Name | Should -Contain 'qwen3-0.6b'
		$displayProperties = @($listCatalog.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames)
		$displayProperties | Should -Contain 'git'
		$displayProperties | Should -Not -Contain 'qwen3-0.6b'
	}

	It 'supports explicit model classification for legacy custom registries' {
		$env:TOOLCHAIN_MODEL_PACKAGES = 'private-model; another-model'
		Mock GetTagsList { @{ Tags = @('private-model-1.0.0', 'git-2.0.0') } }

		$models = GetDockerPackages -Kind Model
		@($models.Keys) | Should -Be @('private-model')
	}

	It 'uses the official migration catalog only before a complete registry catalog exists' {
		$env:TOOLCHAIN_REPOSITORY = 'allsagetech/toolchains'
		Mock GetTagsList { @{ Tags = @('qwen3-0.6b-1.0.0', 'git-2.0.0') } }

		@(GetDockerPackages -Kind Model).Keys | Should -Be @('qwen3-0.6b')

		Mock GetTagsList { @{ Tags = @(
			'qwen3-0.6b-1.0.0',
			'smollm2-135m-instruct-1.0.0',
			'tlc-kind-model-v1-100-1--smollm2-135m-instruct'
		) } }

		# Published generations are authoritative. A newer generation can
		# therefore reclassify an existing package from model to tooling.
		@((GetDockerPackages -Kind Model).Keys) | Should -Be @('smollm2-135m-instruct')
		@((GetDockerPackages -Kind Tooling).Keys) | Should -Be @('qwen3-0.6b')
	}

	It 'ignores incomplete generations and uses the newest complete model catalog' {
		Mock GetTagsList { @{ Tags = @(
			'alpha-1.0.0', 'beta-1.0.0', 'gamma-1.0.0',
			'tlc-kind-model-v1-100-2--alpha',
			'tlc-kind-model-v1-100-2--beta',
			'tlc-kind-model-v1-101-3--alpha',
			'tlc-kind-model-v1-101-3--gamma'
		) } }

		@((GetDockerPackages -Kind Model).Keys | Sort-Object) | Should -Be @('alpha', 'beta')
		@((GetDockerPackages -Kind Tooling).Keys) | Should -Be @('gamma')
	}

	It 'lets a newer complete generation remove models from the catalog' {
		Mock GetTagsList { @{ Tags = @(
			'alpha-1.0.0', 'beta-1.0.0',
			'tlc-kind-model-v1-100-2--alpha',
			'tlc-kind-model-v1-100-2--beta',
			'tlc-kind-model-v1-101-1--alpha'
		) } }

		@((GetDockerPackages -Kind Model).Keys) | Should -Be @('alpha')
		@((GetDockerPackages -Kind Tooling).Keys) | Should -Be @('beta')
	}

	It 'supports an authoritative empty model catalog' {
		Mock GetTagsList { @{ Tags = @(
			'alpha-1.0.0',
			'tlc-kind-model-v1-100-1--alpha',
			'tlc-kind-model-v1-101-0--empty'
		) } }

		@((GetDockerPackages -Kind Model).Keys).Count | Should -Be 0
		@((GetDockerPackages -Kind Tooling).Keys) | Should -Be @('alpha')
	}

	It 'rejects duplicate, case-conflicting, and aliased marker generations' {
		@(GetCompleteRemoteModelCatalog -Tags @(
			'tlc-kind-model-v1-100-1--alpha',
			'tlc-kind-model-v1-0100-01--alpha'
		)).Found | Should -BeFalse

		@(GetCompleteRemoteModelCatalog -Tags @(
			'tlc-kind-model-v1-200-2--alpha',
			'tlc-kind-model-v1-200-2--ALPHA'
		)).Found | Should -BeFalse

		@(GetCompleteRemoteModelCatalog -Tags @(
			'tlc-kind-model-v1-300-0--empty',
			'tlc-kind-model-v1-0300-00--empty'
		)).Found | Should -BeFalse
	}

	It 'does not display models when the remote catalog contains no tooling packages' {
		Mock GetTagsList { @{ Tags = @(
			'qwen3-0.6b-1.0.0',
			'tlc-kind-model-v1-100-1--qwen3-0.6b'
		) } }

		$listCatalog = GetDockerTags -ToolingDefaultDisplay
		$listCatalog.PSObject.Properties.Name | Should -Contain 'qwen3-0.6b'
		$listCatalog.'Tooling packages' | Should -Be 'None'
		$rendered = $listCatalog | Out-String
		$rendered | Should -Match 'Tooling packages'
		$rendered | Should -Not -Match 'qwen3-0.6b'
	}

	It 'keeps raw metadata available through the diagnostic tag view' {
		$signature = 'sha256-' + ('f' * 64) + '.sig'
		Mock GetTagsList { @{ Tags = @('git-2.0.0', $signature) } }

		$tags = @(GetRemoteRegistryTags)
		$tags | Should -Contain 'git-2.0.0'
		$tags | Should -Contain $signature
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

Describe 'Local file package refs' {
	It 'parses root and trims config wrapper' {
		$r = 'file:///C:/toolchains/git<dev>' | ParseLocalPackageRef
		$r.Root | Should -Be 'C:/toolchains/git'
		$r.Config | Should -Be 'dev'
	}

	It 'defaults config and unescapes encoded paths' {
		$r = 'file:///C:/Program%20Files/Toolchain/git' | ParseLocalPackageRef
		$r.Root | Should -Match 'Program Files'
		$r.Config | Should -Be 'default'
	}

	It 'resolves local refs with clean config names' {
		$p = 'file:///C:/toolchains/git<ci>' | ResolvePackage
		$p.Package | Should -Be 'git'
		$p.Config | Should -Be 'ci'
		$p.Tag.Latest | Should -BeTrue
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

	It 'resolves a model while ignoring catalog and Cosign metadata tags' {
		Mock GetTagsList { @{ Tags = @(
			'qwen3-0.6b-2025.7.25_999',
			'qwen3-0.6b-2025.7.26_346',
			'tlc-kind-model-v1-100-1--qwen3-0.6b',
			('sha256-' + ('1' * 64) + '.sig')
		) } }

		$p = @{ Package='qwen3-0.6b'; Tag=@{ Latest=$true } }
		($p | ResolveDockerRef) | Should -Be 'qwen3-0.6b-2025.7.26_346'
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
		$prevToolchainPath = $global:ToolchainPath
		$dir = Join-Path $env:TEMP ('del-' + [Guid]::NewGuid().ToString())
		try {
			$global:ToolchainPath = Join-Path $env:TEMP ('tc-' + [Guid]::NewGuid().ToString())
			New-Item -ItemType Directory -Path $dir | Out-Null
			New-Item -ItemType File -Path (Join-Path $dir 'a.txt') -Value 'x' | Out-Null
			DeleteDirectory $dir
			(Test-Path -LiteralPath $dir) | Should -BeFalse
		} finally {
			$global:ToolchainPath = $prevToolchainPath
		}
	}
}
