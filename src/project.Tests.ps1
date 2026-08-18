<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	function AsTagString {
		param([Parameter(ValueFromPipeline)]$Tag)
		process {
			if ($Tag.Latest) { 'latest' }
			elseif ($Tag.Raw) { [string]$Tag.Raw }
			else { [string]$Tag }
		}
	}
	function AsPackage {
		param([Parameter(ValueFromPipeline)][string]$Pkg)
		process {
			if ($Pkg -match '^([^:@]+)@(sha256:[0-9a-fA-F]{64})(?:::([^:]+))?$') {
				return @{ Package=$Matches[1]; Digest=$Matches[2]; Config=$(if ($Matches[3]) { $Matches[3] } else { 'default' }) }
			}
			if ($Pkg -match '^([^:]+)(?::([^:]+))?(?:::([^:]+))?$') {
				return @{ Package=$Matches[1]; Tag=$(if ($Matches[2]) { @{ Raw=$Matches[2] } } else { @{ Latest=$true } }); Config=$(if ($Matches[3]) { $Matches[3] } else { 'default' }) }
			}
			throw "invalid package: $Pkg"
		}
	}
	function GetDockerTags { }
	function Get-ToolchainBytesSha256Digest {
		param([byte[]]$Bytes)
		$sha = [Security.Cryptography.SHA256]::Create()
		try { 'sha256:' + [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
		finally { $sha.Dispose() }
	}
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'Toolchain YAML parsing and schema' {
	It 'parses mappings, package sequences, dependencies, comments, and quoted constraints' {
		$manifest = ConvertFrom-ToolchainYaml -Text @'
schemaVersion: 1
packages:
  - name: pnpm # application package
    version: latest
    dependencies:
      - name: node
        version: ">=22 <25"
  - git:latest
'@
		$manifest.schemaVersion | Should -Be 1
		@($manifest.packages).Count | Should -Be 2
		$manifest.packages[0].name | Should -Be 'pnpm'
		$manifest.packages[0].dependencies[0].version | Should -Be '>=22 <25'
		$manifest.packages[1] | Should -Be 'git:latest'
	}

	It 'rejects tabs, odd indentation, duplicate keys, and unsupported controls' {
		{ ConvertFrom-ToolchainYaml -Text "schemaVersion:`t1" } | Should -Throw '*tabs*'
		{ ConvertFrom-ToolchainYaml -Text "schemaVersion: 1`n packages:`n   - git" } | Should -Throw '*multiples of two*'
		{ ConvertFrom-ToolchainYaml -Text "schemaVersion: 1`nschemaVersion: 1" } | Should -Throw '*duplicate key*'
		{ ConvertFrom-ToolchainYaml -Text "schemaVersion: 1`npackages:`n  - name: [git]" } | Should -Throw '*unsupported YAML scalar*'
	}
}

Describe 'Toolchain version constraints' {
	It 'supports prefixes, comparators, caret, tilde, wildcard, AND, and OR expressions' {
		Test-ToolchainVersionConstraint 24.2.3 24 | Should -BeTrue
		Test-ToolchainVersionConstraint 24.2.3 '>=22 <25' | Should -BeTrue
		Test-ToolchainVersionConstraint 24.2.3 '^24.1' | Should -BeTrue
		Test-ToolchainVersionConstraint 24.2.3 '~24.2' | Should -BeTrue
		Test-ToolchainVersionConstraint 24.2.3 '24.x' | Should -BeTrue
		Test-ToolchainVersionConstraint 24.2.3 '<20 || >=24' | Should -BeTrue
		Test-ToolchainVersionConstraint 25.0.0 '^24.1' | Should -BeFalse
		{ Test-ToolchainVersionConstraint 24.2.3 'not a constraint' } | Should -Throw '*invalid version constraint*'
	}
}

Describe 'Toolchain project dependency resolution' {
	BeforeEach {
		Mock GetDockerTags {
			[pscustomobject]@{
				node = @('22.9.0', '24.2.0', '25.0.0')
				pnpm = @('9.1.0', '10.0.0')
				git = @('2.50.0')
				a = @('1.0.0')
				b = @('1.0.0')
			}
		}
	}

	It 'merges constraints and orders dependencies before dependents' {
		$specs = @(
			ConvertTo-ToolchainProjectPackageSpec @{
				name='pnpm'; version='latest'; dependencies=@(@{ name='node'; version='^24' })
			}
			ConvertTo-ToolchainProjectPackageSpec @{ name='node'; version='>=22 <25' }
		)
		@(Resolve-ToolchainProjectPackages -PackageSpecs $specs) | Should -Be @('node:24.2.0::default', 'pnpm:10.0.0::default')
		Should -Invoke GetDockerTags -Times 1 -Exactly
	}

	It 'rejects unsatisfied merged requirements, configuration conflicts, and cycles' {
		$unsatisfied = @(
			ConvertTo-ToolchainProjectPackageSpec @{ name='node'; version='^24' }
			ConvertTo-ToolchainProjectPackageSpec @{ name='node'; version='>=25' }
		)
		{ Resolve-ToolchainProjectPackages -PackageSpecs $unsatisfied } | Should -Throw '*satisfies constraints*'

		$conflict = @(
			ConvertTo-ToolchainProjectPackageSpec @{ name='node'; version='24'; configuration='dev' }
			ConvertTo-ToolchainProjectPackageSpec @{ name='node'; version='24'; configuration='release' }
		)
		{ Resolve-ToolchainProjectPackages -PackageSpecs $conflict } | Should -Throw '*conflicting configurations*'

		$a = @{ Name='a'; Constraint='1'; Configuration='default'; Dependencies=@(@{ Name='b'; Constraint='1'; Configuration='default'; Dependencies=@() }) }
		$b = @{ Name='b'; Constraint='1'; Configuration='default'; Dependencies=@(@{ Name='a'; Constraint='1'; Configuration='default'; Dependencies=@() }) }
		{ Resolve-ToolchainProjectPackages -PackageSpecs @($a,$b) } | Should -Throw '*dependency cycle*'
	}

	It 'reads YAML projects and produces a stable intent digest' {
		$path = Join-Path $TestDrive 'toolchain.yaml'
		Set-Content -LiteralPath $path -Encoding utf8 -Value @'
schemaVersion: 1
packages:
  - name: node
    version: ">=22 <25"
'@
		$first = Read-ToolchainProject -Path $path
		$metadataOnly = Read-ToolchainProject -Path $path -NoResolve
		$first.Packages | Should -Be @('node:24.2.0::default')
		$metadataOnly.Packages | Should -BeNullOrEmpty
		$metadataOnly.PackageNames | Should -Be @('node')
		$first.Digest | Should -Be $metadataOnly.Digest
		$first.Digest | Should -Match '^sha256:[0-9a-f]{64}$'
	}

	It 'accepts a deployment-only toolchain.yaml without resolving developer packages' {
		$path = Join-Path $TestDrive 'toolchain.yaml'
		Set-Content -LiteralPath $path -Encoding utf8 -Value @'
schemaVersion: 1
deployment:
  name: demo
  version: 1.0.0
  manifests:
    - deployment.yaml
'@
		$project = Read-ToolchainProject -Path $path
		$project.Packages | Should -BeNullOrEmpty
		$project.Deployment.name | Should -BeExactly 'demo'
	}
}
