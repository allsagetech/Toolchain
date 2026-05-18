<#
Toolchains
Copyright (c) 2021 - 02-08-2026 U.S. Federal Government
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe 'ExecuteScript' {
	Context 'Example Packages' {
		BeforeAll {
			Mock ResolvePackageDigest {
				param (
					[Parameter(Mandatory, ValueFromPipeline)]
					[Collections.Hashtable]$Pkg
				)
				return @{
					'somepkg' = 'sha256-1'
					'anotherpkg' = 'sha256-2'
				}[$Pkg.Package]
			}
			Mock GetPackageDefinition {
				param (
					[Parameter(Mandatory, ValueFromPipeline)]
					[string]$Digest
				)
				return @{
					'sha256-1' = @{
						Env = @{
							'var1' = 'val'
							'path' = 'zzz'
						}
					}
					'sha256-2' = @{
						Env = @{
							'path' = 'fizz'
							'foo' = 'bar'
						}
					}
				}[$Digest]
			}
			function SomeFn { }
			Mock SomeFn { }
		}
		AfterAll {
			Remove-Item 'env:var1' -Force -ErrorAction SilentlyContinue
			Remove-Item 'env:foo' -Force -ErrorAction SilentlyContinue
		}
		It 'Configures' {
			$SysPath = "$env:SYSTEMROOT;$env:SYSTEMROOT\System32;$PSHOME"
			$originalPath = Get-ToolchainPathValue
			try {
				Set-ToolchainPathValue $SysPath
				$ExpectedBasePath = Get-ToolchainPathValue
				Get-ToolchainPathValue | Should -Not -BeLike '*zzz;*'
				$env:var1 | Should -BeNullOrEmpty
				ExecuteScript -Pkgs @{
					Package = 'somepkg'
					Tag = @{ Latest = $true }
					Config = 'default'
				} -ScriptBlock {
					SomeFn
					$yyy = '123'
					$yyy | Should -Not -BeNullOrEmpty
					$script:xxx = '987'
					$script:xxx | Should -Not -BeNullOrEmpty
					Get-ToolchainPathValue | Should -Be "zzz;$ExpectedBasePath"
					$env:var1 | Should -Be 'val'
				}
				Should -Invoke SomeFn -Times 1 -Exactly
				Get-ToolchainPathValue | Should -Not -BeLike '*zzz;*'
				$env:var1 | Should -Be 'val'
				$xxx | Should -Be '987'
				$yyy | Should -BeNullOrEmpty
			} finally {
				Set-ToolchainPathValue $originalPath
			}
		}
		It 'Nests' {
			$SysPath = "$env:SYSTEMROOT;$env:SYSTEMROOT\System32;$PSHOME"
			$originalPath = Get-ToolchainPathValue
			try {
				Set-ToolchainPathValue $SysPath
				$ExpectedBasePath = Get-ToolchainPathValue
				ExecuteScript -Pkgs @{
					Package = 'somepkg'
					Tag = @{ Latest = $true }
					Config = 'default'
				} -ScriptBlock {
					ExecuteScript -Pkgs @{
						Package = 'anotherpkg'
						Tag = @{ Latest = $true }
						Config = 'default'
					} -ScriptBlock {
						SomeFn
						Get-ToolchainPathValue | Should -Be "fizz;$ExpectedBasePath"
						$env:foo | Should -Be 'bar'
					}
					Get-ToolchainPathValue | Should -Be "zzz;$ExpectedBasePath"
				}
				Should -Invoke SomeFn -Times 1 -Exactly
			} finally {
				Set-ToolchainPathValue $originalPath
			}
		}
	}
}

Describe 'ConfigurePackage' {
	BeforeAll {
		$script:_Path = Get-ToolchainPathValue
		Mock GetPackageDefinition {
			@{
				Env = @{
					'path' = 'zzz'
				}
			}
		}
	}
	AfterAll {
		Set-ToolchainPathValue $_Path
	}
	It 'Appends' {
		Set-ToolchainPathValue 'PATH'
		$pkg = @{
			Config = 'default'
			Package = 'foo'
			Tag = @{ Latest = $true }
			Digest = 'sha256'
		}
		$pkg | ConfigurePackage
		Get-ToolchainPathValue | Should -Be 'zzz;PATH'
	}
	It 'Prepends' {
		Set-ToolchainPathValue 'PATH'
		$pkg = @{
			Config = 'default'
			Package = 'foo'
			Tag = @{ Latest = $true }
			Digest = 'sha256'
		}
		$pkg | ConfigurePackage -AppendPath
		Get-ToolchainPathValue | Should -Be 'PATH;zzz'
	}
}
