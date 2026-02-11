<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
	. "$PSScriptRoot\definition.ps1"
}

Describe 'Assert-ToolchainEnvMap' {
	It 'throws when env map is not an object/map' {
		{ Assert-ToolchainEnvMap -EnvMap 1 -Context 'x' } | Should -Throw -ErrorId *
	}

	It 'throws on empty variable name' {
		$envMap = @{ ' ' = 'a' }
		{ Assert-ToolchainEnvMap -EnvMap $envMap -Context 'c' } | Should -Throw
	}

	It 'allows strings and string arrays (ignoring nulls)' {
		$envMap = @{ A='1'; B=@('x',$null,'y') }
		{ Assert-ToolchainEnvMap -EnvMap $envMap -Context 'ok' } | Should -Not -Throw
	}

	It 'throws when array contains non-strings' {
		$envMap = @{ A=@('x',2) }
		{ Assert-ToolchainEnvMap -EnvMap $envMap -Context 'bad' } | Should -Throw
	}

	It 'throws when value is unsupported type' {
		$envMap = @{ A = @{ Nested = 1 } }
		{ Assert-ToolchainEnvMap -EnvMap $envMap -Context 'bad' } | Should -Throw
	}
}

Describe 'Assert-ToolchainDefinition' {
	It 'requires top-level env' {
		{ Assert-ToolchainDefinition -Definition @{} -Context 'def' } | Should -Throw '*missing required top-level*'
	}

	It 'requires each config block to be an object with env' {
		$def = @{ env = @{ X='1' }; foo = 'bar' }
		{ Assert-ToolchainDefinition -Definition $def -Context 'def' } | Should -Throw

		$def2 = @{ env = @{ X='1' }; foo = @{ } }
		{ Assert-ToolchainDefinition -Definition $def2 -Context 'def' } | Should -Throw
	}

	It 'accepts a valid definition with config blocks' {
		$def = @{ env = @{ X='1'; Path=@('a','b') }; dev = @{ env = @{ Y='2' } } }
		{ Assert-ToolchainDefinition -Definition $def -Context 'def' } | Should -Not -Throw
	}
}

Describe 'ConvertTo-SemicolonString' {
	It 'handles null, string, arrays and other objects' {
		($null | ConvertTo-SemicolonString) | Should -Be ''
		('x' | ConvertTo-SemicolonString) | Should -Be 'x'
		(@(' a ','', $null,'b') | ConvertTo-SemicolonString) | Should -Be 'a;b'
		(123 | ConvertTo-SemicolonString) | Should -Be '123'
	}
}
