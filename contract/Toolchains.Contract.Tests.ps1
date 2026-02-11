<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

BeforeAll {
  . "$PSScriptRoot\..\src\tlc.ps1"

  $script:hasPayload = ($env:TLC_CONTRACT_PACKAGE_NAME -and $env:TLC_CONTRACT_DIGEST)

  $global:ToolchainPath = Join-Path $env:RUNNER_TEMP "toolchain-contract"
  Remove-Item -LiteralPath $global:ToolchainPath -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $global:ToolchainPath -Force | Out-Null

  if ($env:TLC_CONTRACT_DOCKER_REPO) {
    $env:TOOLCHAIN_REPOSITORY = $env:TLC_CONTRACT_DOCKER_REPO
  }

  $script:pkgName = [string]$env:TLC_CONTRACT_PACKAGE_NAME
  $script:pkgVer  = [string]$env:TLC_CONTRACT_PACKAGE_VERSION
  $script:digest  = [string]$env:TLC_CONTRACT_DIGEST
  if ($script:digest -and -not $script:digest.StartsWith('sha256:')) {
    $script:digest = "sha256:$script:digest"
  }
  $script:tlcSha256 = [string]$env:TLC_CONTRACT_TLC_SHA256
}

AfterAll {
  Remove-Item -LiteralPath $global:ToolchainPath -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Toolchains contract (Toolchain consumer)' {
  It 'skips when payload is missing' -Skip:$script:hasPayload {
    $true | Should -BeTrue
  }

  Context 'pull by semver tag' {
    It 'pulls and pins to the expected digest' -Skip:(-not $script:hasPayload) {
      Invoke-ToolchainPull -Packages @("$($script:pkgName):$($script:pkgVer)")
      $pkg = AsPackage "$($script:pkgName):$($script:pkgVer)"
      $got = $pkg | ResolvePackageDigest
      $got | Should -Be $script:digest
    }
  }

  Context 'pull by digest pin' {
    It 'accepts pkg@sha256:... and installs to the expected digest' -Skip:(-not $script:hasPayload) {
      Invoke-ToolchainPull -Packages @("$($script:pkgName)@$($script:digest)")
      $pkg = AsPackage "$($script:pkgName)@$($script:digest)"
      $got = $pkg | ResolvePackageDigest
      $got | Should -Be $script:digest
    }
  }

  Context 'toolchain definition integrity' {
    It 'loads the toolchain definition and validates tlc sha256 when provided' -Skip:(-not $script:hasPayload) {
      $root = ResolvePackagePath -Digest $script:digest
      $def = GetToolchainDefinitionFromLabels -Ref $script:digest -RootPath $root
      $def | Should -Not -BeNullOrEmpty

      if ($script:tlcSha256) {
        $tlcPath = Join-Path $root '.tlc'
        if (-not (Test-Path -LiteralPath $tlcPath)) {
          $rel = $env:TLC_CONTRACT_TLC_PATH
          if ($rel) {
            $rel = [string]$rel
            if ($rel.StartsWith('/')) { $rel = $rel.Substring(1) }
            $tlcPath = Join-Path $root $rel
          }
        }

        (Test-Path -LiteralPath $tlcPath) | Should -BeTrue
        $actual = (Get-FileHash -Algorithm SHA256 -Path $tlcPath).Hash.ToLower()
        $actual | Should -Be $script:tlcSha256.ToLower()
      }
    }

    It 'expands ${.} and produces only existing paths for env.Path' -Skip:(-not $script:hasPayload) {
      $root = ResolvePackagePath -Digest $script:digest
      $tlcPath = Join-Path $root '.tlc'
      (Test-Path -LiteralPath $tlcPath) | Should -BeTrue

      $json = (Get-Content -LiteralPath $tlcPath -Raw).Replace('${.}', $root.Replace('\','\\'))
      $def = ($json | ConvertFrom-Json | ConvertTo-HashTable)
      Assert-ToolchainDefinition -Definition $def -Context 'contract'

      $pathVal = $def.env.Path
      if ($null -eq $pathVal) { $pathVal = $def.env.PATH }

      $parts = @()
      if ($pathVal -is [string]) {
        $parts = $pathVal -split ';'
      } elseif ($pathVal -is [System.Collections.IEnumerable]) {
        foreach ($x in $pathVal) { if ($x) { $parts += [string]$x } }
      }

      foreach ($x in $parts) {
        $x = $x.Trim()
        if (-not $x) { continue }
        (Test-Path -LiteralPath $x) | Should -BeTrue
      }
    }
  }
}
