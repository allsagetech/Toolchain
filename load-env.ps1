<#
Toolchain
Copyright (c) 2026 AllSageTech
SPDX-License-Identifier: MPL-2.0
#>

$envFile = Join-Path $PSScriptRoot ".env"

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()

        if (-not $line -or $line.StartsWith('#')) { continue }

        if ($line -match '^\s*export\s+') { 
            $line = $line -replace '^\s*export\s+', '' 
        }

        $parts = $line -split '=', 2
        if ($parts.Count -ne 2) { continue }

        $key = $parts[0].Trim()
        $val = $parts[1].Trim()

        if ($val.Length -ge 2) {
            if (($val.StartsWith('"') -and $val.EndsWith('"')) -or 
                ($val.StartsWith("'") -and $val.EndsWith("'"))) {
                $val = $val.Substring(1, $val.Length - 2)
            }
        }
        if ($key) { Set-Item -Path "Env:$key" -Value $val }
    }
}
