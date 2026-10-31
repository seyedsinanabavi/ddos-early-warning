# Runs vet and tests on Windows without -race (the race detector needs cgo).
# Pass -Build to also build bin\ddos-ew.exe.
[CmdletBinding()]
param(
    [switch]$Build
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Invoke-Step {
    param([string]$Name, [scriptblock]$Command)
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Invoke-Step "go vet" { go vet ./... }
Invoke-Step "go test" { go test -count=1 ./... }

if ($Build) {
    New-Item -ItemType Directory -Force -Path "bin" | Out-Null
    Invoke-Step "go build" { go build -o "bin\ddos-ew.exe" ".\cmd\ddos-ew" }
}

Write-Host "All steps passed." -ForegroundColor Green