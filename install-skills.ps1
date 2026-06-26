#!/usr/bin/env pwsh
# Install the named-mode skills as personal skills so they're available in every project.
#
#   pwsh -File install-skills.ps1            # copy each skill into ~\.claude\skills
#   pwsh -File install-skills.ps1 -Symlink   # symlink instead (repo edits stay live)
#   # or from a PowerShell prompt in this folder:  .\install-skills.ps1
#
# After the first install, restart Claude Code once: a newly created
# ~\.claude\skills directory is only watched after a restart.
param([switch]$Symlink)
$ErrorActionPreference = 'Stop'

$srcDir  = Join-Path $PSScriptRoot '.claude/skills'
$destDir = Join-Path $HOME '.claude/skills'

if (-not (Test-Path $srcDir)) { Write-Error "Source skills directory not found: $srcDir"; exit 1 }
New-Item -ItemType Directory -Force -Path $destDir | Out-Null

$count = 0
Get-ChildItem -Path $srcDir -Directory | ForEach-Object {
    if (-not (Test-Path (Join-Path $_.FullName 'SKILL.md'))) { return }   # only real skill dirs
    $target = Join-Path $destDir $_.Name
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    if ($Symlink) {
        try { New-Item -ItemType SymbolicLink -Path $target -Target $_.FullName | Out-Null }
        catch { Write-Warning "symlink failed for $($_.Name) (needs admin/Dev Mode); copying instead"; Copy-Item -Recurse -Force $_.FullName $target }
    } else {
        Copy-Item -Recurse -Force $_.FullName $target
    }
    Write-Host "  installed $($_.Name)"
    $count++
}

Write-Host ""
Write-Host "Installed $count skills into $destDir."
Write-Host "Now restart Claude Code once so the skills directory is picked up, then type / to see them."
