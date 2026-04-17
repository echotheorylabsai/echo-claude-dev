# common-config.ps1
#
# Shared configuration paths, error helpers, and governance audit log bootstrap
# for secure-copilot PowerShell hooks.
#
# PowerShell equivalent of common-config.sh. Every hook dot-sources this file
# to obtain consistent plugin root resolution, config directory helpers, log
# path setup, and a POSIX-to-.NET regex translation layer so the same generated
# JSON rule files work on both platforms.
#

# ── Plugin root resolution ────────────────────────────────────────────────────

function Get-SecureCopilotPluginRoot {
  if ($env:SECURE_COPILOT_PLUGIN_ROOT) {
    return $env:SECURE_COPILOT_PLUGIN_ROOT
  }
  $scriptDir = Split-Path -Parent $PSCommandPath
  return (Resolve-Path (Join-Path $scriptDir ".." ".." "..")).Path
}

function Get-SecureCopilotShippedConfigDir {
  return Join-Path (Get-SecureCopilotPluginRoot) "hooks" "config"
}

function Get-SecureCopilotGeneratedConfigDir {
  return Join-Path (Get-SecureCopilotShippedConfigDir) "generated"
}

function Get-SecureCopilotPromptRulesJson {
  return Join-Path (Get-SecureCopilotGeneratedConfigDir) "user-prompt-threats.json"
}

function Get-SecureCopilotToolRulesJson {
  return Join-Path (Get-SecureCopilotGeneratedConfigDir) "tool-rules.json"
}

function Get-SecureCopilotIndirectRulesJson {
  return Join-Path (Get-SecureCopilotGeneratedConfigDir) "indirect-injection-patterns.json"
}

# ── User-local config paths ──────────────────────────────────────────────────

function Get-SecureCopilotUserOverrideYaml {
  return Join-Path $HOME ".config" "secure-copilot" "overrides.yaml"
}

function Get-SecureCopilotUserGeneratedDir {
  return Join-Path $HOME ".config" "secure-copilot" "generated"
}

function Get-SecureCopilotUserPromptRulesJson {
  return Join-Path (Get-SecureCopilotUserGeneratedDir) "user-prompt-threats.json"
}

function Get-SecureCopilotUserToolRulesJson {
  return Join-Path (Get-SecureCopilotUserGeneratedDir) "tool-rules.json"
}

function Get-SecureCopilotUserIndirectRulesJson {
  return Join-Path (Get-SecureCopilotUserGeneratedDir) "indirect-injection-patterns.json"
}

# ── Config error logging ─────────────────────────────────────────────────────

function Write-SecureCopilotConfigError {
  param(
    [string]$LogFile,
    [string]$Source,
    [string]$Message
  )

  $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

  if ($LogFile) {
    $logDir = Split-Path -Parent $LogFile
    if (-not (Test-Path $logDir)) {
      New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $entry = [ordered]@{
      timestamp = $timestamp
      event     = "configError"
      source    = $Source
      message   = $Message
    }
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path $LogFile -Encoding UTF8
  }

  [Console]::Error.WriteLine("${Source}: ${Message}")
}

# ── JSON readability check ───────────────────────────────────────────────────

function Test-SecureCopilotJsonReadable {
  param([string]$JsonFile)

  if (-not (Test-Path $JsonFile)) { return $false }
  try {
    $null = Get-Content -Raw $JsonFile | ConvertFrom-Json
    return $true
  }
  catch {
    return $false
  }
}

# ── POSIX ERE to .NET regex translation ──────────────────────────────────────
# The generated JSON rule files use POSIX Extended Regular Expression character
# classes (e.g., [[:space:]], [[:alnum:]]). PowerShell uses .NET regex which
# does not support these. This function translates them at load time.

function ConvertFrom-PosixRegex {
  param([string]$Pattern)

  $result = $Pattern

  # Handle standalone POSIX classes: [[:class:]] → .NET equivalent
  # These are complete bracket expressions containing only the POSIX class.
  $result = $result -replace '\[\[:space:\]\]',  '\s'
  $result = $result -replace '\[\[:print:\]\]',  '\P{C}'
  $result = $result -replace '\[\[:punct:\]\]',  '\p{P}'

  # Handle POSIX classes inside larger bracket expressions: [:class:] → range
  # e.g., [[:alnum:]_.-] → [a-zA-Z0-9_.-]
  $result = $result -replace '\[:space:\]',  '\s'
  $result = $result -replace '\[:alnum:\]',  'a-zA-Z0-9'
  $result = $result -replace '\[:alpha:\]',  'a-zA-Z'
  $result = $result -replace '\[:digit:\]',  '0-9'
  $result = $result -replace '\[:upper:\]',  'A-Z'
  $result = $result -replace '\[:lower:\]',  'a-z'
  $result = $result -replace '\[:punct:\]',  '\p{P}'
  $result = $result -replace '\[:print:\]',  '\P{C}'
  return $result
}

# ── Governance audit log bootstrap ───────────────────────────────────────────
# Sets script-scoped variables: $script:Timestamp, $script:ProjectName,
# $script:LogDir, $script:LogFile

function Initialize-GovernanceAuditLog {
  param([string]$Cwd = "")

  if (-not $Cwd) { $Cwd = (Get-Location).Path }

  $script:Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

  # Derive project name from git repo root; fall back to directory basename
  $gitRoot = ""
  try {
    Push-Location $Cwd
    $gitRoot = & git rev-parse --show-toplevel 2>$null
    Pop-Location
  }
  catch {
    Pop-Location
  }

  if ($gitRoot) {
    $script:ProjectName = Split-Path -Leaf $gitRoot
  }
  else {
    $script:ProjectName = Split-Path -Leaf $Cwd
  }

  $script:LogDir  = Join-Path $HOME "progress-ai" "secure-copilot" "logs" $script:ProjectName
  $script:LogFile = Join-Path $script:LogDir "governance-audit.jsonl"

  if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
  }
}
