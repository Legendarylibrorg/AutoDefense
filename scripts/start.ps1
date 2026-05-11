Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker is required. Install Docker Desktop / Docker Engine and re-run."
}

function Invoke-DockerCompose {
  [CmdletBinding()]
  param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommandArgs
  )
  docker compose version *>$null
  if ($LASTEXITCODE -eq 0) {
    & docker compose @CommandArgs
    return
  }
  if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    & docker-compose @CommandArgs
    return
  }
  Write-Error "Docker Compose is required: install the Compose V2 plugin (docker compose) or docker-compose."
}

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

function GenKeyB64 {
  if (Get-Command python3 -ErrorAction SilentlyContinue) {
    return (python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode(),end='')")
  }
  if (Get-Command openssl -ErrorAction SilentlyContinue) {
    return (openssl rand -base64 32).Trim()
  }
  Write-Error "python3 or openssl required to generate encryption keys"
}

function GenToken {
  if (Get-Command python3 -ErrorAction SilentlyContinue) {
    return (python3 -c "import os;print(os.urandom(24).hex(),end='')")
  }
  if (Get-Command openssl -ErrorAction SilentlyContinue) {
    return (openssl rand -hex 24).Trim()
  }
  Write-Error "python3 or openssl required to generate tokens"
}

function FillKey {
  param([string]$VarName, [scriptblock]$Generator)
  $path = Join-Path (Get-Location) ".env"
  $content = [System.IO.File]::ReadAllText($path)
  if ($content -match "(?m)^${VarName}=.+`$") {
    return
  }
  $key = & $Generator
  $newContent = $content -replace "(?m)^${VarName}=.*", "${VarName}=${key}"
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  $text = $newContent.TrimEnd("`r", "`n") + [Environment]::NewLine
  [System.IO.File]::WriteAllText($path, $text, $utf8)
  Write-Host "Generated ${VarName}"
}

FillKey "AUTODEFENSE_DATA_KEY_B64"      { GenKeyB64 }
FillKey "AUTODEFENSE_TRANSPORT_KEY_B64" { GenKeyB64 }
FillKey "AUTODEFENSE_API_KEY"           { GenToken }
FillKey "AUTODEFENSE_SCANNER_HMAC_KEY"  { GenToken }
FillKey "AUTODEFENSE_REDIS_PASSWORD"    { GenToken }

$apiLine = (Get-Content ".env") | Where-Object { $_ -match "^AUTODEFENSE_API_KEY=" } | Select-Object -First 1
$apiKey = if ($apiLine) { $apiLine -replace "^AUTODEFENSE_API_KEY=", "" } else { "" }
Write-Host ""
Write-Host "=============================="
Write-Host "  API Key (save this): $apiKey"
Write-Host "=============================="
Write-Host ""

Invoke-DockerCompose config -q
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
Invoke-DockerCompose up --build
exit $LASTEXITCODE
