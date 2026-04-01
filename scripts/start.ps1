Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker is required. Install Docker Desktop / Docker Engine and re-run."
}

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

function GenKeyB64 {
  if (Get-Command python3 -ErrorAction SilentlyContinue) {
    return (python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode(),end='')")
  } elseif (Get-Command openssl -ErrorAction SilentlyContinue) {
    return (openssl rand -base64 32).Trim()
  } else {
    Write-Error "python3 or openssl required to generate encryption keys"
  }
}

function GenToken {
  if (Get-Command python3 -ErrorAction SilentlyContinue) {
    return (python3 -c "import os;print(os.urandom(24).hex(),end='')")
  } elseif (Get-Command openssl -ErrorAction SilentlyContinue) {
    return (openssl rand -hex 24).Trim()
  } else {
    Write-Error "python3 or openssl required to generate tokens"
  }
}

function FillKey($var, $generator) {
  $content = Get-Content ".env" -Raw
  if ($content -match "(?m)^${var}=.+") { return }
  $key = & $generator
  $content = $content -replace "(?m)^${var}=.*", "${var}=${key}"
  Set-Content ".env" $content -NoNewline
  Write-Host "Generated ${var}"
}

FillKey "AUTODEFENSE_DATA_KEY_B64"      { GenKeyB64 }
FillKey "AUTODEFENSE_TRANSPORT_KEY_B64" { GenKeyB64 }
FillKey "AUTODEFENSE_API_KEY"           { GenToken }
FillKey "AUTODEFENSE_SCANNER_HMAC_KEY"  { GenToken }
FillKey "AUTODEFENSE_REDIS_PASSWORD"    { GenToken }

$apiKey = ((Get-Content ".env") | Where-Object { $_ -match "^AUTODEFENSE_API_KEY=" }) -replace "^AUTODEFENSE_API_KEY=", ""
Write-Host ""
Write-Host "=============================="
Write-Host "  API Key (save this): $apiKey"
Write-Host "=============================="
Write-Host ""

docker compose up --build
