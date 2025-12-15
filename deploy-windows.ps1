$ErrorActionPreference = 'Stop'
param(
  [Parameter(Mandatory = $true)][string]$FleetUrl,
  [Parameter(Mandatory = $true)][string]$EnrollmentToken,
  [Parameter(Mandatory = $true)][string]$PolicyId,
  [string]$Proxy = "",
  [string]$CaPath = ".\http_ca.crt",
  [string]$ArtifactPath = ".\elastic-agent-9.2.2-windows-x86_64.zip",
  [string]$CaptureInterfaceEthernet = "",
  [string]$CaptureInterfaceWifi = ""
)

function Assert-Admin {
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
  }
}

function Test-Connectivity($url) {
  try { Invoke-WebRequest -Uri $url -UseBasicParsing -Method Head -TimeoutSec 10 | Out-Null }
  catch { throw "Cannot reach $url. Check connectivity/firewall/TLS." }
}

function Ensure-Agent {
  if (-not (Test-Path $ArtifactPath)) { throw "Agent artifact not found at $ArtifactPath" }
  $dest = Join-Path $PSScriptRoot "elastic-agent"
  if (-not (Test-Path $dest)) {
    Expand-Archive -Path $ArtifactPath -DestinationPath $dest
  }
  return (Get-ChildItem -Path $dest -Recurse -Filter "elastic-agent.exe" | Select-Object -First 1).DirectoryName
}

function Get-NpcapDeviceFromAdapter($adapter) {
  if (-not $adapter -or -not $adapter.InterfaceGuid) { return "" }
  $guid = $adapter.InterfaceGuid.ToString().Trim('{}').ToUpper()
  return "\\Device\\NPF_{$guid}"
}

function ConvertTo-NpcapDevice([string]$Identifier) {
  if ([string]::IsNullOrWhiteSpace($Identifier)) { return "" }
  $trimmed = $Identifier.Trim()
  if ($trimmed -match "^\\\\Device\\\\NPF_") { return $trimmed }
  if ($trimmed -match "^NPF_") { return "\\Device\\$trimmed" }
  if ($trimmed -match "^[{(]?[0-9A-Fa-f-]{36}[)}]?$") {
    $guid = ($trimmed -replace '[{}()]', '').ToUpper()
    return "\\Device\\NPF_{$guid}"
  }
  if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
    $adapter = Get-NetAdapter -Name $trimmed -ErrorAction SilentlyContinue
    if (-not $adapter) {
      $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*$trimmed*" -or $_.Name -like "*$trimmed*" } | Select-Object -First 1
    }
    if ($adapter) { return Get-NpcapDeviceFromAdapter $adapter }
  }
  return ""
}

function Detect-CaptureInterfaces {
  param([string]$EthernetHint, [string]$WifiHint)
  $result = @{
    Ethernet = ConvertTo-NpcapDevice $EthernetHint
    Wifi = ConvertTo-NpcapDevice $WifiHint
  }
  if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
    if (-not $result.Ethernet -or -not $result.Wifi) {
      Write-Warning "Get-NetAdapter cmdlet unavailable; set CAPTURE_INTERFACE_* manually if packet capture should be enabled."
    }
    return $result
  }
  $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
  if (-not $result.Ethernet) {
    $wired = $adapters | Where-Object {
      ($_.NdisPhysicalMedium -and "$($_.NdisPhysicalMedium)" -match "802\.3") -or
      $_.InterfaceDescription -match "Ethernet|LAN" -or
      $_.Name -match "Ethernet"
    } | Select-Object -First 1
    if ($wired) { $result.Ethernet = Get-NpcapDeviceFromAdapter $wired }
  }
  if (-not $result.Wifi) {
    $wifi = $adapters | Where-Object {
      ($_.NdisPhysicalMedium -and "$($_.NdisPhysicalMedium)" -match "802\.11|Wireless") -or
      $_.InterfaceDescription -match "Wi-?Fi|Wireless" -or
      $_.Name -match "Wi-?Fi"
    } | Select-Object -First 1
    if ($wifi) { $result.Wifi = Get-NpcapDeviceFromAdapter $wifi }
  }
  return $result
}

function Set-CaptureInterfaceEnvironment($interfaces) {
  Set-InterfaceVar "CAPTURE_INTERFACE_ETHERNET" $interfaces.Ethernet
  Set-InterfaceVar "CAPTURE_INTERFACE_WIFI" $interfaces.Wifi
}

function Set-InterfaceVar($name, $value) {
  if ($value) {
    [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
    Write-Host "Set $name to $value"
  }
  else {
    [Environment]::SetEnvironmentVariable($name, $null, 'Machine')
    Write-Warning "$name not detected; the corresponding packet capture input will remain idle."
  }
}

function Install-Agent($agentDir) {
  $proxyArgs = ""
  if ($Proxy) { $proxyArgs = "--proxy $Proxy" }
  $cmd = ".\elastic-agent.exe install --url `"$FleetUrl`" --enrollment-token `"$EnrollmentToken`" --certificate-authorities `"$CaPath`" --non-interactive --force --policy-id `"$PolicyId`" $proxyArgs"
  Write-Host "Installing Elastic Agent with fleet URL $FleetUrl and policy $PolicyId"
  Push-Location $agentDir
  try { iex $cmd }
  finally { Pop-Location }
}

function Validate-Agent {
  $svc = Get-Service elastic-agent -ErrorAction SilentlyContinue
  if (-not $svc) { throw "Elastic Agent service missing after install." }
  if ($svc.Status -ne 'Running') { Start-Service elastic-agent }
  Start-Sleep -Seconds 5
  & "C:\Program Files\Elastic\Agent\elastic-agent.exe" status 2>$null
}

Assert-Admin
Test-Connectivity $FleetUrl
$agentDir = Ensure-Agent
$interfaces = Detect-CaptureInterfaces -EthernetHint $CaptureInterfaceEthernet -WifiHint $CaptureInterfaceWifi
Set-CaptureInterfaceEnvironment $interfaces
Install-Agent $agentDir
Validate-Agent
Write-Host "Elastic Agent enrolled and validated. Policy: $PolicyId" -ForegroundColor Green
