$ErrorActionPreference = 'Stop'

$Namespace = 'default'
$ServiceName = 'terraform-scanner-frontend-service'
$RemotePort = 80

function Test-PortInUse([int]$Port) {
  $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  return $null -ne $conn
}

function Get-FreePort([int]$StartPort, [int]$MaxPort = 65535) {
  for ($p = $StartPort; $p -le $MaxPort; $p++) {
    if (-not (Test-PortInUse -Port $p)) { return $p }
  }
  throw "No free port found starting at $StartPort"
}

$LocalPort = Get-FreePort -StartPort 18080

Write-Host "[1/3] Checking kubectl..."
kubectl version --client | Out-Null

Write-Host "[2/3] Verifying service exists: $Namespace/$ServiceName"
kubectl -n $Namespace get svc $ServiceName | Out-Null

Write-Host "[3/3] Port-forwarding http://<THIS-PC-IP>:$LocalPort -> ${Namespace}/${ServiceName}:${RemotePort}"
Write-Host "Open from this PC: http://localhost:$LocalPort"
Write-Host "Open from another PC: http://<THIS-PC-IP>:$LocalPort"
Write-Host "Stop with Ctrl+C"

kubectl -n $Namespace port-forward --address 0.0.0.0 "svc/$ServiceName" "$LocalPort`:$RemotePort"