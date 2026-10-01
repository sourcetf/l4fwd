# 在指定网卡上添加/删除 RAW 端到端测试所需的别名 IP。
#
# 用法（需要管理员权限）：
#   powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Add
#   powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Remove
#
# 默认在 detected 到的第一个可用网卡上添加 172.16.0.40 与 172.16.0.41，
# 前缀长度沿用该网卡上已有 /24 以内地址的掩码；可用参数覆盖：
#   -InterfaceName external -Base 172.16.0 -PrefixLength 24

param(
    [switch]$Add,
    [switch]$Remove,
    [string]$InterfaceName = "",
    [string]$Base = "172.16.0",
    [int]$PrefixLength = 24
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "需要管理员权限：请以管理员身份运行 PowerShell。"
    }
}

function Resolve-Interface {
    param([string]$Name)
    if ($Name -ne "") { return $Name }
    # 选第一个已启用、且有 IPv4 地址的物理网卡。
    $candidate = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Loopback"
    } | Select-Object -First 1
    if (-not $candidate) { throw "找不到可用网卡，请用 -InterfaceName 指定。" }
    return $candidate.Name
}

Assert-Admin
$iface = Resolve-Interface $InterfaceName
$client = "$Base.40"
$target = "$Base.41"

if ($Add) {
    foreach ($ip in @($client, $target)) {
        $existing = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $ip }
        if ($existing) {
            Write-Host "已存在：$ip"
            continue
        }
        Write-Host "添加 $ip/$PrefixLength 到 $iface"
        New-NetIPAddress -InterfaceAlias $iface -IPAddress $ip -PrefixLength $PrefixLength | Out-Null
    }
    Start-Sleep -Seconds 1
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "$Base.*" } |
        Select-Object IPAddress, InterfaceAlias, PrefixLength | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "完成。现在可以运行：bash scripts/e2e.sh"
}

if ($Remove) {
    foreach ($ip in @($client, $target)) {
        $existing = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $ip }
        if (-not $existing) {
            Write-Host "不存在：$ip"
            continue
        }
        Write-Host "删除 $ip"
        Remove-NetIPAddress -IPAddress $ip -Confirm:$false
    }
    Write-Host "已清理别名地址。"
}

