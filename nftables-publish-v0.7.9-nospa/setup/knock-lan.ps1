# knock-lan.ps1 — LAN 端口敲门客户端（nftables-web-v2, Windows PowerShell）
#
# nftables 模板里 chain knock_lan 已实现 LAN 端 4 步敲门流程：
#   knock1 (8s 内) -> knock2 (8s 内) -> knock3 (8s 内) -> knock4 -> 加入 @allowed4
# 白名单默认持续 5 小时（whitelist_timeout 配置）。
#
# 用法：
#   .\knock-lan.ps1
#   .\knock-lan.ps1 -Host 192.168.4.1
#   .\knock-lan.ps1 -Ports "1234,5678,9012,3456"
#   .\knock-lan.ps1 -Host 192.168.4.1 -Ports "1234,5678,9012,3456"
#   .\knock-lan.ps1 -Host 192.168.4.1 -Ports "1234,5678,9012,3456" -IntervalSeconds 1
#
# 验证方法（路由器上）：
#   nft list set inet fw4 allowed4
# 应能看到你的客户端 IP（带 expires 过期时间）
#
# 注意：Windows 默认没有 nftables 配置路径，所以本脚本不自动读取配置，
# 必须显式传 -Host 和 -Ports。

[CmdletBinding()]
param(
    [string]$Host = "",
    [string]$Ports = "",
    [int]$IntervalSeconds = 1
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Host) -or [string]::IsNullOrWhiteSpace($Ports)) {
    Write-Host "ERROR: 必须显式指定 -Host 和 -Ports 参数" -ForegroundColor Red
    Write-Host ""
    Write-Host "示例："
    Write-Host "  .\knock-lan.ps1 -Host 192.168.4.1 -Ports '1234,5678,9012,3456'"
    exit 1
}

$portArr = $Ports -split "," | ForEach-Object { $_.Trim() }
if ($portArr.Count -ne 4) {
    Write-Host "ERROR: -Ports 必须是 4 个端口，逗号分隔。当前: $Ports" -ForegroundColor Red
    exit 1
}

foreach ($p in $portArr) {
    if (-not ($p -match '^\d+$') -or [int]$p -lt 1 -or [int]$p -gt 65535) {
        Write-Host "ERROR: 无效端口 '$p'（必须 1-65535 的整数）" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[LAN-Knock] target=$Host ports=$($portArr -join ' ') interval=${IntervalSeconds}s"

function Send-UdpKnock {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][int]$Port
    )
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.SendTimeout = 2000
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("k")
        $null = $udpClient.Send($bytes, $bytes.Length, $Target, $Port)
        $udpClient.Close()
    } catch {
        # UDP 无连接，路由丢弃也算正常发送成功；只记录非网络错误
        Write-Verbose "UDP send to $Target`:$Port : $_"
    }
}

for ($i = 0; $i -lt 4; $i++) {
    $port = [int]$portArr[$i]
    Write-Host "[LAN-Knock] step $($i+1) -> $Host`:$port"
    Send-UdpKnock -Target $Host -Port $port
    if ($i -lt 3) {
        Start-Sleep -Seconds $IntervalSeconds
    }
}

Write-Host "[LAN-Knock] 4 步敲门已发送（UDP 无连接，发送成功即认为完成）"
Write-Host "[LAN-Knock] 验证方法（路由器 SSH）："
Write-Host "    nft list set inet fw4 allowed4"
Write-Host "  你应该看到本机 LAN IP 出现在列表中"
Write-Host "[LAN-Knock] 白名单默认 5 小时（whitelist_timeout），超时后需重新敲门"
exit 0
