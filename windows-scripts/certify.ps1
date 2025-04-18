# certify.ps1 - 修改版本，完全跳过许可证检查
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "无效果 - 仅为兼容性保留")]
    [switch]$ForceLicense
)

# 配置目录
$ConfigDir = "$env:USERPROFILE\.config\dosyago\bbpro"
$TestEnvFile = "$ConfigDir\test.env"
$TicketsDir = "$ConfigDir\tickets"
$TicketFile = "$TicketsDir\ticket.json"

# 确保配置目录存在
if (-not (Test-Path $ConfigDir)) {
    New-Item -Path $ConfigDir -ItemType Directory -Force | Out-Null
}

# 确保ticket目录存在
if (-not (Test-Path $TicketsDir)) {
    New-Item -Path $TicketsDir -ItemType Directory -Force | Out-Null
}

# 从test.env加载现有配置（如果存在）
$Config = @{}
if (Test-Path $TestEnvFile) {
    Get-Content $TestEnvFile | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") {
            $Config[$Matches[1]] = $Matches[2]
        }
    }
}

# 保存配置到test.env的函数
function Save-Config {
    $envContent = $Config.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
    $envContent | Out-File $TestEnvFile -Encoding utf8 -Force
    Write-Verbose "配置已保存到 $TestEnvFile"
}

# 如果ticket文件不存在，创建一个虚假的有效ticket
if (-not (Test-Path $TicketFile)) {
    Write-Host "创建虚假有效许可证ticket..." -ForegroundColor Yellow
    
    # 计算远期时间戳（当前时间+10年，以秒为单位）
    $currentTime = [int](Get-Date -UFormat %s)
    $futureTime = $currentTime + 315360000
    
    # 生成随机ID
    $randomId = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
    $deviceId = "$env:COMPUTERNAME-$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))"
    $seatId = "seat-$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}))"
    
    # 创建虚假ticket的基本结构
    $dummyTicket = @{
        valid = $true
        enterpriseLicense = $true
        ticket = @{
            ticketData = @{
                timeSlot = $futureTime
                deviceId = $deviceId
                seatId = $seatId
                features = @("all", "premium", "enterprise")
                seats = 999999
                licenseType = "enterprise"
            }
            issuer = "local"
            signature = "dummy-signature-$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_}))"
        }
        certificate = @{
            certificateData = @{
                ticketId = $randomId
                issueDate = (Get-Date).ToString("o")
                expiryDate = (Get-Date).AddSeconds(315360000).ToString("o")
            }
            issuer = "local"
            signature = "dummy-signature-$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_}))"
        }
    }
    
    # 保存虚假ticket
    $dummyTicket | ConvertTo-Json -Depth 10 | Set-Content $TicketFile -Force
    Write-Host "虚假有效许可证ticket已创建于 $TicketFile" -ForegroundColor Green
}

# 保存配置并完成
Save-Config
Write-Host "许可证检查已完全跳过 (许可证检测已完全移除)." -ForegroundColor Green
Write-Host "认证过程完成." -ForegroundColor Green
