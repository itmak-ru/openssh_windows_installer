#Requires -RunAsAdministrator

# ������ ����������
$admin_username = "special_user_ssh"
$ssh_port = 12345

# ����������� IP � ������� CIDR
$allowed_ips = @(
    "10.11.12.13",
    "192.168.88.99",
    "172.16.32.25"
)

# === ��������������� ����� : ������ � �������� ���� (���������������� � ������� ���� ������) ===
#$plain_password = "Super-Secret5-Passw0rd"

# ������� ��� ����������� ����� ������
function Get-SecurePassword {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt
    )
    
    $password = $null
    $confirm = $null
    
    do {
        # ������ ���� ������
        Write-Host $Prompt -ForegroundColor Cyan -NoNewline
        $password = Read-Host -AsSecureString
        
        # �������� �� ������ ������
        if (-not $password -or $password.Length -eq 0) {
            Write-Host "������ �� ����� ���� ������!" -ForegroundColor Red
            continue
        }
        
        # ������������� ������
        Write-Host "��������� ������: " -ForegroundColor Cyan -NoNewline
        $confirm = Read-Host -AsSecureString
        
        # ��������� �������
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $confirmText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        
        if ($passwordText -ne $confirmText) {
            Write-Host "������ �� ���������! ���������� �����." -ForegroundColor Red
        }
        else {
            # ������� ��������� ���������� �� ������
            $passwordText = $null
            $confirmText = $null
            [System.GC]::Collect()
            return $password
        }
        
        # ������� ��������� ���������� �� ������ ��� ������������
        $passwordText = $null
        $confirmText = $null
        [System.GC]::Collect()
        
    } while ($true)
}

# ��������� ������ ��������������
if ($plain_password) {
    Write-Host "`n������������ ������ �� ���������� `$plain_password" -ForegroundColor Yellow
    $admin_password = ConvertTo-SecureString $plain_password -AsPlainText -Force
}
else {
    Write-Host "`n=== ��������� ������ �������������� SSH ===" -ForegroundColor Yellow
    Write-Host "������ ������ ��������������� ����������� ��������� Windows:" -ForegroundColor Cyan
    Write-Host "  - ������� 8 ��������" -ForegroundColor Cyan
    Write-Host "  - ��������� � �������� �����" -ForegroundColor Cyan
    Write-Host "  - ����� � ����������� �������" -ForegroundColor Cyan
    Write-Host "  - �� ��������� ��� ������������" -ForegroundColor Cyan

    $admin_password = Get-SecurePassword -Prompt "������� ������ ��� �������������� $admin_username`: "
}

# ��������� �������� ������
try {
    # ����������� �������� ����� ����� ������� (��� ������ ��� ������)
    net accounts /maxpwage:unlimited | Out-Null

    # ������� �������� ������ ��������������� �� SID
    $adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

    # ������� �������, ���� �� �� ����������
    if (-not (Get-LocalUser -Name $admin_username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $admin_username -Password $admin_password -AccountNeverExpires -PasswordNeverExpires
    }
    else {
        # ��������� ������, ���� ������������ ��� ����������
        Set-LocalUser -Name $admin_username -Password $admin_password -PasswordNeverExpires $true
    }

    # ������ ������� � ������ winlogon
    $registryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name $admin_username -Value 0 -Type DWord -Force

    # ��������� � ������ ���������������, ���� �� ��������
    if (-not (Get-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction Stop
    }
}
catch {
    Write-Error "������ ���������������� ��������: $_"
    exit 1
}

# ��������� OpenSSH Server
try {
    Write-Host "`n=== ����������� �������� � ��������� OpenSSH Server ===" -ForegroundColor Yellow
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
    if ($capability.State -ne "Installed") {
        $capability | Add-WindowsCapability -Online
    }
}
catch {
    Write-Error "������ ��������� OpenSSH Server: $_"
    exit 2
}

# ��������� SSH
$sshConfigPath = "$env:ProgramData\ssh\sshd_config"
try {
    # ��������� ������ ��� �������� ������� ��-���������
    Start-Service sshd -ErrorAction Stop
    
    # ������ ������
    $configContent = Get-Content $sshConfigPath -Raw
    
    # ������ ���� SSH
    if ($configContent -match "(?m)^#?Port\s+.*") {
        $configContent = $configContent -replace "(?m)^#?Port\s+.*", "Port $ssh_port"
    }
    else {
        $configContent = "Port $ssh_port`n$configContent"
    }
    
    # ���������� ������ AllowUsers ��� ���� ����������� IP
    $allowUsersEntries = foreach ($ip in $allowed_ips) {
        "${admin_username}@$ip"
    }
    $allowUsersString = $allowUsersEntries -join " "
    
    # ��������� AllowUsers
    if ($configContent -match "(?m)^#?AllowUsers\s+.*") {
        $configContent = $configContent -replace "(?m)^#?AllowUsers\s+.*", "AllowUsers $allowUsersString"
    }
    else {
        $configContent = $configContent.TrimEnd() + "`nAllowUsers $allowUsersString"
    }
    
    $configContent | Set-Content $sshConfigPath -Encoding UTF8 -Force
    
}
catch {
    Write-Error "������ ��������� SSH: $_"
    exit 3
}

# ��������� ����������� Windows
try {
    $ruleName = "OpenSSH_CustomPort"
    
    # ������� �������, ���� ��� ��� ����������
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName -Confirm:$false
    }
    
    # ������� ����� ������� ��� ���� ����������� IP
    New-NetFirewallRule -DisplayName $ruleName `
        -Name $ruleName `
        -Protocol TCP `
        -Direction Inbound `
        -LocalPort $ssh_port `
        -RemoteAddress $allowed_ips `
        -Action Allow `
        -Enabled True | Out-Null
}
catch {
    Write-Error "������ ��������� �����������: $_"
    exit 4
}

# ��������� ��������� ������ sshd
try {
    Set-Service -Name sshd -StartupType Automatic
    Restart-Service sshd -Force -ErrorAction Stop
}
catch {
    Write-Error "������ ��������� ������: $_"
    exit 5
}

Write-Host "`n��������� ��������� ���������!" -ForegroundColor Green
Write-Host "������ �������� ��� ������������: $admin_username" -ForegroundColor Cyan
Write-Host "���� SSH: $ssh_port" -ForegroundColor Cyan
Write-Host "����������� IP:" -ForegroundColor Cyan
$allowed_ips | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }

# �������������� ������������
if (-not $plain_password) {
    Write-Host "`n=== ����� ===" -ForegroundColor Red
    Write-Host "������ �������������� �� �������� � �������!" -ForegroundColor Red
    Write-Host "��������� ��� � �������� �����." -ForegroundColor Red
}

# ������������� ������� �������� ������
$plain_password = $null