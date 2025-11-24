[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Принудительная установка через MSI")]
    [bool]$forceMsiInstall = $false,
    
    [Parameter(HelpMessage = "Полный путь к MSI-файлу")]
    [string]$msiPath = $null,

    [Parameter(HelpMessage = "Имя файла MSI по-умолчанию (если находится там же, где и скрипт)")]
    [string]$msiFileName = "OpenSSH.msi",
    
    [Parameter(HelpMessage = "Создавать специального администратора")]
    [bool]$createLocalAdmin = $true,
    
    [Parameter(HelpMessage = "Имя администратора SSH (макс. 20 символов)")]
    [ValidateLength(1, 20)]
    [string]$admin_username = "special_user_ssh",
    
    [Parameter(HelpMessage = "Пароль администратора (открытым текстом)")]
    [string]$plain_password = $null,
    
    [Parameter(HelpMessage = "SSH порт")]
    [ValidateRange(1, 65535)]
    [int]$ssh_port = 12345,
    
    [Parameter(HelpMessage = "Создавать группу SSH-пользователей")]
    [bool]$create_local_ssh_users_group = $true,
    
    [Parameter(HelpMessage = "Имя группы SSH-пользователей (макс. 20 символов)")]
    [ValidateLength(1, 20)]
    [string]$local_ssh_users_group = "Special-SSH-Users"
)

# ===== ДОМЕН И ДОМЕННАЯ ГРУППА ДЛЯ ДОСТУПА SSH =====
$domain = "YOUR_DOMAIN"
$domainGroup = "SSH-Users"

# ===== ПРАВИЛА ДОСТУПА ДЛЯ IP И ГРУПП =====
$accessRules = @(
    @{
        Address = "10.11.22.0/24"
        Groups = @(
            "$domain\$domainGroup",
            $local_ssh_users_group
        )
    },
    @{
        Address = "192.168.1.0/24"
        Groups = @(
            "$domain\$domainGroup",
            $local_ssh_users_group
        )
    },
    @{
        Address = "172.29.30.31/32"
        Groups = @($local_ssh_users_group)
    }
)

# ===== ПАРАМЕТРЫ УСТАНОВКИ =====
$maxServiceCheckAttempts = 4   # Максимальное количество проверок состояния службы
$serviceCheckDelay = 3         # Задержка между проверками в секундах

# Если путь к MSI не указан, используем имя файла в текущей директории
if ([string]::IsNullOrEmpty($msiPath)) {
    $msiPath = Join-Path -Path $PSScriptRoot -ChildPath $msiFileName
}

# Проверяем, есть ли у нас права администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`nСкрипт необходимо запускать с правами администратора" -ForegroundColor Red
    exit 1
}

# ===== ФУНКЦИИ =====
function Get-SecurePassword {
    param([Parameter(Mandatory=$true)][string]$Prompt)
    
    $password = $null
    $confirm = $null
    
    do {
        Write-Host $Prompt -ForegroundColor Cyan -NoNewline
        $password = Read-Host -AsSecureString
        
        if (-not $password -or $password.Length -eq 0) {
            Write-Host "Пароль не может быть пустым!" -ForegroundColor Red
            continue
        }
        
        Write-Host "Повторите пароль: " -ForegroundColor Cyan -NoNewline
        $confirm = Read-Host -AsSecureString
        
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $confirmText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        
        if ($passwordText -ne $confirmText) {
            Write-Host "Пароли не совпадают! Попробуйте снова." -ForegroundColor Red
        }
        else {
            $passwordText = $null
            $confirmText = $null
            [System.GC]::Collect()
            return $password
        }
        
        $passwordText = $null
        $confirmText = $null
        [System.GC]::Collect()
    } while ($true)
}

# ===== УСТАНОВКА OPENSSH SERVER =====
try {
    Write-Host "`n=== Установка OpenSSH Server ===" -ForegroundColor Yellow
    $serviceStarted = $false
    
    # Принудительная установка через MSI
    if ($forceMsiInstall) {
        Write-Host "Принудительная установка через MSI включена" -ForegroundColor Yellow
        throw "Forced MSI installation"
    }
    
    # Попытка установки через DISM
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
    if ($capability.State -ne "Installed") {
        $capability | Add-WindowsCapability -Online | Out-Null
    }
    
    # Проверка существования службы
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        throw "Служба sshd не существует после установки"
    }
    
    # Запуск и проверка службы
    Start-Service sshd -ErrorAction Stop
    
    # Проверка состояния службы
    $attempt = 0
    do {
        $service = Get-Service sshd -ErrorAction SilentlyContinue
        if ($service.Status -eq 'Running') {
            $serviceStarted = $true
            break
        }
        $attempt++
        Write-Host "Проверка состояния службы ($attempt/$maxServiceCheckAttempts)..." -ForegroundColor Yellow
        Start-Sleep -Seconds $serviceCheckDelay
    } while ($attempt -lt $maxServiceCheckAttempts)
    
    if (-not $serviceStarted) {
        throw "Служба sshd не запустилась после $maxServiceCheckAttempts попыток"
    }
}
catch {
    # Fallback: Установка из MSI
    Write-Host "`n=== ВЫПОЛНЕНИЕ FALLBACK НА MSI УСТАНОВКУ ===" -ForegroundColor Yellow
    Write-Host "Причина: $($_.Exception.Message)" -ForegroundColor Red
    
    # Удаление DISM-версии
    try {
        $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
        if ($capability -and $capability.State -eq "Installed") {
            $capability | Remove-WindowsCapability -Online | Out-Null
            Write-Host "DISM-версия OpenSSH удалена" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Ошибка удаления DISM-версии: $_" -ForegroundColor Red
    }
    
    # Установка из MSI
    try {
        $msiPath = Join-Path -Path $PSScriptRoot -ChildPath $msiFileName
        
        if (-not (Test-Path -Path $msiPath -PathType Leaf)) {
            Write-Host "MSI-файл не найден: $msiPath" -ForegroundColor Red
            exit 3
        }

        $installArgs = "/i `"$msiPath`" /quiet"
        Write-Host "Запуск установки: msiexec $installArgs" -ForegroundColor Cyan
        
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
        
        if ($process.ExitCode -ne 0) {
            Write-Host "Ошибка установки MSI. Код выхода: $($process.ExitCode)" -ForegroundColor Red
            exit 4
        }
        
        Write-Host "OpenSSH Server успешно установлен из MSI" -ForegroundColor Green
    }
    catch {
        Write-Error "Ошибка установки из MSI: $_"
        exit 5
    }
}

# ===== СОЗДАНИЕ ЛОКАЛЬНОЙ ГРУППЫ SSH =====
if ($create_local_ssh_users_group) {
    if (-not (Get-LocalGroup -Name $local_ssh_users_group -ErrorAction SilentlyContinue)) {
        try {
            New-LocalGroup -Name $local_ssh_users_group -Description "Группа для доступа по SSH"
            Write-Host "Создана локальная группа SSH: $local_ssh_users_group" -ForegroundColor Green
        }
        catch {
            Write-Error "Ошибка создания группы SSH: $_"
            exit 6
        }
    }
    else {
        Write-Host "Локальная группа SSH уже существует: $local_ssh_users_group" -ForegroundColor Yellow
    }
}
else {
    Write-Host "Пропущено создание локальной группы SSH" -ForegroundColor Yellow
}

# ===== СОЗДАНИЕ ЛОКАЛЬНОГО АДМИНИСТРАТОРА =====
$createLocalAdmin = $true
if (-not $createLocalAdmin) {
    Write-Host "`nСоздание учетной записи администратора SSH пропущено" -ForegroundColor Yellow
}
if ($createLocalAdmin -and -not [string]::IsNullOrEmpty($admin_username)) {
    # Обработка пароля администратора
    if ($plain_password) {
        Write-Host "`nИспользуется пароль из переменной `$plain_password" -ForegroundColor Yellow
        $admin_password = ConvertTo-SecureString $plain_password -AsPlainText -Force
    }
    else {
        Write-Host "`n=== УСТАНОВКА ПАРОЛЯ АДМИНИСТРАТОРА SSH ===" -ForegroundColor Yellow
        Write-Host "Пароль должен соответствовать требованиям сложности Windows" -ForegroundColor Cyan
        $admin_password = Get-SecurePassword -Prompt "Введите пароль для администратора $admin_username`: "
    }
    try {
        net accounts /maxpwage:unlimited | Out-Null
        $adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

        if (-not (Get-LocalUser -Name $admin_username -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $admin_username -Password $admin_password -AccountNeverExpires -PasswordNeverExpires
        }
        else {
            Set-LocalUser -Name $admin_username -Password $admin_password -PasswordNeverExpires $true
        }

        $registryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $registryPath -Name $admin_username -Value 0 -Type DWord -Force

        if (-not (Get-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction Stop
        }
        
        # Добавляем пользователя в группу SSH
        if (-not (Get-LocalGroupMember -Group $local_ssh_users_group -Member $admin_username -ErrorAction SilentlyContinue)) {
            Add-LocalGroupMember -Group $local_ssh_users_group -Member $admin_username
        }
    }
    catch {
        Write-Error "Ошибка конфигурирования аккаунта: $_"
        exit 1
    }
}

# ===== НАСТРОЙКА SSH КОНФИГА =====
$sshConfigPath = "$env:ProgramData\ssh\sshd_config"
try {
    Start-Service sshd -ErrorAction Stop
    $configContent = Get-Content $sshConfigPath -Raw
    
    # Аутентификация и безопасность
    $configContent = $configContent -replace "(?m)^#?GSSAPIAuthentication\s+.*", "GSSAPIAuthentication yes"
    $configContent = $configContent -replace "(?m)^#?PasswordAuthentication\s+.*", "PasswordAuthentication yes"
    $configContent = $configContent -replace "(?m)^#?AllowAgentForwarding\s+.*", "AllowAgentForwarding no"
    
    # Установка порта
    $configContent = $configContent -replace "(?m)^#?Port\s+.*", "Port $ssh_port"
    
    # Удаляем старые сгенерированные правила
    $startMarker = [regex]::Escape("# ===========================================")
    $endMarker = [regex]::Escape("# === END ACCESS RULES ===")
    $configContent = $configContent -replace "(?s)$startMarker.*?$endMarker", ""
    
    # === ГЕНЕРАЦИЯ ПРАВИЛ ДОСТУПА ===
    $accessRulesConfig = @"
# ===========================================
# === ACCESS RULES - GENERATED BY SCRIPT ===
# ===========================================

"@

    foreach ($rule in $accessRules) {
        $address = $rule.Address
        # Преобразуем одиночные IP в формат CIDR /32
        if ($address -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $address = "$address/32"
        }
        $groups = $rule.Groups -join " "
        $accessRulesConfig += @"
# [IP: $address]
Match Address $address
    AllowGroups $groups

"@
    }
    
    # Добавляем блок для запрета всех остальных
    $accessRulesConfig += @"
# Deny all others
Match Address *
    AllowGroups dummy_group

# === END ACCESS RULES ===
"@
    
    $configContent += "`n$accessRulesConfig"
    $configContent | Set-Content $sshConfigPath -Encoding UTF8 -Force
}
catch {
    Write-Error "Ошибка настройки SSH: $_"
    exit 3
}

# ===== НАСТРОЙКА БРАНДМАУЭРА =====
try {
    $ruleName = "OpenSSH_CustomRule_$ssh_port"
    
    # Собираем все адреса из правил доступа
    $ipList = @()
    foreach ($rule in $accessRules) {
        $ipList += $rule.Address
    }
    
    # Извлекаем уникальные адреса
    $allowedIps = $ipList | Select-Object -Unique
    
    # Преобразуем одиночные IP в формат CIDR /32
    $validAddresses = @()
    foreach ($ip in $allowedIps) {
        if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $validAddresses += "$ip/32"
        }
        elseif ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$') {
            $validAddresses += $ip
        }
        else {
            Write-Error "Неверный формат IP-адреса: $ip"
            exit 42
        }
    }
    
    # Удаляем старое правило, если оно существует
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName -Confirm:$false
    }
    
    # Создаем новое правило с валидными адресами
    New-NetFirewallRule -DisplayName $ruleName `
        -Name $ruleName `
        -Protocol TCP `
        -Direction Inbound `
        -LocalPort $ssh_port `
        -RemoteAddress $validAddresses `
        -Action Allow `
        -Enabled True | Out-Null
}
catch {
    Write-Error "Ошибка настройки брандмауэра: $_"
    exit 4
}

# ===== ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ =====
try {
    # Настройка PowerShell как оболочки по умолчанию
    $shellParams = @{
        Path = 'HKLM:\SOFTWARE\OpenSSH'
        Name = 'DefaultShell'
        Value = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        PropertyType = 'String'
        Force = $true
    }
    New-ItemProperty @shellParams -ErrorAction Stop

    # Финальная настройка службы
    Set-Service -Name sshd -StartupType Automatic
    Restart-Service sshd -Force -ErrorAction Stop
}
catch {
    Write-Error "Ошибка дополнительных настроек: $_"
    exit 5
}

# ===== ИНФОРМАЦИЯ ПОСЛЕ УСТАНОВКИ =====
Write-Host "`n=== НАСТРОЙКА ЗАВЕРШЕНА ===" -ForegroundColor Green
Write-Host "Порт SSH: $ssh_port" -ForegroundColor Cyan
Write-Host "Правила доступа:" -ForegroundColor Cyan

foreach ($rule in $accessRules) {
    $address = $rule.Address
    if ($address -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $address = "$address/32"
    }
    Write-Host "  - $address`: Группы: " -NoNewline -ForegroundColor Cyan
    Write-Host ($rule.Groups -join ", ") -ForegroundColor Yellow
}

if ($createLocalAdmin -and -not [string]::IsNullOrEmpty($admin_username)) {
    if (-not $plain_password) {
        Write-Host "`n=== ВАЖНО ===" -ForegroundColor Red
        Write-Host "Пароль администратора не сохранен в скрипте!" -ForegroundColor Red
        Write-Host "Сохраните его в надежном месте." -ForegroundColor Red
    }
}

# Очистка пароля
$plain_password = $null