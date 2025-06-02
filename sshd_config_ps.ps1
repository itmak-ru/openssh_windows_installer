#Requires -RunAsAdministrator

# Задаем переменные
$admin_username = "special_user_ssh"
$ssh_port = 12345

# Разрешенные IP в формате CIDR
$allowed_ips = @(
    "10.11.12.13",
    "192.168.88.99",
    "172.16.32.25"
)

# === НЕРЕКОМЕНДУЕМАЯ ОПЦИЯ : Пароль в открытом виде (раскомментируйте и задайте свой пароль) ===
#$plain_password = "Super-Secret5-Passw0rd"

# Функция для безопасного ввода пароля
function Get-SecurePassword {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt
    )
    
    $password = $null
    $confirm = $null
    
    do {
        # Первый ввод пароля
        Write-Host $Prompt -ForegroundColor Cyan -NoNewline
        $password = Read-Host -AsSecureString
        
        # Проверка на пустой пароль
        if (-not $password -or $password.Length -eq 0) {
            Write-Host "Пароль не может быть пустым!" -ForegroundColor Red
            continue
        }
        
        # Подтверждение пароля
        Write-Host "Повторите пароль: " -ForegroundColor Cyan -NoNewline
        $confirm = Read-Host -AsSecureString
        
        # Сравнение паролей
        $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $confirmText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        
        if ($passwordText -ne $confirmText) {
            Write-Host "Пароли не совпадают! Попробуйте снова." -ForegroundColor Red
        }
        else {
            # Очистка текстовых переменных из памяти
            $passwordText = $null
            $confirmText = $null
            [System.GC]::Collect()
            return $password
        }
        
        # Очистка текстовых переменных из памяти при несовпадении
        $passwordText = $null
        $confirmText = $null
        [System.GC]::Collect()
        
    } while ($true)
}

# Обработка пароля администратора
if ($plain_password) {
    Write-Host "`nИспользуется пароль из переменной `$plain_password" -ForegroundColor Yellow
    $admin_password = ConvertTo-SecureString $plain_password -AsPlainText -Force
}
else {
    Write-Host "`n=== УСТАНОВКА ПАРОЛЯ АДМИНИСТРАТОРА SSH ===" -ForegroundColor Yellow
    Write-Host "Пароль должен соответствовать требованиям сложности Windows:" -ForegroundColor Cyan
    Write-Host "  - Минимум 8 символов" -ForegroundColor Cyan
    Write-Host "  - Заглавные и строчные буквы" -ForegroundColor Cyan
    Write-Host "  - Цифры и специальные символы" -ForegroundColor Cyan
    Write-Host "  - Не содержать имя пользователя" -ForegroundColor Cyan

    $admin_password = Get-SecurePassword -Prompt "Введите пароль для администратора $admin_username`: "
}

# Настройка аккаунта админа
try {
    # Настраиваем политику срока жизни паролей (для систем без домена)
    net accounts /maxpwage:unlimited | Out-Null

    # Находим название группы администраторов по SID
    $adminGroup = Get-LocalGroup -SID "S-1-5-32-544"

    # Создаем аккаунт, если он не существует
    if (-not (Get-LocalUser -Name $admin_username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $admin_username -Password $admin_password -AccountNeverExpires -PasswordNeverExpires
    }
    else {
        # Обновляем пароль, если пользователь уже существует
        Set-LocalUser -Name $admin_username -Password $admin_password -PasswordNeverExpires $true
    }

    # Прячем аккаунт с экрана winlogon
    $registryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name $admin_username -Value 0 -Type DWord -Force

    # Добавляем в группу администраторов, если не добавлен
    if (-not (Get-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group $adminGroup -Member $admin_username -ErrorAction Stop
    }
}
catch {
    Write-Error "Ошибка конфигурирования аккаунта: $_"
    exit 1
}

# Установка OpenSSH Server
try {
    Write-Host "`n=== Выполняется загрузка и установка OpenSSH Server ===" -ForegroundColor Yellow
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Server*"
    if ($capability.State -ne "Installed") {
        $capability | Add-WindowsCapability -Online
    }
}
catch {
    Write-Error "Ошибка установки OpenSSH Server: $_"
    exit 2
}

# Настройка SSH
$sshConfigPath = "$env:ProgramData\ssh\sshd_config"
try {
    # Запускаем службу для создания конфига по-умолчанию
    Start-Service sshd -ErrorAction Stop
    
    # Читаем конфиг
    $configContent = Get-Content $sshConfigPath -Raw
    
    # Задаем порт SSH
    if ($configContent -match "(?m)^#?Port\s+.*") {
        $configContent = $configContent -replace "(?m)^#?Port\s+.*", "Port $ssh_port"
    }
    else {
        $configContent = "Port $ssh_port`n$configContent"
    }
    
    # Генерируем строку AllowUsers для всех разрешенных IP
    $allowUsersEntries = foreach ($ip in $allowed_ips) {
        "${admin_username}@$ip"
    }
    $allowUsersString = $allowUsersEntries -join " "
    
    # Обновляем AllowUsers
    if ($configContent -match "(?m)^#?AllowUsers\s+.*") {
        $configContent = $configContent -replace "(?m)^#?AllowUsers\s+.*", "AllowUsers $allowUsersString"
    }
    else {
        $configContent = $configContent.TrimEnd() + "`nAllowUsers $allowUsersString"
    }
    
    $configContent | Set-Content $sshConfigPath -Encoding UTF8 -Force
    
}
catch {
    Write-Error "Ошибка настройки SSH: $_"
    exit 3
}

# Настройка брандмауэра Windows
try {
    $ruleName = "OpenSSH_CustomPort"
    
    # Удаляем правило, если оно уже существует
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName -Confirm:$false
    }
    
    # Создаем новое правило для всех разрешенных IP
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
    Write-Error "Ошибка настройки брандмауэра: $_"
    exit 4
}

# Финальная настройка службы sshd
try {
    Set-Service -Name sshd -StartupType Automatic
    Restart-Service sshd -Force -ErrorAction Stop
}
catch {
    Write-Error "Ошибка настройки службы: $_"
    exit 5
}

Write-Host "`nНастройка полностью завершена!" -ForegroundColor Green
Write-Host "Доступ разрешен для пользователя: $admin_username" -ForegroundColor Cyan
Write-Host "Порт SSH: $ssh_port" -ForegroundColor Cyan
Write-Host "Разрешенные IP:" -ForegroundColor Cyan
$allowed_ips | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }

# Дополнительные рекомендации
if (-not $plain_password) {
    Write-Host "`n=== ВАЖНО ===" -ForegroundColor Red
    Write-Host "Пароль администратора не сохранен в скрипте!" -ForegroundColor Red
    Write-Host "Сохраните его в надежном месте." -ForegroundColor Red
}

# Дополнительно очищаем открытый пароль
$plain_password = $null
