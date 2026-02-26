# Execution policy ayarı (gerekirse)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Scripti çalıştır
.\CrowdStrike-Test-Suite.ps1

# Verbose mod ile
.\CrowdStrike-Test-Suite.ps1 -Verbose

# Özel log yolu ile
.\CrowdStrike-Test-Suite.ps1 -LogPath "C:\Logs\cstest.log"
