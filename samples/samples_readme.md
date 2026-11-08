# SABRE Test Samples Catalog

> **Safety Notice**: All files in this `samples/` directory are **100% inert, non-executable test artifacts** created specifically to validate static analysis, indicator extraction, and rule generation in **SABRE** (**S**tatic **A**rtifact & **B**inary **R**ule **E**ngine — [`sabre.py`](../sabre.py)). They contain synthetic headers (`MZ`/`PE`, `ELF`, `#!`) paired with harmless ASCII and UTF-16LE strings using RFC 5737 documentation IP blocks (`198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606 reserved domains (`.example.com`, `.example.net`, `.example.org`, `.test`).

---

## Summary Matrix

| Sample File | Simulated TTP / Category | Format Header | Priority | Expected Suricata Rules | Expected Sigma Docs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [`mock_ransomware_simulator.bin`](mock_ransomware_simulator.bin) | Ransomware & Recovery Inhibition | Windows PE32 (x86) Executable | `P1 - Critical` | 2 HTTP, 2 DNS, 2 TLS, 1 IP (7 total) | 2 (`registry_event`, `process_creation`) |
| [`mock_lotl_privesc.bin`](mock_lotl_privesc.bin) | Living off the Land (LotL) PrivEsc & UAC Bypass | Windows PE32+ (x64) Executable | `P1 - Critical` | 1 HTTP, 1 DNS, 1 TLS, 1 IP (4 total) | 2 (`registry_event`, `process_creation`) |
| [`mock_lateral_movement.bin`](mock_lateral_movement.bin) | SMB / PsExec / WinRM / RDP Lateral Movement | Windows PE32+ (x64) Executable | `P1 - Critical` | 2 HTTP, 2 DNS, 2 TLS, 1 IP (7 total) | 2 (`registry_event`, `process_creation`) |
| [`mock_malleable_c2_implant.dll`](mock_malleable_c2_implant.dll) | Multi-Channel Malleable C2 & Domain Fronting | Windows PE32+ (x64) DLL | `P1 - Critical` | 4 HTTP, 4 DNS, 4 TLS, 1 IP (13 total) | 2 (`registry_event`, `process_creation`) |
| [`mock_beacon_x64.bin`](mock_beacon_x64.bin) | Standard x64 C2 Beacon & Persistence | Windows PE32+ (x64) Executable | `P1 - Critical` | 1 HTTP, 2 DNS, 2 TLS, 1 IP (6 total) | 2 (`registry_event`, `process_creation`) |
| [`mock_linux_agent.elf`](mock_linux_agent.elf) | Linux ELF Beacon & Staging Script | Linux/Unix ELF 64-bit Binary | `P1 - Critical` | 2 HTTP, 1 DNS, 1 TLS, 1 IP (5 total) | 1 (`process_creation`) |
| [`mock_dropper_script.ps1`](mock_dropper_script.ps1) | PowerShell Stage-2 Dropper & Service Hook | Executable Script (`#!`) | `P1 - Critical` | 1 HTTP, 1 DNS, 1 TLS, 1 IP (4 total) | 2 (`registry_event`, `process_creation`) |
| [`benign_utility_control.bin`](benign_utility_control.bin) | Clean Control Binary (False-Positive Test) | Unknown / Raw Binary | `P2 - High` | 0 alerts (comment header only) | 1 (`process_creation` hash-only) |

---

## Detailed Sample Specifications & Expected Indicators

### 1. `mock_ransomware_simulator.bin`
* **Purpose**: Validates detection of ransomware persistence hooks, Safe Mode boot survival, Windows Defender tampering, and key-escrow HTTP check-ins.
* **Binary Metadata**:
  * **File Type**: `Windows PE32 Executable` (`x86 (I386)`)
  * **Section**: `.rdata`
* **Expected Extracted Indicators**:
  * **C2 IPs**: `198.51.100.77`, `203.0.113.150`
  * **C2 Domains**: `decrypt-portal.test`, `key-escrow-sim.example.com`
  * **C2 URLs**:
    * `http://decrypt-portal.test/status.php?key=test_only`
    * `https://key-escrow-sim.example.com/api/v2/register.php?victim_id=sim9001&enc=aes256`
  * **URI Patterns**:
    * `/api/v2/register.php?victim_id=sim9001&enc=aes256`
    * `/status.php?key=test_only`
  * **Registry Keys**:
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\MockRansomNoteDisplay` *(UTF-16LE)*
    * `HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
    * `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MockRansomSvc`
    * `HKCU\Control Panel\Desktop\Wallpaper` *(UTF-16LE)*
  * **Mutexes**:
    * `Global\MockCryptLockerMutex_v4` *(UTF-16LE)*

---

### 2. `mock_lotl_privesc.bin`
* **Purpose**: Validates extraction of Living-off-the-Land (LotL) privilege escalation and UAC bypass registry keys (`fodhelper.exe`, `eventvwr.exe`, Sticky Keys `sethc.exe` IFEO debugger injection, and `SilentProcessExit` monitoring).
* **Binary Metadata**:
  * **File Type**: `Windows PE32+ Executable` (`x64 (AMD64)`)
  * **Section**: `.rdata`
* **Expected Extracted Indicators**:
  * **C2 IPs**: `198.51.100.112`
  * **C2 Domains**: `lotl-stage.example.org`
  * **C2 URLs**: `https://lotl-stage.example.org/payloads/elevate.ps1?method=fodhelper`
  * **URI Patterns**: `/payloads/elevate.ps1?method=fodhelper`
  * **Registry Keys**:
    * `Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` *(UTF-16LE)*
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\svchost.exe`
    * `HKLM\SYSTEM\CurrentControlSet\Services\MockPrivEscSvc\Parameters` *(UTF-16LE)*
    * `HKCU\Software\Classes\ms-settings\Shell\Open\command`
    * `HKCU\Software\Classes\mscfile\shell\open\command`
  * **Mutexes**:
    * `Local\MockElevationBypassMutex` *(UTF-16LE)*

---

### 3. `mock_lateral_movement.bin`
* **Purpose**: Validates detection of lateral movement artifacts including PsExec service installation (`PSEXESVC`), Remote Desktop enablement (`fDenyTSConnections`), Pass-the-Hash RestrictedAdmin mode (`DisableRestrictedAdmin`), WinRM `/wsman` URIs, and internal RFC 1918 pivot IPs.
* **Binary Metadata**:
  * **File Type**: `Windows PE32+ Executable` (`x64 (AMD64)`)
  * **Section**: `.rdata`
* **Expected Extracted Indicators**:
  * **C2 IPs (Default Run)**: `198.51.100.240`
  * **C2 IPs (With `--include-private-ips`)**: `10.10.50.15`, `192.168.100.25`, `198.51.100.240`
  * **C2 Domains**: `fileserver-pivot.lan`, `internal-dc01.corp`
  * **URI Patterns**:
    * `/admin/lateral_beacon.aspx?pivot=smb`
    * `/wsman?remote_shell=winrm_test`
  * **Registry Keys**:
    * `Software\Microsoft\Windows\CurrentVersion\Run\MockLateralPivotAgent` *(UTF-16LE)*
    * `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
    * `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin`
    * `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC\ImagePath`
  * **Mutexes**:
    * `Global\MockPsExecLateralMutex` *(UTF-16LE)*
    * `BaseNamedObjects\MockWmiExecPipeMutex` *(UTF-16LE)*

---

### 4. `mock_malleable_c2_implant.dll`
* **Purpose**: Validates PE32+ DLL classification and high-density C2 indicator extraction across malleable HTTP profiles (disguised as jQuery/API traffic), semicolons in URI query parameters (testing Suricata `|3b|` hex-escaping), proxy settings tampering, and multi-domain DNS/TLS SNI rule generation.
* **Binary Metadata**:
  * **File Type**: `Windows PE32+ DLL` (`x64 (AMD64)`, `is_dll: true`)
  * **Section**: `.rdata`
* **Expected Extracted Indicators**:
  * **C2 IPs**: `198.51.100.10`, `198.51.100.11`, `203.0.113.50`, `203.0.113.51`
  * **C2 Domains**: `cdn-fronting.example.org`, `dead-drop.test`, `fallback-dns-c2.example.net`, `primary-c2.example.com`
  * **C2 URLs**:
    * `https://cdn-fronting.example.org/api/v3/telemetry.php?beacon=active;jitter=30`
    * `https://primary-c2.example.com:443/jquery-3.6.0.min.js?session=98a7f6&arch=x64`
  * **URI Patterns**:
    * `/api/v3/telemetry.php?beacon=active;jitter=30` *(escaped as `|3b|` in Suricata)*
    * `/jquery-3.6.0.min.js?session=98a7f6&arch=x64`
    * `/submit.php?id=implant_04&chunk=1`
    * `/updates/check.cgi?ver=2.1`
  * **Registry Keys**:
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` *(UTF-16LE)*
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MockC2HeartbeatDll` *(UTF-16LE)*
  * **Mutexes**:
    * `Global\MockMalleableC2Beacon_Mutex` *(UTF-16LE)*
    * `Local\MockDnsTunnelSyncMutex` *(UTF-16LE)*

---

### 5. `mock_beacon_x64.bin`
* **Purpose**: Baseline PE32+ x64 test sample combining valid ASCII and UTF-16LE IOCs with common binary noise (`KERNEL32.dll`, `advapi32.dll`, `CreateMutexW`, loopback `127.0.0.1`, PE version `10.0.19041.1`, and `crl.microsoft.com`) to verify false-positive filtering.
* **Binary Metadata**:
  * **File Type**: `Windows PE32+ Executable` (`x64 (AMD64)`)
* **Expected Extracted Indicators**:
  * **C2 IPs**: `198.51.100.42`, `203.0.113.88` *(filters out `127.0.0.1` and `10.0.19041.1`)*
  * **C2 Domains**: `beacon-node.test`, `c2-telemetry.example.com` *(filters out `KERNEL32.dll`, `advapi32.dll`, `crl.microsoft.com`)*
  * **C2 URLs**: `https://c2-telemetry.example.com:8443/gate.php?id=test101;mode=sync`
  * **URI Patterns**: `/gate.php?id=test101;mode=sync`
  * **Registry Keys**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MockTelemetrySync` *(UTF-16LE)*
  * **Mutexes**: `Global\MockBeaconSyncMutex_01` *(UTF-16LE; filters out `CreateMutexW`)*

---

### 6. `mock_linux_agent.elf`
* **Purpose**: Validates 64-bit ELF magic byte detection (`\x7fELF`) and cross-platform URI/C2 extraction.
* **Binary Metadata**:
  * **File Type**: `Linux/Unix ELF 64-bit Binary`
* **Expected Extracted Indicators**:
  * **C2 IPs**: `198.51.100.215`
  * **C2 Domains**: `update-mirror.example.net`
  * **C2 URLs**: `https://update-mirror.example.net/api/v1/checkin.jsp?host=lab01`
  * **URI Patterns**:
    * `/api/v1/checkin.jsp?host=lab01`
    * `/var/tmp/stage_check.sh`
  * **Registry Keys**: *(None)*
  * **Mutexes**: `Local\LinuxAgentTestMutex`

---

### 7. `mock_dropper_script.ps1`
* **Purpose**: Validates analysis of script-based payloads starting with `#!` and extraction of Windows service `ImagePath` hooks and `BaseNamedObjects\` mutexes.
* **Binary Metadata**:
  * **File Type**: `Executable Script`
* **Expected Extracted Indicators**:
  * **C2 IPs**: `203.0.113.199`
  * **C2 Domains**: `dropper-sim.example.org`
  * **URI Patterns**: `/stage2/config.dat?token=demo_test`
  * **Registry Keys**: `HKLM\SYSTEM\CurrentControlSet\Services\MockTestService\ImagePath`
  * **Mutexes**: `BaseNamedObjects\MockDropperTestMutex`

---

### 8. `benign_utility_control.bin`
* **Purpose**: Negative control sample containing only benign strings (`USER32.dll`, `GDI32.dll`, `KERNEL32.dll`, `127.0.0.1`, `0.0.0.0`, `1.0.0.0`, `www.microsoft.com`, `ocsp.digicert.com`, and C++ mangled symbol `?id@?$codecvt@DDU_Mbstatet@@@std@@`).
* **Expected Extracted Indicators**:
  * **C2 IPs**: `[]` *(None)*
  * **C2 Domains**: `[]` *(None)*
  * **URI Patterns**: `[]` *(None)*
  * **Registry Keys**: `[]` *(None)*
  * **Mutexes**: `[]` *(None)*
* **Expected Artifacts**:
  * **RFC JSON**: `P2 - High` priority with only the baseline EDR cryptographic hash-blocking directive.
  * **Suricata `.rules`**: Comment line noting zero network indicators extracted (no false-positive rules emitted).
  * **Sigma `.yml`**: Single `process_creation` hash-matching document (no `registry_event` rule emitted).
