# SABRE: Quick User Guide

**SABRE** (**S**tatic **A**rtifact & **B**inary **R**ule **E**ngine — [`sabre.py`](sabre.py)) is a self-contained, zero-dependency Python tool for rapid static analysis of raw binaries and executables in air-gapped environments. Using safe, read-only file handling and heuristic extraction, it parses binary metadata and embedded indicators of compromise (IOCs) to generate ready-to-deploy containment and detection artifacts.

---

## 1. Requirements

* **Python**: 3.8 or newer (uses only the Python Standard Library; no `pip` packages or internet access required).
* **OS**: Windows, Linux, or macOS.

---

## 2. Quick Start

### Step 1: Place Binaries in the Sample Directory
By default, SABRE reads files from the `./samples` directory. If `./samples` does not exist on the first run, the tool will create it automatically:

```bash
python sabre.py
```

Copy the target executables, DLLs, ELF binaries, or raw payloads into `./samples/` and run the tool again:

```bash
python sabre.py
```

### Step 2: Review Generated Artifacts
Artifacts are exported to `./outputs/` (or your custom `--output-dir`) across three subdirectories:

```text
outputs/
├── rfc/
│   └── RFC_<filename>.json        # Change Management containment payload
├── suricata/
│   └── <filename>.rules           # Network IDS rules (HTTP, DNS, TLS SNI, IP)
└── sigma/
    └── <filename>_sigma.yml       # Host SIEM detection rules (Registry & Process)
```

---

## 3. Command-Line Options

```text
usage: sabre [-h] [-o OUTPUT_DIR] [-m MIN_LENGTH] [-r] [--include-private-ips]
             [--demo-fallbacks] [--max-size-mb MAX_SIZE_MB]
             [sample_dir]
```

| Argument / Flag | Default | Description |
| :--- | :--- | :--- |
| `sample_dir` | `samples` | Directory containing sample binaries to analyze. |
| `-o`, `--output-dir` | `outputs` | Base directory for generated RFC, Suricata, and Sigma files. |
| `-m`, `--min-length` | `5` | Minimum printable character length for ASCII and UTF-16LE string extraction. |
| `-r`, `--recursive` | `False` | Recursively scan all subdirectories inside `sample_dir`. |
| `--include-private-ips` | `False` | Include RFC 1918 private IPv4 addresses (e.g., `10.x.x.x`, `192.168.x.x`) for internal lab samples. |
| `--demo-fallbacks` | `False` | Populate mock fallback IOCs when a sample has no embedded indicators (useful for pipeline testing). |
| `--max-size-mb` | `100` | Maximum megabytes per file to scan for strings in memory (full-file hashes are still computed). |

### Common CLI Examples

* **Analyze a custom directory and output to `./output`:**
  ```bash
  python sabre.py ./quarantine -o ./output
  ```
* **Recursively scan nested sample folders including internal lab IPs:**
  ```bash
  python sabre.py ./malware_zoo -r --include-private-ips
  ```
* **Test downstream SIEM/SOAR ingestion using dummy files:**
  ```bash
  python sabre.py ./samples --demo-fallbacks
  ```

---

## 4. What SABRE Extracts & Generates

### Static Binary Metadata
* **Cryptographic Hashes**: `MD5`, `SHA-1`, and `SHA-256`.
* **Shannon Entropy**: Calculates whole-file and per-section entropy (`0.0`–`8.0` bits/byte) to flag packed, compressed, or encrypted binaries (`>= 7.2`).
* **Header Inspection**: Identifies Windows `PE32`/`PE32+` (`.exe`/`.dll`), Linux `ELF`, and macOS `Mach-O` formats, including architecture (`x86`, `x64`, `ARM64`), UTC compile timestamps, and PE section breakdown.

### Extracted Indicators (ASCII & UTF-16LE Wide Strings)
* **Network IOCs**: Routable IPv4 addresses, validated C2 domain names (filtering out DLL names, PE section names, and benign OS/CA certificate domains), full HTTP/HTTPS URLs, and URI paths.
* **Host IOCs**: Windows Registry persistence keys (`HKLM`, `HKCU`, `CurrentVersion\Run`, `Services`) and execution mutexes (`Global\`, `Local\`, `BaseNamedObjects\`).

### Exported Intelligence Artifacts
1. **Change Management Payload (`outputs/rfc/RFC_<filename>.json`)**
   * Prioritized (`P1 - Critical` or `P2 - High`) JSON payload containing binary metadata and structured containment directives for EDR hash blocking, firewall/DNS sinkholing, and host registry/mutex threat hunting.
2. **Suricata Network Rules (`outputs/suricata/<filename>.rules`)**
   * Deterministic SIDs (`9000000+`) with hex-escaped content strings covering:
     * `alert http` (`http.uri`)
     * `alert dns` (`dns.query`)
     * `alert tls` (`tls.sni`)
     * `alert ip` (outbound traffic to extracted C2 IPs)
3. **Sigma Host Rules (`outputs/sigma/<filename>_sigma.yml`)**
   * Multi-document YAML with deterministic UUIDv5 rule IDs covering:
     * `registry_event`: Detects modifications to extracted persistence registry keys.
     * `process_creation`: Detects execution via `SHA256`, `SHA1`, `MD5`, or `OriginalFileName`.

---

## 5. Programmatic Usage

You can import `SabreAnalyzer` directly into other Python automation workflows:

```python
from sabre import SabreAnalyzer

analyzer = SabreAnalyzer(
    sample_dir="samples",
    output_base="outputs",
    recursive=True,
)
results = analyzer.run()
for item in results:
    print(item["filename"], item["sha256"], item["c2_domains"])
```
