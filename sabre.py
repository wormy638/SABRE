#!/usr/bin/env python3
"""
SABRE: Static Artifact & Binary Rule Engine
Author: Kinetic Defense / Engineering Automation
Description: Self-contained, air-gapped static binary analyzer that extracts operational IOCs
             and exports Change Management RFCs, Suricata network rules, and Sigma host rules.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
import struct
import sys
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


class SabreAnalyzer:
    """SABRE (Static Artifact & Binary Rule Engine): Air-gapped binary analyzer and detection generator."""

    # Pre-compiled heuristic regex patterns
    IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
    )
    URL_PATTERN = re.compile(
        r"\bhttps?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?::\d{1,5})?(?:/[^\s\"'<>\x00]*)?",
        re.IGNORECASE,
    )
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,24})\b"
    )
    URI_PATTERN = re.compile(
        r"(?<![a-zA-Z0-9_/:.\\])/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+"
        r"(?:\?[a-zA-Z0-9_=&%;.-]+|\.(?:php|asp|aspx|jsp|cgi|bin|dat|dll|exe|ps1|sh))\b",
        re.IGNORECASE,
    )
    REGISTRY_PATTERN = re.compile(
        r"\b(?:(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|"
        r"HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\x00\r\n\"'<>|*?]+|"
        r"(?:Software|SYSTEM)\\(?:Microsoft\\Windows(?: NT)?\\CurrentVersion|"
        r"CurrentControlSet\\(?:Services|Control)|Classes|Policies|Wow6432Node)\\[^\x00\r\n\"'<>|*?]+|"
        r"Control Panel\\Desktop\\[^\x00\r\n\"'<>|*?]+)",
        re.IGNORECASE,
    )
    MUTEX_PATTERN = re.compile(
        r"(?<![$a-zA-Z0-9_\\])(?:Global\\[a-zA-Z0-9_.\-{}]+|Local\\[a-zA-Z0-9_.\-{}]+|"
        r"BaseNamedObjects\\[a-zA-Z0-9_.\-{}]+|"
        r"[a-zA-Z0-9_.\-{}]*Mutex[a-zA-Z0-9_.\-{}]*)\b"
    )
    UNSAFE_FILENAME_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

    # Pre-compiled binary header structs
    PE_OFFSET_STRUCT = struct.Struct("<I")
    PE_COFF_STRUCT = struct.Struct("<HHIIIHH")
    PE_MAGIC_STRUCT = struct.Struct("<H")
    PE_SECTION_STRUCT = struct.Struct("<IIII")

    # Common file/section extensions & runtime tokens that look like domains in binaries
    IGNORED_PSEUDO_TLDS = frozenset({
        "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "mui", "pdb", "obj", "lib",
        "exp", "def", "manifest", "res", "rsrc", "rc", "cpp", "cxx", "cc", "c", "h",
        "hpp", "hxx", "asm", "inc", "inl", "py", "pyc", "pyo", "pyd", "js", "ts",
        "vbs", "ps1", "bat", "cmd", "sh", "xml", "json", "yml", "yaml", "ini", "cfg",
        "conf", "txt", "log", "csv", "dat", "bin", "tmp", "bak", "old", "orig",
        "html", "htm", "css", "svg", "png", "jpg", "jpeg", "gif", "ico", "bmp",
        "wav", "mp3", "ogg", "mp4", "avi", "ttf", "otf", "woff", "woff2", "eot",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z",
        "tar", "gz", "bz2", "xz", "cab", "msi", "msp", "iso", "img", "vhd", "vhdx",
        "text", "rdata", "data", "idata", "edata", "pdata", "reloc", "tls", "bss",
        "crt", "debug", "drectve", "gfids", "giats", "gljmp", "eh_frame", "rodata",
        "got", "plt", "symtab", "strtab", "shstrtab", "init", "fini", "ctors", "dtors",
    })

    # Known valid TLDs commonly seen in C2 or enterprise environments
    COMMON_VALID_TLDS = frozenset({
        "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app",
        "dev", "cloud", "tech", "online", "site", "xyz", "top", "icu", "cyou", "club",
        "info", "biz", "name", "pro", "mobi", "asia", "tel", "travel", "xxx", "aero",
        "coop", "museum", "cat", "jobs", "post", "onion", "bit", "internal", "local",
        "lan", "corp", "home", "arpa", "test", "example", "invalid", "localhost",
        # Common ccTLDs
        "us", "uk", "ca", "au", "de", "fr", "nl", "ru", "cn", "jp", "kr", "br", "in",
        "it", "es", "pl", "se", "no", "fi", "dk", "ch", "at", "be", "cz", "hu", "ro",
        "bg", "gr", "pt", "ie", "il", "tr", "ua", "by", "kz", "uz", "za", "ng", "ke",
        "eg", "ma", "mx", "ar", "cl", "co", "pe", "ve", "uy", "sg", "my", "th", "vn",
        "ph", "id", "tw", "hk", "mo", "nz", "su", "to", "tv", "cc", "ws", "bz", "nu",
        "me", "ly", "gl", "fm", "am", "im", "gg", "je", "sh", "ac", "io", "vc", "ag",
        "sc", "la", "pw", "tk", "ml", "ga", "cf", "gq", "st", "so", "vg", "ms", "tc",
        "gd", "kn", "lc", "vc", "dm", "bs", "bb", "tt", "jm", "ky", "bm", "pr", "vi",
        "ir", "kp", "sy", "cu", "sd", "pk", "bd", "lk", "np",
    })

    # Benign domains commonly embedded in Windows PE certificates / manifests
    BENIGN_DOMAIN_SUFFIXES = (
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "live.com",
        "office.com",
        "digicert.com",
        "verisign.com",
        "symantec.com",
        "thawte.com",
        "sectigo.com",
        "comodoca.com",
        "usertrust.com",
        "globalsign.com",
        "globalsign.net",
        "entrust.net",
        "godaddy.com",
        "letsencrypt.org",
        "lencr.org",
        "w3.org",
        "xmlsoap.org",
        "schemas.microsoft.com",
        "purl.org",
        "iana.org",
        "aka.ms",
    )

    # Standard Windows Mutex API names to exclude from extracted mutex names
    IGNORED_MUTEX_TOKENS = frozenset({
        "CreateMutex", "CreateMutexA", "CreateMutexW", "CreateMutexEx",
        "CreateMutexExA", "CreateMutexExW", "OpenMutex", "OpenMutexA",
        "OpenMutexW", "ReleaseMutex", "WaitForSingleObject", "Mutex",
        "_Mutex_base", "_Mtx_init", "_Mtx_destroy", "_Mtx_lock", "_Mtx_unlock",
    })

    PE_MACHINE_TYPES = {
        0x014C: "x86 (I386)",
        0x8664: "x64 (AMD64)",
        0x01C0: "ARM",
        0xAA64: "ARM64",
        0x0200: "Intel Itanium",
    }

    def __init__(
        self,
        sample_dir: str = "samples",
        output_base: str = "outputs",
        min_string_length: int = 5,
        recursive: bool = False,
        include_private_ips: bool = False,
        demo_fallbacks: bool = False,
        max_file_size_mb: int = 100,
    ):
        self.sample_dir = Path(sample_dir)
        self.min_string_length = max(3, int(min_string_length))
        self.recursive = recursive
        self.include_private_ips = include_private_ips
        self.demo_fallbacks = demo_fallbacks
        self.max_file_size_bytes = max(1, int(max_file_size_mb)) * 1024 * 1024
        self._seen_output_names: Dict[str, str] = {}

        len_bytes = str(self.min_string_length).encode("ascii")
        self._ascii_str_re = re.compile(b"[ -~]{" + len_bytes + b",}")
        self._wide_str_re = re.compile(b"(?<![ -~])(?:[ -~]\\x00){" + len_bytes + b",}")

        self.output_dirs = {
            "rfc": Path(output_base) / "rfc",
            "suricata": Path(output_base) / "suricata",
            "sigma": Path(output_base) / "sigma",
        }

        # Ensure output directories exist
        for d in self.output_dirs.values():
            d.mkdir(parents=True, exist_ok=True)

    def run(self) -> List[Dict[str, Any]]:
        if not self.sample_dir.exists():
            print(f"[*] Sample directory '{self.sample_dir}' not found. Creating it...")
            self.sample_dir.mkdir(parents=True, exist_ok=True)
            print(f"[+] Please place target binaries into '{self.sample_dir}/' and re-run.")
            return []

        iterator = self.sample_dir.rglob("*") if self.recursive else self.sample_dir.iterdir()
        files = sorted([
            f for f in iterator
            if f.is_file() and f.suffix.lower() != ".md"
        ])
        if not files:
            print(f"[-] No sample files found in '{self.sample_dir}/'. Add binaries to analyze.")
            return []

        self._seen_output_names.clear()
        print(f"[*] Initializing SABRE Pipeline. Processing {len(files)} sample(s)...")
        results = []
        for file_path in files:
            try:
                artifact_data = self._analyze_file(file_path)
                if artifact_data is not None:
                    results.append(artifact_data)
            except OSError as exc:
                print(f"[!] I/O error analyzing '{file_path}': {exc}")
            except Exception as exc:
                print(f"[!] Unexpected error analyzing '{file_path}': {exc}")
        return results

    def _read_sample_bytes(self, file_path: Path) -> Tuple[bytes, Dict[str, str], int]:
        """Opens the file once (avoiding TOCTOU stat races), hashes full content, and caps memory buffer."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        captured_chunks: List[bytes] = []
        captured_bytes = 0

        with open(file_path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

                if captured_bytes < self.max_file_size_bytes:
                    remaining = self.max_file_size_bytes - captured_bytes
                    captured_chunks.append(chunk[:remaining])
                    captured_bytes += min(len(chunk), remaining)

        if file_size > self.max_file_size_bytes:
            print(
                f"   [!] File size ({file_size:,} bytes) exceeds limit "
                f"({self.max_file_size_bytes:,} bytes); static string scan truncated to limit."
            )

        hashes = {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }
        return b"".join(captured_chunks), hashes, file_size

    def _hash_file(self, file_path: Path) -> str:
        """Computes the SHA-256 hex digest of a file."""
        with open(file_path, "rb") as f:
            if hasattr(hashlib, "file_digest"):
                return hashlib.file_digest(f, "sha256").hexdigest()
            sha256_hash = hashlib.sha256()
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()

    @staticmethod
    def _calculate_entropy(data: Union[bytes, bytearray, memoryview]) -> float:
        """Calculates Shannon entropy (0.0 to 8.0 bits/byte) without copying memoryview slices."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        return round(
            -sum((count / length) * math.log2(count / length) for count in counts.values()),
            4,
        )

    def _inspect_binary_metadata(self, content: bytes, file_size: int) -> Dict[str, Any]:
        """Extracts file format, entropy, and PE/ELF structural metadata using stdlib struct."""
        entropy = self._calculate_entropy(content)
        if entropy >= 7.2:
            entropy_assessment = "High (>=7.2) - Likely Packed, Compressed, or Encrypted"
        elif entropy >= 6.0:
            entropy_assessment = "Moderate (6.0-7.2) - Standard Compiled Native Code"
        else:
            entropy_assessment = "Low (<6.0) - Text, Script, or Unpacked Data"

        metadata: Dict[str, Any] = {
            "size_bytes": file_size,
            "entropy": entropy,
            "entropy_assessment": entropy_assessment,
            "file_type": "Unknown / Raw Binary",
            "pe_info": None,
        }

        if content.startswith(b"MZ") and len(content) >= 0x40:
            pe_offset = self.PE_OFFSET_STRUCT.unpack_from(content, 0x3C)[0]
            if 0 <= pe_offset <= len(content) - 24 and content[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                machine, num_sections, timestamp, _, _, opt_header_size, characteristics = (
                    self.PE_COFF_STRUCT.unpack_from(content, pe_offset + 4)
                )
                opt_offset = pe_offset + 24
                pe_magic = (
                    self.PE_MAGIC_STRUCT.unpack_from(content, opt_offset)[0]
                    if opt_offset + 2 <= len(content)
                    else 0
                )
                pe_format = "PE32+" if pe_magic == 0x20B else ("PE32" if pe_magic == 0x10B else "PE")
                is_dll = bool(characteristics & 0x2000)
                metadata["file_type"] = f"Windows {pe_format} {'DLL' if is_dll else 'Executable'}"

                compile_time_iso = None
                if timestamp > 0:
                    try:
                        compile_time_iso = datetime.datetime.fromtimestamp(
                            timestamp, tz=datetime.timezone.utc
                        ).isoformat()
                    except (OverflowError, OSError, ValueError):
                        compile_time_iso = None

                sections: List[Dict[str, Any]] = []
                sec_table_offset = opt_offset + opt_header_size
                mv = memoryview(content)
                for i in range(min(num_sections, 64)):
                    sec_offset = sec_table_offset + (i * 40)
                    if sec_offset + 40 > len(content):
                        break
                    raw_name = content[sec_offset : sec_offset + 8].split(b"\x00", 1)[0]
                    sec_name = raw_name.decode("latin-1", errors="replace").strip()
                    vsize, _, raw_size, raw_ptr = self.PE_SECTION_STRUCT.unpack_from(content, sec_offset + 8)
                    if 0 <= raw_ptr < len(content) and raw_size > 0:
                        end_ptr = min(len(content), raw_ptr + raw_size)
                        sec_entropy = self._calculate_entropy(mv[raw_ptr:end_ptr])
                    else:
                        sec_entropy = 0.0
                    sections.append({
                        "name": sec_name or f"sec_{i}",
                        "virtual_size": vsize,
                        "raw_size": raw_size,
                        "entropy": sec_entropy,
                    })
                mv.release()

                metadata["pe_info"] = {
                    "architecture": self.PE_MACHINE_TYPES.get(machine, f"0x{machine:04x}"),
                    "compile_timestamp_utc": compile_time_iso,
                    "is_dll": is_dll,
                    "sections": sections,
                }
            else:
                metadata["file_type"] = "DOS / MZ Executable"
        elif content.startswith(b"\x7fELF") and len(content) >= 20:
            ei_class = content[4]
            elf_bits = "64-bit" if ei_class == 2 else ("32-bit" if ei_class == 1 else "Unknown-bit")
            metadata["file_type"] = f"Linux/Unix ELF {elf_bits} Binary"
        elif content[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            metadata["file_type"] = "macOS Mach-O Binary"
        elif content.lstrip(b"\xef\xbb\xbf").startswith(b"#!"):
            metadata["file_type"] = "Executable Script"

        return metadata

    def _extract_strings(self, file_or_bytes: Any, min_length: Optional[int] = None) -> List[str]:
        """Extracts both ASCII and UTF-16LE (wide-char) printable strings from binary content."""
        min_len = self.min_string_length if min_length is None else max(1, int(min_length))
        if isinstance(file_or_bytes, (bytes, bytearray)):
            content = bytes(file_or_bytes)
        else:
            with open(file_or_bytes, "rb") as f:
                content = f.read(self.max_file_size_bytes)

        if min_len == self.min_string_length:
            ascii_re = self._ascii_str_re
            wide_re = self._wide_str_re
        else:
            len_bytes = str(min_len).encode("ascii")
            ascii_re = re.compile(b"[ -~]{" + len_bytes + b",}")
            wide_re = re.compile(b"(?<![ -~])(?:[ -~]\\x00){" + len_bytes + b",}")

        # 1. Single-byte printable ASCII strings
        ascii_strings = [m.decode("latin-1") for m in ascii_re.findall(content)]

        # 2. UTF-16LE (wide-character) printable strings common in Windows binaries
        wide_strings = [m.decode("utf-16le") for m in wide_re.findall(content)]

        # Preserve discovery order while deduplicating
        seen = set()
        combined: List[str] = []
        for s in ascii_strings + wide_strings:
            cleaned = s.strip()
            if len(cleaned) >= min_len and cleaned not in seen:
                seen.add(cleaned)
                combined.append(cleaned)
        return combined

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validates an IPv4 string and filters out non-routable/version-like addresses."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local:
            return False

        # Filter common PE version numbers (e.g., 1.0.0.0, 4.0.30319.1, 6.0.6000.16386)
        octets = [int(o) for o in ip_str.split(".")]
        if octets[0] in (0, 1, 2, 4, 5, 6, 10) and octets[1] == 0 and octets[2] == 0:
            return False

        if self.include_private_ips:
            return not ip_obj.is_reserved
        return ip_obj.is_global

    def _is_valid_domain(self, domain: str) -> bool:
        """Filters out DLL names, PE section names, code symbols, and benign certificate domains."""
        candidate = domain.strip(".").lower()
        if len(candidate) < 4 or len(candidate) > 253 or ".." in candidate:
            return False

        labels = candidate.split(".")
        if len(labels) < 2:
            return False

        tld = labels[-1]
        if tld in self.IGNORED_PSEUDO_TLDS or tld not in self.COMMON_VALID_TLDS:
            return False

        # Disallow purely numeric labels or labels starting/ending with hyphens or underscores
        for label in labels:
            if not label or label.startswith("-") or label.endswith("-"):
                return False
            if label.isdigit():
                return False

        # Exclude known benign OS/CA certificate domains
        if any(candidate == b or candidate.endswith("." + b) for b in self.BENIGN_DOMAIN_SUFFIXES):
            return False

        return True

    def _extract_indicators(self, strings: Sequence[str]) -> Dict[str, List[str]]:
        """Extracts, validates, deduplicates, and ranks network and host IOCs from strings."""
        found_ips = set()
        found_domains = set()
        found_urls = set()
        found_uris = set()
        found_mutexes = set()
        found_registry = set()

        for s in strings:
            # Skip obvious C++ mangled symbols and XML declarations for URL/URI parsing
            is_mangled_or_xml = s.startswith("?") or s.startswith("<?xml")
            s_without_urls = s

            # 1. Full URLs
            if not is_mangled_or_xml and ("http://" in s.lower() or "https://" in s.lower()):
                for url in self.URL_PATTERN.findall(s):
                    cleaned_url = url.rstrip(".,;)'\"]}>")
                    s_without_urls = s_without_urls.replace(url, " ")
                    # Skip benign certificate/schema URLs
                    lower_url = cleaned_url.lower()
                    if not any(b in lower_url for b in self.BENIGN_DOMAIN_SUFFIXES):
                        found_urls.add(cleaned_url)
                        # Also extract URI path from URL if present
                        parts = cleaned_url.split("/", 3)
                        if len(parts) == 4 and parts[3]:
                            found_uris.add("/" + parts[3])

            # 2. IPv4 Addresses
            for ip in self.IP_PATTERN.findall(s):
                if self._is_valid_ip(ip):
                    found_ips.add(ip)

            # 3. Domains
            for match in self.DOMAIN_PATTERN.finditer(s):
                domain = match.group(0)
                if self._is_valid_domain(domain):
                    found_domains.add(domain.lower())

            # 4. Standalone URI Paths (searched on string with full URLs removed)
            if not is_mangled_or_xml:
                for uri in self.URI_PATTERN.findall(s_without_urls):
                    if len(uri) >= 4 and not uri.startswith("//"):
                        found_uris.add(uri)

            # 5. Registry Keys
            for reg in self.REGISTRY_PATTERN.findall(s):
                cleaned_reg = reg.strip().rstrip("\\")
                if len(cleaned_reg) >= 12:
                    found_registry.add(cleaned_reg)

            # 6. Mutexes
            for mtx in self.MUTEX_PATTERN.findall(s):
                if mtx not in self.IGNORED_MUTEX_TOKENS and len(mtx) >= 6:
                    found_mutexes.add(mtx)

        return {
            "c2_ips": sorted(found_ips),
            "c2_domains": sorted(found_domains),
            "c2_urls": sorted(found_urls),
            "uri_patterns": sorted(found_uris, key=lambda u: ("?" not in u, -len(u), u)),
            "mutexes": sorted(found_mutexes, key=lambda m: (not m.startswith(("Global\\", "Local\\")), m)),
            "registry_keys": sorted(
                found_registry,
                key=lambda r: ("currentversion\\run" not in r.lower(), -len(r), r),
            ),
        }

    def _resolve_output_stem(self, filename: str, sha256_hex: str) -> str:
        """Sanitizes filename for output paths and prevents overwrite collisions in recursive scans."""
        safe_name = self.UNSAFE_FILENAME_PATTERN.sub("_", filename).strip(" .") or "sample"
        prev_hash = self._seen_output_names.get(safe_name)
        if prev_hash is not None and prev_hash != sha256_hex:
            safe_name = f"{safe_name}_{sha256_hex[:8]}"
        self._seen_output_names[safe_name] = sha256_hex
        return safe_name

    @staticmethod
    def _atomic_write_text(target_path: Path, text: str) -> None:
        """Writes text atomically via a temporary file in the target directory to prevent partial reads."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_name: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(target_path.parent),
                prefix=f".{target_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp_file:
                tmp_name = tmp_file.name
                tmp_file.write(text)
            os.replace(tmp_name, target_path)
        except Exception:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise

    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        print(f"\n[+] Analyzing: {file_path.name}")
        content, hashes, file_size = self._read_sample_bytes(file_path)
        metadata = self._inspect_binary_metadata(content, file_size)
        strings = self._extract_strings(content)
        # Release raw binary buffer immediately after string extraction
        del content

        iocs = self._extract_indicators(strings)
        del strings

        c2_ips = iocs["c2_ips"]
        c2_domains = iocs["c2_domains"]
        c2_urls = iocs["c2_urls"]
        uri_patterns = iocs["uri_patterns"]
        mutexes = iocs["mutexes"]
        registry_keys = iocs["registry_keys"]

        used_fallbacks = False
        if self.demo_fallbacks:
            if not c2_ips:
                c2_ips = ["198.51.100.45"]
                used_fallbacks = True
            if not c2_domains:
                c2_domains = ["malicious-payload-drop.internal"]
                used_fallbacks = True
            if not uri_patterns:
                uri_patterns = ["/gate.php?key="]
                used_fallbacks = True
            if not mutexes:
                mutexes = ["Global\\DefaultMalwareMutex"]
                used_fallbacks = True
            if not registry_keys:
                registry_keys = ["Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence"]
                used_fallbacks = True

        output_stem = self._resolve_output_stem(file_path.name, hashes["sha256"])

        artifact_data: Dict[str, Any] = {
            "filename": file_path.name,
            "output_stem": output_stem,
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "metadata": metadata,
            "c2_ips": c2_ips,
            "c2_domains": c2_domains,
            "c2_urls": c2_urls,
            "uri_patterns": uri_patterns,
            "mutexes": mutexes,
            "registry_keys": registry_keys,
            # Backwards-compatible singular fields for external consumers
            "mutex": mutexes[0] if mutexes else None,
            "uri_pattern": uri_patterns[0] if uri_patterns else None,
            "registry_key": registry_keys[0] if registry_keys else None,
            "used_demo_fallbacks": used_fallbacks,
        }

        print(
            f"   |-- Type: {metadata['file_type']} | "
            f"Size: {metadata['size_bytes']:,} B | "
            f"Entropy: {metadata['entropy']} bits/B"
        )
        print(
            f"   |-- Extracted IOCs: {len(c2_ips)} IP(s), {len(c2_domains)} Domain(s), "
            f"{len(uri_patterns)} URI(s), {len(registry_keys)} Registry Key(s), {len(mutexes)} Mutex(es)"
        )

        # Generate Exports
        self._export_rfc(artifact_data)
        self._export_suricata(artifact_data)
        self._export_sigma(artifact_data)
        return artifact_data

    def _export_rfc(self, data: Dict[str, Any]) -> Path:
        metadata = data.get("metadata", {})
        network_iocs = data.get("c2_ips", []) + data.get("c2_domains", []) + data.get("c2_urls", [])
        registry_keys = data.get("registry_keys", [])
        mutexes = data.get("mutexes", [])

        requested_actions: List[Dict[str, Any]] = [
            {
                "action_type": "EDR / Endpoint Control",
                "directive": "Block binary execution by cryptographic hash across all enterprise endpoints",
                "indicators": [
                    f"SHA256:{data['sha256']}",
                    f"SHA1:{data.get('sha1', '')}",
                    f"MD5:{data.get('md5', '')}",
                ],
            }
        ]

        if network_iocs:
            requested_actions.append({
                "action_type": "Network Firewalls / Proxy / DNS",
                "directive": "Block egress traffic and sinkhole DNS requests to identified C2 infrastructure",
                "indicators": network_iocs,
            })

        if registry_keys or mutexes:
            host_directives = []
            if registry_keys:
                host_directives.append(
                    f"Inspect endpoints for registry persistence keys ({len(registry_keys)} identified)"
                )
            if mutexes:
                host_directives.append(
                    f"Scan active handles for behavioral mutex indicators ({len(mutexes)} identified)"
                )
            requested_actions.append({
                "action_type": "Host Remediation & Threat Hunting",
                "directive": "; ".join(host_directives),
                "registry_keys": registry_keys,
                "mutexes": mutexes,
            })

        priority = "P1 - Critical" if (network_iocs or registry_keys) else "P2 - High"
        rfc_payload = {
            "rfc_title": f"SABRE Emergency Mitigation: Containment for Binary - {data['filename']}",
            "category": "Security Incident Response",
            "priority": priority,
            "justification": (
                f"SABRE static analysis signature extraction on {data['filename']} "
                f"(SHA256: {data['sha256'][:16]}..., Type: {metadata.get('file_type', 'Binary')}, "
                f"Entropy: {metadata.get('entropy', 0.0)}) identified "
                f"{len(network_iocs)} network indicator(s) and "
                f"{len(registry_keys) + len(mutexes)} host artifact(s)."
            ),
            "binary_metadata": {
                "filename": data["filename"],
                "sha256": data["sha256"],
                "sha1": data.get("sha1"),
                "md5": data.get("md5"),
                "size_bytes": metadata.get("size_bytes"),
                "file_type": metadata.get("file_type"),
                "entropy": metadata.get("entropy"),
                "entropy_assessment": metadata.get("entropy_assessment"),
                "pe_info": metadata.get("pe_info"),
            },
            "requested_actions": requested_actions,
        }

        stem = data.get("output_stem") or data["filename"]
        out_path = self.output_dirs["rfc"] / f"RFC_{stem}.json"
        self._atomic_write_text(out_path, json.dumps(rfc_payload, indent=4) + "\n")
        print(f"   |-- RFC Payload saved: {out_path}")
        return out_path

    @staticmethod
    def _escape_suricata_content(raw_value: str) -> str:
        """Escapes Suricata special characters (\\, \", ;, |) into hex pipe notation."""
        escaped = []
        for ch in raw_value:
            code = ord(ch)
            if ch in ('"', ";", "\\", "|") or code < 0x20 or code > 0x7E:
                escaped.append(f"|{code:02x}|")
            else:
                escaped.append(ch)
        return "".join(escaped)

    @staticmethod
    def _derive_base_sid(sha256_hex: str) -> int:
        """Derives a deterministic base SID in the local rule range (9000000 - 9999999) with 40-SID spacing."""
        offset = int(sha256_hex[:8], 16) % 25000
        return 9000000 + (offset * 40)

    def _export_suricata(self, data: Dict[str, Any]) -> Path:
        base_sid = self._derive_base_sid(data["sha256"])
        sid_counter = base_sid
        rules: List[str] = []
        safe_fname = self._escape_suricata_content(data["filename"])

        # 1. HTTP URI Rules
        uri_list = list(data.get("uri_patterns") or [])
        if not uri_list and data.get("uri_pattern"):
            uri_list = [data["uri_pattern"]]

        for uri in uri_list[:10]:
            escaped_uri = self._escape_suricata_content(uri)
            startswith_mod = " startswith;" if uri.startswith("/") else ""
            rules.append(
                f"alert http $HOME_NET any -> $EXTERNAL_NET any (\n"
                f'    msg:"SABRE-CNC Suspected Static URI Indicator Match [{safe_fname}]";\n'
                f"    flow:established,to_server;\n"
                f'    http.uri; content:"{escaped_uri}";{startswith_mod}\n'
                f"    classtype:trojan-activity;\n"
                f'    reference:hashes,sha256:{data["sha256"]};\n'
                f"    sid:{sid_counter}; rev:1;\n"
                f")"
            )
            sid_counter += 1

        # 2. DNS & TLS SNI Rules for Extracted Domains
        for domain in (data.get("c2_domains") or [])[:10]:
            escaped_dom = self._escape_suricata_content(domain)
            rules.append(
                f"alert dns $HOME_NET any -> any any (\n"
                f'    msg:"SABRE-CNC Suspected Static DNS Query [{safe_fname} - {escaped_dom}]";\n'
                f'    dns.query; content:"{escaped_dom}"; nocase; endswith;\n'
                f"    classtype:trojan-activity;\n"
                f'    reference:hashes,sha256:{data["sha256"]};\n'
                f"    sid:{sid_counter}; rev:1;\n"
                f")"
            )
            sid_counter += 1

            rules.append(
                f"alert tls $HOME_NET any -> $EXTERNAL_NET any (\n"
                f'    msg:"SABRE-CNC Suspected Static TLS SNI [{safe_fname} - {escaped_dom}]";\n'
                f"    flow:established,to_server;\n"
                f'    tls.sni; content:"{escaped_dom}"; nocase; endswith;\n'
                f"    classtype:trojan-activity;\n"
                f'    reference:hashes,sha256:{data["sha256"]};\n'
                f"    sid:{sid_counter}; rev:1;\n"
                f")"
            )
            sid_counter += 1

        # 3. Direct C2 IP Egress Rule
        c2_ips = data.get("c2_ips") or []
        if c2_ips:
            ip_group = "[" + ",".join(c2_ips[:20]) + "]" if len(c2_ips) > 1 else c2_ips[0]
            rules.append(
                f"alert ip $HOME_NET any -> {ip_group} any (\n"
                f'    msg:"SABRE-CNC Outbound Traffic to Extracted Static C2 IP [{safe_fname}]";\n'
                f"    flow:to_server;\n"
                f"    classtype:trojan-activity;\n"
                f'    reference:hashes,sha256:{data["sha256"]};\n'
                f"    sid:{sid_counter}; rev:1;\n"
                f")"
            )
            sid_counter += 1

        if not rules:
            rules.append(
                f"# No network indicators (IPs, Domains, or URIs) extracted from {data['filename']} "
                f"(SHA256: {data['sha256']})"
            )

        stem = data.get("output_stem") or data["filename"]
        out_path = self.output_dirs["suricata"] / f"{stem}.rules"
        self._atomic_write_text(out_path, "\n\n".join(rules) + "\n")
        print(f"   |-- Suricata Rules saved: {out_path} ({len(rules)} block(s))")
        return out_path

    @staticmethod
    def _escape_sigma_single_quote(val: str) -> str:
        """Escapes single quotes for YAML single-quoted scalars ('' in YAML)."""
        return val.replace("'", "''")

    def _export_sigma(self, data: Dict[str, Any]) -> Path:
        reg_keys = list(data.get("registry_keys") or [])
        if not reg_keys and data.get("registry_key"):
            reg_keys = [data["registry_key"]]

        mutexes = list(data.get("mutexes") or [])
        if not mutexes and data.get("mutex"):
            mutexes = [data["mutex"]]

        today = datetime.date.today().isoformat()
        safe_fname = self._escape_sigma_single_quote(data["filename"])
        yaml_docs: List[str] = []

        # Document 1: Registry Persistence Rule (if registry keys found)
        if reg_keys:
            reg_rule_id = uuid.uuid5(uuid.NAMESPACE_OID, f"sabre:sigma:registry:{data['sha256']}")
            reg_items = "\n".join(
                f"      - '{self._escape_sigma_single_quote(k)}'" for k in reg_keys[:25]
            )
            yaml_docs.append(
                f"title: SABRE Persistence Detection for {safe_fname}\n"
                f"id: {reg_rule_id}\n"
                f"status: experimental\n"
                f"description: Automatically generated Sigma rule from SABRE static heuristic analysis of {safe_fname} (SHA256: {data['sha256']}).\n"
                f"author: SABRE (Static Artifact & Binary Rule Engine)\n"
                f"date: {today}\n"
                f"logsource:\n"
                f"  category: registry_event\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    TargetObject|contains:\n"
                f"{reg_items}\n"
                f"  condition: selection\n"
                f"falsepositives:\n"
                f"  - Authorized software installations\n"
                f"level: high"
            )

        # Document 2: Process Creation / Cryptographic Hash & Filename Execution Rule
        proc_rule_id = uuid.uuid5(uuid.NAMESPACE_OID, f"sabre:sigma:process:{data['sha256']}")
        hash_filters = [f"      - 'SHA256={data['sha256']}'"]
        if data.get("md5"):
            hash_filters.append(f"      - 'MD5={data['md5']}'")
        if data.get("sha1"):
            hash_filters.append(f"      - 'SHA1={data['sha1']}'")
        hash_block = "\n".join(hash_filters)

        mutex_note = (
            f" Observed Mutex(es): {', '.join(self._escape_sigma_single_quote(m) for m in mutexes[:5])}."
            if mutexes
            else ""
        )

        yaml_docs.append(
            f"title: SABRE Suspicious Binary Execution - {safe_fname}\n"
            f"id: {proc_rule_id}\n"
            f"status: experimental\n"
            f"description: Detects execution of binary {safe_fname} via cryptographic hashes extracted by SABRE.{mutex_note}\n"
            f"author: SABRE (Static Artifact & Binary Rule Engine)\n"
            f"date: {today}\n"
            f"logsource:\n"
            f"  category: process_creation\n"
            f"  product: windows\n"
            f"detection:\n"
            f"  selection_hashes:\n"
            f"    Hashes|contains:\n"
            f"{hash_block}\n"
            f"  selection_filename:\n"
            f"    OriginalFileName: '{safe_fname}'\n"
            f"  condition: selection_hashes or selection_filename\n"
            f"falsepositives:\n"
            f"  - Unlikely for cryptographic hash match\n"
            f"level: critical"
        )

        stem = data.get("output_stem") or data["filename"]
        out_path = self.output_dirs["sigma"] / f"{stem}_sigma.yml"
        self._atomic_write_text(out_path, "\n---\n".join(yaml_docs) + "\n")
        print(f"   '-- Sigma Rule saved: {out_path} ({len(yaml_docs)} document(s))")
        return out_path


# Backwards-compatible alias
NativeMalwareAnalyzer = SabreAnalyzer


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sabre",
        description="SABRE (Static Artifact & Binary Rule Engine): Air-gapped static binary analyzer and RFC/Suricata/Sigma generator.",
    )
    parser.add_argument(
        "sample_dir",
        nargs="?",
        default="samples",
        help="Directory containing sample binaries to analyze (default: samples).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="outputs",
        help="Base directory for generated RFC, Suricata, and Sigma artifacts (default: outputs).",
    )
    parser.add_argument(
        "-m",
        "--min-length",
        type=int,
        default=5,
        help="Minimum printable string length to extract (default: 5).",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories inside the sample directory.",
    )
    parser.add_argument(
        "--include-private-ips",
        action="store_true",
        help="Include RFC 1918 private IPv4 addresses in extracted C2 indicators.",
    )
    parser.add_argument(
        "--demo-fallbacks",
        action="store_true",
        help="Populate fallback mock indicators when a binary contains no embedded IOCs.",
    )
    parser.add_argument(
        "--max-size-mb",
        type=int,
        default=100,
        help="Maximum bytes (in MB) per sample to scan for strings in memory (default: 100).",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="replace")

    args = parse_args()
    analyzer = SabreAnalyzer(
        sample_dir=args.sample_dir,
        output_base=args.output_dir,
        min_string_length=args.min_length,
        recursive=args.recursive,
        include_private_ips=args.include_private_ips,
        demo_fallbacks=args.demo_fallbacks,
        max_file_size_mb=args.max_size_mb,
    )
    analyzer.run()
