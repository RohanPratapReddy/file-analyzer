"""
config_formats -- real, pure-stdlib parsers for every configuration file format.

This module backs :class:`..config.config_analyzer.ConfigAnalyzer`.  It covers the
345 ``config``-type residual extensions catalogued in
``DUMP/tabgen/docs/residual.json`` (families in ``_CONFIG_REGISTRY`` below).

Contract (identical in spirit to :mod:`..database.db_formats` and
:mod:`..binary.format_parsers`):

  * Content is sniffed first.  A genuinely binary payload -- whether the format
    is inherently binary (``.abr``/``.aco``/``.suo``/``.fxb`` ...) or a text
    format carrying binary bytes -- is NEVER fake-parsed: it degrades to an
    honest forensic byte profile (size / sha256 / entropy / printable-string
    sample count) with no fabricated keys or values.
  * A text config is parsed by a real parser for its syntax family into a
    canonical nested Python object (``dict`` / ``list`` / scalar).  The parsers
    are genuine (configparser-style INI, RFC822 deb822, s-expression reader,
    Windows ``.reg`` decoder, Fortran namelist, Valve KeyValues, PostScript
    ``.ppd``, cron/fstab/hosts tables, a block-directive parser for
    nginx/apache/caddy/hcl, an indentation YAML-subset parser, ``plistlib`` for
    plists, ``tomllib`` for TOML, ``xml.etree`` for XML, ``json`` -- with
    tolerant comment/trailing-comma stripping -- for JSON).  Where a family is a
    complex DSL, the parser extracts the real assignments/records it can and
    reports ``status="partial"`` -- it never invents structure.
  * Never stores the raw payload.  Scalars are bounded; strings truncated.

Public API:
  known_exts()            -> frozenset of every extension this module claims
  family_for(ext)         -> syntax-family string for an extension
  label_for(ext)          -> human label for an extension
  routing_suffixes()      -> tuple(sorted known_exts())
  analyze(path, ext)      -> profile dict:
      {
        "format": label, "family": fam, "engine": eng,
        "detected_via": "extension"|"content"|"binary_sniff",
        "status": "ok"|"partial"|"forensic"|"empty",
        "root": <canonical nested object or None>,
        "properties": [(group, name, value), ...],   # file-level metadata
        "notes": str,
        "byte_size": int, "encoding": str,
        # forensic-only: "sha256", "entropy", "printable_strings"
      }
"""

from __future__ import annotations

import csv as _csvmod
import hashlib
import io
import json
import re
from math import log2
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # Python 3.11+
    import tomllib as _tomllib
except Exception:  # pragma: no cover
    _tomllib = None

import plistlib
import xml.etree.ElementTree as _ET

# ======================================================================
# Registry: extension -> (syntax_family, human_label)   (all 345 config exts)
# ======================================================================
_CONFIG_REGISTRY: Dict[str, Tuple[str, str]] = {
    ".abr": ("opaque_binary", "Photoshop Brush Preset"),
    ".acf": ("acf", "X-Plane Aircraft File"),
    ".acl": ("directive", "Access Control List Definition"),
    ".aco": ("opaque_binary", "Adobe Color Swatch File"),
    ".act": ("opaque_binary", "Adobe Color Table"),
    ".action": ("yaml", "GitHub Action Metadata File"),
    ".adg": ("opaque_binary", "Ableton Device Group"),
    ".adtxt": ("csv", "Ads.txt Authorized Seller File"),
    ".aero": ("opaque_binary", "Windows Aero Theme Resource"),
    ".air": ("ini", "Flight Simulator Aircraft Config"),
    ".alacritty": ("toml", "Alacritty Terminal Configuration"),
    ".anacrontab": ("crontab", "Anacron Schedule Table"),
    ".appspec": ("json", "AWS CodeDeploy Application Spec"),
    ".automount": ("ini", "systemd Automount Unit"),
    ".babelrc": ("json", "Babel Configuration"),
    ".bacnet": ("properties", "BACnet Device Configuration"),
    ".bazel": ("starlark", "Bazel Build File"),
    ".bicepparam": ("kv_dsl", "Bicep Parameter File"),
    ".bnd": ("properties", "Bnd OSGi Bundle Descriptor"),
    ".brewfile": ("ruby_dsl", "Homebrew Bundle Manifest"),
    ".buck": ("starlark", "Buck Build File"),
    ".buildpack": ("directive", "Cloud Native Buildpack Descriptor"),
    ".buildspec": ("json", "AWS CodeBuild Build Specification"),
    ".cabal": ("kv_dsl", "Haskell Cabal Package Description"),
    ".caddyfile": ("directive", "Caddy Server Configuration"),
    ".capa": ("yaml", "Capa Capability Rule File"),
    ".cargo": ("toml", "Cargo Manifest Reference"),
    ".cas": ("opaque_binary", "ANSYS Fluent Case File"),
    ".ccd": ("ini", "CloneCD Disc Image Descriptor"),
    ".ccy": ("ini", "Currency Configuration File"),
    ".cda": ("opaque_binary", "CD Audio Track Shortcut"),
    ".changes": ("deb822", "Debian Upload Control File"),
    ".cht": ("ini", "Emulator Cheat File"),
    ".circleci": ("yaml", "CircleCI Pipeline Config"),
    ".clang-format": ("yaml", "Clang Format Style File"),
    ".clang-tidy": ("yaml", "Clang-Tidy Configuration"),
    ".classpath": ("xml", "Eclipse Java Classpath"),
    ".cloudbuild": ("json", "Google Cloud Build Config"),
    ".cloudinit": ("yaml", "Cloud-init User Data File"),
    ".cm": ("kv_dsl", "SML Compilation Manager File"),
    ".cntl": ("rulelist", "MVS Control Data Set"),
    ".codeowners": ("rulelist", "Code Ownership Rules File"),
    ".colorscheme": ("ini", "Desktop Color Scheme File"),
    ".conkyrc": ("ini", "Conky System Monitor Configuration"),
    ".containerfile": ("dockerfile", "OCI Container Build Recipe"),
    ".control": ("deb822", "Debian Package Control File"),
    ".cpf": ("directive", "Common Power Format"),
    ".cpg": ("rulelist", "Shapefile Code Page File"),
    ".cproject": ("xml", "Embedded CDT Project Settings"),
    ".crontab": ("crontab", "Cron Schedule Table"),
    ".csh": ("opaque_binary", "Photoshop Custom Shapes"),
    ".ctg": ("opaque_binary", "Canon Catalog File"),
    ".cube": ("auto", "OLAP Cube Definition"),
    ".dashboard": ("json", "BI Dashboard Definition"),
    ".datahub": ("json", "DataHub Metadata Ingestion Recipe"),
    ".dbd": ("rulelist", "IMS Database Descriptor"),
    ".debezium": ("json", "Debezium Connector Config"),
    ".default": ("auto", "Default Configuration Copy"),
    ".defconfig": ("properties", "Default Kernel Configuration"),
    ".designspace": ("xml", "Variable Font Design Space"),
    ".desktop": ("ini", "Desktop Entry / Shortcut"),
    ".device": ("ini", "systemd Device Unit"),
    ".dfm": ("dfm", "Delphi Form File"),
    ".dhall": ("kv_dsl", "Dhall Configuration Language File"),
    ".dhclient": ("directive", "DHCP Client Configuration"),
    ".dircolors": ("directive", "Directory Color Configuration"),
    ".directory": ("ini", "Desktop Directory Entry"),
    ".dist": ("auto", "Distribution Default Configuration"),
    ".dmc": ("xml", "Data Migration Configuration"),
    ".dockercompose": ("yaml", "Docker Compose Service Definition"),
    ".dockerfile": ("dockerfile", "Docker Image Build Recipe"),
    ".dockerignore": ("rulelist", "Docker Ignore Rules"),
    ".docusaurus": ("json", "Docusaurus Site Configuration"),
    ".doxyfile": ("properties", "Doxygen Configuration File"),
    ".dq": ("yaml", "Data Quality Rule Definition"),
    ".drone": ("yaml", "Drone CI Pipeline File"),
    ".dsc": ("deb822", "Descriptor / Control File"),
    ".dub": ("json", "D Language DUB Package File"),
    ".dws": ("opaque_binary", "AutoCAD Drawing Standards File"),
    ".editorconfig": ("ini", "EditorConfig Style Definition"),
    ".eds": ("ini", "Electronic Data Sheet (CANopen/EtherNet-IP)"),
    ".entitlements": ("plist", "Code Signing Entitlements"),
    ".epf": ("properties", "Eclipse Preferences File"),
    ".epics": ("directive", "EPICS Control System Database"),
    ".eslintrc": ("json", "ESLint Configuration"),
    ".expo": ("json", "Expo App Configuration"),
    ".fea": ("directive", "OpenType Feature File"),
    ".filters": ("xml", "Visual C++ Filters File"),
    ".flake": ("kv_dsl", "Nix Flake Definition"),
    ".flatpakref": ("ini", "Flatpak Application Reference"),
    ".flink": ("yaml", "Apache Flink Job Definition"),
    ".fm3": ("opaque_binary", "Lotus 1-2-3 Formatting File"),
    ".foam": ("marker", "OpenFOAM Case Marker File"),
    ".fstab": ("fstab", "Filesystem Mount Table"),
    ".ftp": ("ini", "FTP Connection Profile"),
    ".fuse": ("properties", "Microcontroller Fuse Settings"),
    ".fxb": ("opaque_binary", "VST Plugin Bank"),
    ".fxp": ("opaque_binary", "VST Plugin Preset"),
    ".gih": ("opaque_binary", "GIMP Image Hose Brush"),
    ".gitattributes": ("rulelist", "Git Attributes File"),
    ".gitignore": ("rulelist", "Git Ignore Rules"),
    ".gitmodules": ("ini", "Git Submodule Configuration"),
    ".gn": ("starlark", "GN Build Configuration"),
    ".gni": ("starlark", "GN Import File"),
    ".godot": ("ini", "Godot Project File"),
    ".gpl": ("gimp_palette", "GIMP Palette File"),
    ".grub": ("directive", "GRUB Bootloader Configuration"),
    ".gsd": ("ini", "PROFIBUS Device Description"),
    ".gsheet": ("json", "Google Sheets Shortcut"),
    ".gtkrc": ("ini", "GTK Theme Resource File"),
    ".gyp": ("json", "GYP Build Configuration"),
    ".haproxy": ("directive", "HAProxy Load Balancer Configuration"),
    ".headers": ("rulelist", "Static Host Header Rules"),
    ".helmignore": ("rulelist", "Helm Ignore Rules"),
    ".hgignore": ("rulelist", "Mercurial Ignore File"),
    ".hosts": ("hosts", "Hosts Name Resolution File"),
    ".htaccess": ("directive", "Apache Per-directory Configuration"),
    ".htgroup": ("directive", "Apache Group Authorization File"),
    ".htpasswd": ("htpasswd", "Apache Password File"),
    ".hxml": ("rulelist", "Haxe Build Configuration"),
    ".hyprlang": ("directive", "Hyprland Configuration File"),
    ".i3config": ("directive", "i3 Window Manager Configuration"),
    ".ica": ("ini", "Citrix Independent Computing Architecture File"),
    ".icc": ("opaque_binary", "ICC Color Profile"),
    ".icf": ("directive", "IAR Linker Configuration File"),
    ".icm": ("opaque_binary", "Image Color Matching Profile"),
    ".idf": ("idf", "EnergyPlus Input Data File"),
    ".ifo": ("opaque_binary", "DVD Information File"),
    ".imp": ("opaque_binary", "Imposition Layout File"),
    ".incar": ("properties", "VASP Input Parameters"),
    ".index.theme": ("ini", "Icon Theme Index"),
    ".inf": ("ini", "Setup Information / Driver Install File"),
    ".inp": ("abaqus", "Abaqus Input Deck"),
    ".inputrc": ("directive", "Readline Key Binding Configuration"),
    ".ioc": ("properties", "STM32CubeMX Project Configuration"),
    ".iptables": ("directive", "iptables Rules Export"),
    ".iscsi": ("directive", "iSCSI Target Configuration"),
    ".ivy": ("xml", "Apache Ivy Dependency Descriptor"),
    ".jgw": ("worldfile", "JPEG World File"),
    ".jnlp": ("xml", "Java Network Launch Protocol File"),
    ".kafka": ("properties", "Kafka Topic Configuration Reference"),
    ".kbd": ("directive", "Keyboard Layout Definition"),
    ".kconfig": ("kconfig", "Kconfig Configuration Definition"),
    ".keybindings": ("json", "Editor Key Binding Definition"),
    ".kicad_mod": ("sexpr", "KiCad Footprint Module"),
    ".kicad_sym": ("sexpr", "KiCad Symbol Library"),
    ".klc": ("klc", "Windows Keyboard Layout Source"),
    ".kmmacros": ("plist", "Keyboard Maestro Macro Library"),
    ".knsrc": ("ini", "KDE New Stuff Resource File"),
    ".kpp": ("opaque_binary", "Krita Brush Preset"),
    ".kubeconfig": ("yaml", "Kubernetes Cluster Access Config"),
    ".kustomization": ("yaml", "Kustomize Overlay Definition"),
    ".kwinrule": ("ini", "KWin Window Rule File"),
    ".langgraph": ("json", "LangGraph Application Configuration"),
    ".launch": ("xml", "Eclipse Launch Configuration"),
    ".lbr": ("xml", "Eagle Component Library"),
    ".ld": ("directive", "GNU Linker Script"),
    ".lds": ("directive", "Linker Script Definition"),
    ".lighttpd": ("directive", "Lighttpd Server Configuration"),
    ".limits": ("directive", "Resource Limits Configuration"),
    ".link": ("ini", "systemd udev Link Configuration"),
    ".list": ("rulelist", "APT Source List"),
    ".localized": ("marker", "macOS Localized Folder Marker"),
    ".logrotate": ("directive", "Log Rotation Configuration"),
    ".look": ("opaque_binary", "Color Look File"),
    ".lproj": ("marker", "macOS Language Project Folder Marker"),
    ".lrtemplate": ("kv_dsl", "Lightroom Preset Template"),
    ".lvm": ("kv_dsl", "LVM Metadata Backup"),
    ".lyr": ("opaque_binary", "ArcGIS Layer File"),
    ".lyrx": ("json", "ArcGIS Pro Layer File"),
    ".mailmap": ("rulelist", "Git Author Mapping File"),
    ".mdadm": ("directive", "mdadm RAID Configuration"),
    ".mds": ("rulelist", "Media Descriptor Sidecar"),
    ".meltano": ("yaml", "Meltano Project Configuration"),
    ".meson": ("starlark", "Meson Build Definition"),
    ".meta": ("yaml", "Unity Asset Metadata"),
    ".mkdocs": ("yaml", "MkDocs Site Configuration"),
    ".mlb": ("rulelist", "MLton Basis File"),
    ".mobileconfig": ("plist", "Apple Configuration Profile"),
    ".modbus": ("csv", "Modbus Register Map File"),
    ".modelfile": ("directive", "Ollama Model Definition"),
    ".modflow": ("namelist", "MODFLOW Groundwater Model File"),
    ".modprobe": ("directive", "Kernel Module Configuration"),
    ".mount": ("ini", "systemd Mount Unit"),
    ".msstyles": ("opaque_binary", "Windows Visual Style Theme"),
    ".myb": ("opaque_binary", "MyPaint Brush File"),
    ".nam": ("namelist", "MODFLOW Name File"),
    ".namelist": ("namelist", "Model Namelist Configuration"),
    ".nats": ("yaml", "NATS Stream Configuration"),
    ".nd": ("ini", "QuickBooks Network Data File"),
    ".netdev": ("ini", "systemd-networkd Virtual Device Config"),
    ".netlify": ("toml", "Netlify Site Configuration"),
    ".netplan": ("yaml", "Netplan Network Configuration"),
    ".network": ("ini", "systemd-networkd Network Config"),
    ".nfs": ("directive", "NFS Export Configuration"),
    ".nftables": ("directive", "nftables Ruleset File"),
    ".nimble": ("kv_dsl", "Nim Package Definition"),
    ".ninja": ("ninja", "Ninja Build File"),
    ".nojekyll": ("marker", "GitHub Pages Jekyll Bypass Marker"),
    ".nomad": ("directive", "Nomad Job Specification"),
    ".nomedia": ("marker", "Android Media Scan Exclusion Marker"),
    ".npmrc": ("ini", "npm Configuration"),
    ".nspawn": ("ini", "systemd-nspawn Container Settings"),
    ".nsswitch": ("directive", "Name Service Switch Configuration"),
    ".nvim": ("kv_dsl", "Neovim Configuration Script"),
    ".nvmrc": ("rulelist", "Node Version Manager Config"),
    ".nxs": ("properties", "NoMachine Session File"),
    ".ocd": ("directive", "OpenOCD Configuration File"),
    ".ocio": ("yaml", "OpenColorIO Configuration"),
    ".opam": ("kv_dsl", "OPAM Package Definition"),
    ".ora": ("auto", "Oracle Configuration File"),
    ".ovf": ("xml", "Open Virtualization Format Descriptor"),
    ".ovpn": ("directive", "OpenVPN Client Profile"),
    ".ozw": ("xml", "OpenZWave Network Cache"),
    ".p4ignore": ("rulelist", "Perforce Ignore File"),
    ".pal": ("opaque_binary", "Color Palette File"),
    ".pam_environment": ("properties", "PAM Environment File"),
    ".partitions": ("csv", "ESP32 Partition Table CSV"),
    ".pat": ("opaque_binary", "Photoshop/GIMP Pattern File"),
    ".path": ("ini", "systemd Path Unit"),
    ".pbids": ("json", "Power BI Data Source File"),
    ".pbxproj": ("plist", "Xcode Project Description"),
    ".pc": ("kv_dsl", "pkg-config Metadata File"),
    ".pdd": ("opaque_binary", "Printer Description Data File"),
    ".pif": ("opaque_binary", "Program Information File"),
    ".platformio": ("ini", "PlatformIO Project Configuration"),
    ".po": ("gettext", "Gettext Portable Object Translation"),
    ".pom": ("xml", "Maven Project Object Model"),
    ".ppd": ("ppd", "PostScript Printer Description"),
    ".prettierrc": ("json", "Prettier Configuration"),
    ".pro": ("rulelist", "ProGuard Rules File"),
    ".procfile": ("properties", "Process Type Declaration File"),
    ".promptfoo": ("yaml", "Promptfoo Evaluation Configuration"),
    ".pssc": ("xml", "PowerShell Session Configuration"),
    ".pulsar": ("properties", "Apache Pulsar Topic Config"),
    ".pulumi": ("yaml", "Pulumi Project File"),
    ".pvs": ("xml", "Parallels VM Configuration"),
    ".qcs": ("json", "Quantum Cloud Services Job File"),
    ".qpu": ("json", "Quantum Processor Configuration"),
    ".qsf": ("directive", "Intel Quartus Settings File"),
    ".rasi": ("directive", "Rofi Theme/Configuration File"),
    ".rclone": ("ini", "Rclone Remote Configuration"),
    ".rdp": ("properties", "Remote Desktop Connection Profile"),
    ".rdpw": ("properties", "RDP Session Wrapper Configuration"),
    ".rebar": ("kv_dsl", "Erlang Rebar Configuration"),
    ".redirects": ("rulelist", "Static Host Redirect Rules"),
    ".reg": ("reg", "Windows Registry Export"),
    ".repo": ("ini", "Package Repository Definition"),
    ".resolv": ("directive", "DNS Resolver Configuration"),
    ".robots": ("directive", "Robots Exclusion File"),
    ".rockspec": ("starlark", "LuaRocks Package Specification"),
    ".rules": ("kv_dsl", "Business Rules Definition"),
    ".s3cfg": ("ini", "S3 Client Configuration"),
    ".sample": ("auto", "Sample/Example Configuration"),
    ".sapgui": ("ini", "SAP GUI Shortcut"),
    ".savedsearch": ("plist", "Smart Folder Saved Search"),
    ".sbt": ("starlark", "SBT Build Definition"),
    ".scope": ("ini", "systemd Scope Unit"),
    ".screenrc": ("directive", "GNU Screen Configuration"),
    ".sct": ("directive", "ARM Scatter File"),
    ".sdkconfig": ("properties", "ESP-IDF SDK Configuration"),
    ".sdp": ("sdp", "Session Description Protocol File"),
    ".serverless": ("yaml", "Serverless Framework Config"),
    ".service": ("ini", "systemd Service Unit"),
    ".sfdisk": ("sfdisk", "sfdisk Partition Layout Dump"),
    ".sftp": ("ini", "SFTP Site Profile"),
    ".sfz": ("sfz", "SFZ Sampler Instrument"),
    ".shlibs": ("rulelist", "Debian Shared Library Dependencies"),
    ".shortcut": ("ini", "Application Shortcut Definition"),
    ".sigma": ("yaml", "Sigma Detection Rule"),
    ".slice": ("ini", "systemd Slice Unit"),
    ".sls": ("auto", "SaltStack State File"),
    ".smb": ("ini", "SMB Share Configuration"),
    ".snapcraft": ("yaml", "Snapcraft Build Definition"),
    ".snort": ("directive", "Snort IDS Rule File"),
    ".socket": ("ini", "systemd Socket Unit"),
    ".soda": ("yaml", "Soda Data Quality Check File"),
    ".sources": ("deb822", "Deb822 APT Sources File"),
    ".spice": ("ini", "SPICE Connection File"),
    ".ssh_config": ("directive", "SSH Client Configuration"),
    ".storm": ("yaml", "Apache Storm Topology Definition"),
    ".strings": ("strings", "Localizable Strings File"),
    ".sudoers": ("directive", "Sudo Privilege Policy File"),
    ".suo": ("opaque_binary", "Visual Studio Solution User Options"),
    ".swap": ("ini", "systemd Swap Unit"),
    ".swmm": ("ini", "EPA SWMM Stormwater Model"),
    ".symbols": ("rulelist", "Debian Library Symbols File"),
    ".sysctl": ("properties", "Kernel Parameter Configuration"),
    ".sysin": ("rulelist", "Batch Job Input Stream"),
    ".target": ("ini", "systemd Target Unit"),
    ".tds": ("xml", "Tableau Data Source"),
    ".terminal": ("plist", "Terminal Settings File"),
    ".tfw": ("worldfile", "TIFF World File"),
    ".theme": ("ini", "Windows Theme File"),
    ".thmx": ("opaque_binary", "Office Theme File"),
    ".timer": ("ini", "systemd Timer Unit"),
    ".tm": ("spice_kernel", "SPICE Meta-Kernel File"),
    ".tmlanguage": ("plist", "TextMate Language Grammar"),
    ".tmtheme": ("plist", "TextMate Color Theme"),
    ".tmux": ("directive", "tmux Configuration File"),
    ".tool": ("auto", "Tool Library Definition"),
    ".tool-versions": ("properties", "asdf Tool Version Pins"),
    ".top": ("gromacs", "GROMACS Topology File"),
    ".tpl": ("opaque_binary", "Photoshop Tool Preset"),
    ".traefik": ("yaml", "Traefik Dynamic Configuration"),
    ".triggers": ("rulelist", "Debian Package Triggers File"),
    ".ucf": ("directive", "Xilinx User Constraints File"),
    ".ufd": ("auto", "Cellebrite Extraction Descriptor"),
    ".unv": ("opaque_binary", "BusinessObjects Universe"),
    ".unx": ("opaque_binary", "BusinessObjects Universe (new)"),
    ".upf": ("directive", "Unified Power Format"),
    ".url": ("ini", "Internet Shortcut"),
    ".user": ("xml", "Per-user Project Settings"),
    ".vbox": ("xml", "VirtualBox Machine Definition"),
    ".vbr": ("opaque_binary", "GIMP Parametric Brush"),
    ".vdf": ("vdf", "Valve Data Format Config"),
    ".vhost": ("directive", "Virtual Host Configuration"),
    ".vimrc": ("vimscript", "Vim Configuration"),
    ".vllm": ("yaml", "vLLM Serving Configuration"),
    ".vmpl": ("ini", "VMware Player Preferences"),
    ".vmsd": ("ini", "VMware Snapshot Metadata"),
    ".vmx": ("ini", "VMware Virtual Machine Configuration"),
    ".vmxf": ("xml", "VMware Team Configuration"),
    ".vnc": ("properties", "VNC Connection Profile"),
    ".wallpaper": ("ini", "Desktop Wallpaper Definition"),
    ".webloc": ("plist", "macOS Web Location Shortcut"),
    ".wf": ("xml", "Workflow Definition File"),
    ".wflow": ("plist", "Shortcuts Workflow File"),
    ".wg": ("ini", "WireGuard Configuration"),
    ".winscp": ("ini", "WinSCP Session Configuration"),
    ".wireshark": ("ini", "Wireshark Profile Configuration"),
    ".woodpecker": ("yaml", "Woodpecker CI Pipeline File"),
    ".workflow": ("yaml", "GitHub Actions Workflow"),
    ".wpa_supplicant": ("directive", "Wi-Fi Supplicant Configuration"),
    ".wrangler": ("toml", "Cloudflare Workers Configuration"),
    ".wsh": ("ini", "Windows Script Host Settings"),
    ".xcconfig": ("kv_dsl", "Xcode Build Configuration"),
    ".xdc": ("directive", "Xilinx Design Constraints"),
    ".xdefaults": ("xresources", "X Application Defaults"),
    ".xkb": ("directive", "X Keyboard Extension Layout"),
    ".xlw": ("opaque_binary", "Excel Workspace"),
    ".xmodmap": ("directive", "X Keyboard Mapping File"),
    ".xresources": ("xresources", "X Resource Database"),
    ".zap": ("json", "Zigbee Cluster Configuration File"),
    ".zone": ("zone", "DNS Zone File"),
}


# ======================================================================
# Public registry helpers
# ======================================================================
def known_exts() -> frozenset:
    return frozenset(_CONFIG_REGISTRY)


def family_for(ext: str) -> Optional[str]:
    hit = _CONFIG_REGISTRY.get((ext or "").lower())
    return hit[0] if hit else None


def label_for(ext: str) -> Optional[str]:
    hit = _CONFIG_REGISTRY.get((ext or "").lower())
    return hit[1] if hit else None


def routing_suffixes() -> Tuple[str, ...]:
    return tuple(sorted(_CONFIG_REGISTRY))


# ======================================================================
# I/O + content sniffing
# ======================================================================
_MAX_BYTES = 8 * 1024 * 1024  # parse cap
_ENTROPY_CAP = 1024 * 1024


def _read_bytes(path: Path) -> Tuple[bytes, bool]:
    """Return (data, truncated). Reads at most ``_MAX_BYTES + 1``."""
    with open(path, "rb") as fh:
        data = fh.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        return data[:_MAX_BYTES], True
    return data, False


def _looks_binary(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    texty = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 0xA0)
    return (texty / len(sample)) < 0.85


def _decode(data: bytes) -> Tuple[str, str]:
    """Decode config text; return (text, encoding). BOM-aware."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16"
        try:
            return data.decode(enc), enc
        except Exception:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace"), "latin-1"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(data: bytes) -> float:
    d = data[:_ENTROPY_CAP]
    if not d:
        return 0.0
    counts = [0] * 256
    for b in d:
        counts[b] += 1
    n = len(d)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * log2(p)
    return round(ent, 4)


_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _printable_strings(data: bytes, cap: int = 64) -> int:
    return min(len(_STRING_RE.findall(data[:_ENTROPY_CAP])), 10**9) if data else 0


# ======================================================================
# analyze() -- entry point
# ======================================================================
def analyze(path: Path, ext: str) -> Dict[str, Any]:
    ext = (ext or "").lower()
    fam, label = _CONFIG_REGISTRY.get(ext, ("auto", ext.lstrip(".") or "config"))

    data, truncated = _read_bytes(path)
    byte_size = _file_size(path)
    detected_via = "extension"

    # ---- forensic (inherently binary, or a text format carrying binary) ----
    if fam == "opaque_binary" or (fam not in ("marker",) and _looks_binary(data)):
        via = "extension" if fam == "opaque_binary" else "content"
        return _forensic(path, ext, fam, label, data, byte_size, via)

    # marker files are presence-significant and typically empty -- never binary
    if fam == "marker":
        return _marker_profile(ext, label, byte_size)

    text, encoding = _decode(data)

    # empty (whitespace-only) config
    if not text.strip():
        return {
            "format": label,
            "family": fam,
            "engine": "empty",
            "detected_via": detected_via,
            "status": "empty",
            "root": None,
            "properties": [],
            "notes": "empty configuration file",
            "byte_size": byte_size,
            "encoding": encoding,
        }

    engine = fam
    if fam == "auto":
        engine, detected_via = _detect_engine(text), "content"

    parser = _ENGINES.get(engine)
    if parser is None:  # safety net -- treat as flat key/value
        parser = _e_kv
        engine = "kv_dsl"

    status = "ok"
    notes = ""
    root: Any = None
    try:
        root, pnotes = parser(text)
        if pnotes:
            notes = pnotes
            if "partial" in pnotes or "approx" in pnotes:
                status = "partial"
    except Exception as err:  # real parse failure -> honest partial, never fake
        status = "partial"
        notes = f"{engine} parse incomplete: {type(err).__name__}: {err}"
        root = _e_rulelist(text)[0]  # keep the raw lines as an honest fallback
        engine = engine + "->lines"

    if truncated:
        notes = (
            notes + "; " if notes else ""
        ) + f"payload truncated at {_MAX_BYTES} bytes for parsing"

    return {
        "format": label,
        "family": fam,
        "engine": engine,
        "detected_via": detected_via,
        "status": status,
        "root": root,
        "properties": [
            ("file", "syntax_family", fam),
            ("file", "parse_engine", engine),
        ],
        "notes": notes,
        "byte_size": byte_size,
        "encoding": encoding,
    }


def _forensic(
    path: Path,
    ext: str,
    fam: str,
    label: str,
    data: bytes,
    byte_size: Optional[int],
    via: str,
) -> Dict[str, Any]:
    note = (
        "inherently binary format; forensic byte profile only"
        if fam == "opaque_binary"
        else "declared a text config but the payload is binary; "
        "forensic byte profile only"
    )
    return {
        "format": label,
        "family": fam,
        "engine": "forensic",
        "detected_via": "binary_sniff" if via == "content" else "extension",
        "status": "forensic",
        "root": None,
        "properties": [
            ("forensic", "byte_size", byte_size),
            ("forensic", "sha256", _sha256(path)),
            ("forensic", "shannon_entropy", _entropy(data)),
            ("forensic", "printable_string_count", _printable_strings(data)),
        ],
        "notes": note,
        "byte_size": byte_size,
        "encoding": "binary",
    }


def _marker_profile(ext: str, label: str, byte_size: Optional[int]) -> Dict[str, Any]:
    return {
        "format": label,
        "family": "marker",
        "engine": "marker",
        "detected_via": "extension",
        "status": "ok",
        "root": {},
        "properties": [("file", "marker", True), ("file", "byte_size", byte_size)],
        "notes": "presence-significant marker file (typically empty)",
        "byte_size": byte_size,
        "encoding": "n/a",
    }


def _file_size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _detect_engine(text: str) -> str:
    """Content sniff for 'auto' extensions."""
    s = text.lstrip()
    head = s[:1]
    if head in "{[":
        try:
            json.loads(_json_strip(s))
            return "json"
        except Exception:
            pass
    if s[:5].lower() == "<?xml" or head == "<":
        return "xml"
    if s.startswith("---") or re.match(r"^[^\n:]{1,80}:\s", s):
        return "yaml"
    if re.search(r"^\s*\[[^\]\n]+\]\s*$", text, re.M):
        return "ini"
    if re.search(r"^\s*[\w.\-]+\s*=", text, re.M):
        return "properties"
    return "kv_dsl"


# ======================================================================
# Scalar coercion (shared by several text parsers)
# ======================================================================
_BOOL_TRUE = {"true", "yes", "on"}
_BOOL_FALSE = {"false", "no", "off"}
_INT_RE = re.compile(r"^[+-]?\d+$")
_HEX_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F]+$")
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")


def _coerce_scalar(v: str) -> Any:
    s = v.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    low = s.lower()
    if low in ("null", "none", "nil", "~"):
        return None
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    if _HEX_RE.match(s):
        try:
            return int(s, 16)
        except ValueError:
            return s
    if _INT_RE.match(s):
        try:
            return int(s)
        except ValueError:
            return s
    if _FLOAT_RE.match(s) and any(c in s for c in ".eE"):
        try:
            return float(s)
        except ValueError:
            return s
    return s


# ======================================================================
# JSON (tolerant: strips // and /* */ comments and trailing commas)
# ======================================================================
def _json_strip(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in "\"'":
            in_str = True
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    # drop trailing commas before } or ]
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    return s


def _e_json(text: str) -> Tuple[Any, str]:
    try:
        return json.loads(text), ""
    except Exception:
        return (
            json.loads(_json_strip(text)),
            "tolerant JSON (comments/trailing commas stripped)",
        )


# ======================================================================
# TOML
# ======================================================================
def _e_toml(text: str) -> Tuple[Any, str]:
    if _tomllib is not None:
        return _tomllib.loads(text), ""
    return _e_ini(text)[0], "tomllib unavailable; parsed with INI reader (approx)"


# ======================================================================
# INI / systemd-unit / desktop-entry
# ======================================================================
def _e_ini(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    current = root
    cur_name = None
    approx = False
    cont_key = None
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            cont_key = None
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            cur_name = stripped[1:-1].strip()
            current = root.setdefault(cur_name, {})
            if not isinstance(current, dict):
                current = root[cur_name] = {"_value": current}
            cont_key = None
            continue
        # line continuation (value ended with backslash)
        if cont_key is not None and (line[:1] in " \t"):
            prev = current.get(cont_key)
            current[cont_key] = (str(prev) + "\n" + stripped) if prev else stripped
            continue
        m = re.match(r"^([^=:]+?)\s*[:=]\s*(.*)$", stripped)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            trailing_bs = val.endswith("\\")
            if trailing_bs:
                val = val[:-1].rstrip()
            coerced = _coerce_scalar(val)
            if key in current:  # duplicate key -> promote to list
                existing = current[key]
                if isinstance(existing, list):
                    existing.append(coerced)
                else:
                    current[key] = [existing, coerced]
            else:
                current[key] = coerced
            cont_key = key if trailing_bs else None
        else:
            # bare token line (flags) -> record as key with empty value
            current[stripped] = current.get(stripped, "")
            approx = True
            cont_key = None
    return root, ("bare-token lines recorded as empty-valued keys" if approx else "")


# ======================================================================
# Java-properties / sysctl / env-style key=value
# ======================================================================
def _e_properties(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        s = line.strip()
        if not s or s[0] in "#!;":
            continue
        # "# CONFIG_X is not set" already skipped as comment
        while s.endswith("\\") and i < len(lines):
            s = s[:-1] + lines[i].strip()
            i += 1
        m = re.match(r"^([^=:\s]+)\s*[:=]\s*(.*)$", s)
        if not m:
            m = re.match(r"^(\S+)\s+(.*)$", s)
        if m:
            root[m.group(1)] = _coerce_scalar(m.group(2))
        else:
            root[s] = ""
    return root, ""


# ======================================================================
# kconfig  (CONFIG_X=y  /  # CONFIG_X is not set)
# ======================================================================
def _e_kconfig(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"^#\s*(CONFIG_\w+)\s+is not set$", s)
        if m:
            root[m.group(1)] = False
            continue
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(\w+)\s*=\s*(.*)$", s)
        if m:
            root[m.group(1)] = _coerce_scalar(m.group(2))
    return root, ""


# ======================================================================
# Generic key/value DSL  (dhall / nix / pkg-config / xcconfig / cabal / opam)
# ======================================================================
def _e_kv(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    hit = False
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", "//", "--", ";")):
            continue
        m = re.match(r"^([\w.\-/$]+)\s*[:=]\s*(.+?)\s*[,;]?\s*$", s)
        if m:
            root[m.group(1)] = _coerce_scalar(m.group(2))
            hit = True
    note = "" if hit else "no top-level assignments found (approx extraction)"
    return root, (
        "extracted top-level assignments only (approx for nested DSL)" if hit else note
    )


# ======================================================================
# xresources / xdefaults   (App*resource: value  with '!' comments)
# ======================================================================
def _e_xresources(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("!"):
            continue
        m = re.match(r"^([^:]+):\s*(.*)$", s)
        if m:
            root[m.group(1).strip()] = _coerce_scalar(m.group(2))
    return root, ""


# ======================================================================
# PostScript Printer Description (.ppd)   (*Keyword optionKeyword: value)
# ======================================================================
def _e_ppd(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.startswith("*") or s.startswith("*%"):
            continue
        m = re.match(r"^\*([\w./\- ]+?)\s*:\s*(.*)$", s)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip().strip('"')
            if key in root:
                ex = root[key]
                if isinstance(ex, list):
                    ex.append(val)
                else:
                    root[key] = [ex, val]
            else:
                root[key] = _coerce_scalar(val)
    return root, ""


# ======================================================================
# Session Description Protocol (.sdp)   (single-letter typed lines)
# ======================================================================
_SDP_NAMES = {
    "v": "version",
    "o": "origin",
    "s": "session_name",
    "i": "info",
    "u": "uri",
    "e": "email",
    "p": "phone",
    "c": "connection",
    "b": "bandwidth",
    "t": "timing",
    "r": "repeat",
    "z": "timezone",
    "k": "encryption_key",
    "a": "attribute",
    "m": "media",
}


def _e_sdp(text: str) -> Tuple[Any, str]:
    records: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s or "=" not in s or len(s) < 2 or s[1] != "=":
            continue
        t = s[0]
        records.append({"type": t, "field": _SDP_NAMES.get(t, t), "value": s[2:]})
    return {"lines": records}, ""


# ======================================================================
# SFZ sampler   (<header> sections + opcode=value)
# ======================================================================
def _e_sfz(text: str) -> Tuple[Any, str]:
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    sections: List[Dict[str, Any]] = []
    current = {"header": "(global)", "opcodes": {}}
    tokens = re.findall(r"<(\w+)>|([\w]+)=(\S+)", text)
    for hdr, op, val in tokens:
        if hdr:
            if current["opcodes"] or current["header"] != "(global)":
                sections.append(current)
            current = {"header": hdr, "opcodes": {}}
        elif op:
            current["opcodes"][op] = _coerce_scalar(val)
    sections.append(current)
    return {"sections": sections}, ""


# ======================================================================
# Ninja build   (var = value ; rule NAME ; build OUT: RULE INS)
# ======================================================================
def _e_ninja(text: str) -> Tuple[Any, str]:
    variables: Dict[str, Any] = {}
    rules: List[Dict[str, Any]] = []
    builds: List[Dict[str, Any]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        i += 1
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^rule\s+(\S+)", s)
        if m:
            rule = {"name": m.group(1), "vars": {}}
            while i < len(lines) and lines[i][:1] in " \t" and lines[i].strip():
                mv = re.match(r"^\s+(\w+)\s*=\s*(.*)$", lines[i])
                if mv:
                    rule["vars"][mv.group(1)] = mv.group(2).strip()
                i += 1
            rules.append(rule)
            continue
        m = re.match(r"^build\s+(.+?):\s*(\S+)\s*(.*)$", s)
        if m:
            builds.append(
                {
                    "outputs": m.group(1).strip(),
                    "rule": m.group(2),
                    "inputs": m.group(3).strip(),
                }
            )
            continue
        m = re.match(r"^(\w+)\s*=\s*(.*)$", s)
        if m:
            variables[m.group(1)] = _coerce_scalar(m.group(2))
    return {"variables": variables, "rules": rules, "builds": builds}, ""


# ======================================================================
# Ruby-DSL Brewfile   (brew "x" ; cask "y" ; tap "z")
# ======================================================================
def _e_ruby_dsl(text: str) -> Tuple[Any, str]:
    items: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(\w+)\s+[\"']([^\"']+)[\"'](?:\s*,\s*(.*))?$", s)
        if m:
            item = {"method": m.group(1), "name": m.group(2)}
            if m.group(3):
                item["args"] = m.group(3).strip()
            items.append(item)
    return {"entries": items}, "" if items else "no recognizable DSL entries"


# ======================================================================
# Vimscript (.vimrc)   (set opt=val ; let g:x = y)
# ======================================================================
def _e_vimscript(text: str) -> Tuple[Any, str]:
    settings: Dict[str, Any] = {}
    lets: Dict[str, Any] = {}
    other: List[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith('"'):
            continue
        m = re.match(r"^set(?:l|local)?\s+(\w+)=(.*)$", s)
        if m:
            settings[m.group(1)] = _coerce_scalar(m.group(2))
            continue
        m = re.match(r"^set(?:l|local)?\s+(no)?(\w+)!?\s*$", s)
        if m:
            settings[m.group(2)] = m.group(1) != "no"
            continue
        m = re.match(r"^let\s+([\w:.\[\]']+)\s*=\s*(.*)$", s)
        if m:
            lets[m.group(1)] = _coerce_scalar(m.group(2))
            continue
        other.append(s.split()[0] if s.split() else s)
    root: Dict[str, Any] = {}
    if settings:
        root["set"] = settings
    if lets:
        root["let"] = lets
    if other:
        root["commands"] = sorted(set(other))
    return root, "extracted set/let assignments (commands summarized)"


# ======================================================================
# YAML subset (indentation block mappings/sequences + flow + scalars)
# ======================================================================
def _e_yaml(text: str) -> Tuple[Any, str]:
    docs = _yaml_documents(text)
    if not docs:
        return None, ""
    if len(docs) == 1:
        return docs[0], "YAML-subset parser"
    return {"documents": docs}, "YAML-subset parser (multi-document)"


def _yaml_documents(text: str) -> List[Any]:
    raw_lines = text.splitlines()
    # split logical lines, dropping comments and blanks; keep indentation
    docs: List[List[Tuple[int, str]]] = [[]]
    for raw in raw_lines:
        stripped = _yaml_strip_comment(raw)
        if stripped.strip() in ("---", ""):
            if stripped.strip() == "---":
                if docs[-1]:
                    docs.append([])
            continue
        if stripped.strip() == "...":
            docs.append([])
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        docs[-1].append((indent, stripped.strip()))
    out = []
    for d in docs:
        if not d:
            continue
        val, _ = _yaml_block(d, 0, 0)
        out.append(val)
    return out


def _yaml_strip_comment(line: str) -> str:
    out = []
    in_str = False
    quote = ""
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if c == quote:
                in_str = False
        elif c in "\"'":
            in_str = True
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _yaml_block(lines: List[Tuple[int, str]], idx: int, indent: int):
    """Parse a block at >= given indent starting at lines[idx]. Returns (value, next_idx)."""
    if idx >= len(lines):
        return None, idx
    cur_indent = lines[idx][0]
    if lines[idx][1].startswith("- "):
        return _yaml_seq(lines, idx, cur_indent)
    if lines[idx][1] == "-":
        return _yaml_seq(lines, idx, cur_indent)
    return _yaml_map(lines, idx, cur_indent)


def _yaml_seq(lines, idx, indent):
    seq = []
    while idx < len(lines):
        ind, content = lines[idx]
        if ind < indent or not (content == "-" or content.startswith("- ")):
            break
        item = content[1:].strip()
        if item == "":
            # nested block on following lines
            val, idx = _yaml_block(lines, idx + 1, indent + 1)
            seq.append(val)
        elif ":" in item and not _yaml_is_flow(item):
            # inline map entry starting the sequence item
            synthetic = [(ind + 2, item)]
            j = idx + 1
            while j < len(lines) and lines[j][0] > ind:
                synthetic.append((lines[j][0], lines[j][1]))
                j += 1
            val, _ = _yaml_map(synthetic, 0, ind + 2)
            seq.append(val)
            idx = j
        else:
            seq.append(_yaml_scalar(item))
            idx += 1
    return seq, idx


def _yaml_map(lines, idx, indent):
    mapping: Dict[str, Any] = {}
    while idx < len(lines):
        ind, content = lines[idx]
        if ind < indent or content == "-" or content.startswith("- "):
            break
        if ind > indent:  # unexpected deeper line; skip defensively
            idx += 1
            continue
        m = re.match(r"^(.+?):(?:\s+(.*))?$", content)
        if not m:
            idx += 1
            continue
        key = _yaml_key(m.group(1))
        rest = (m.group(2) or "").strip()
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            block, idx = _yaml_block_scalar(lines, idx + 1, indent)
            mapping[key] = block
        elif rest == "":
            # nested block or empty
            if idx + 1 < len(lines) and lines[idx + 1][0] > indent:
                val, idx = _yaml_block(lines, idx + 1, indent + 1)
                mapping[key] = val
            else:
                mapping[key] = None
                idx += 1
        else:
            mapping[key] = _yaml_scalar(rest)
            idx += 1
    return mapping, idx


def _yaml_block_scalar(lines, idx, indent):
    collected = []
    while idx < len(lines) and lines[idx][0] > indent:
        collected.append(lines[idx][1])
        idx += 1
    return "\n".join(collected), idx


def _yaml_key(k: str) -> str:
    k = k.strip()
    if len(k) >= 2 and k[0] in "\"'" and k[-1] == k[0]:
        return k[1:-1]
    return k


def _yaml_is_flow(s: str) -> bool:
    s = s.strip()
    return s[:1] in "[{"


def _yaml_scalar(s: str) -> Any:
    s = s.strip()
    if not s:
        return None
    if s[0] == "[" and s[-1] == "]":
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_yaml_scalar(x) for x in _split_flow(inner)]
    if s[0] == "{" and s[-1] == "}":
        inner = s[1:-1].strip()
        d: Dict[str, Any] = {}
        if inner:
            for part in _split_flow(inner):
                if ":" in part:
                    k, v = part.split(":", 1)
                    d[_yaml_key(k)] = _yaml_scalar(v)
        return d
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    return _coerce_scalar(s)


def _split_flow(inner: str) -> List[str]:
    parts, depth, buf = [], 0, []
    in_str = False
    quote = ""
    for c in inner:
        if in_str:
            buf.append(c)
            if c == quote:
                in_str = False
            continue
        if c in "\"'":
            in_str = True
            quote = c
            buf.append(c)
            continue
        if c in "[{":
            depth += 1
            buf.append(c)
        elif c in "]}":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


# ======================================================================
# XML  (etree -> canonical nested dict)
# ======================================================================
def _e_xml(text: str) -> Tuple[Any, str]:
    root = _ET.fromstring(text)
    return {_local_tag(root.tag): _xml_to_obj(root)}, ""


def _local_tag(tag: str) -> str:
    if isinstance(tag, str) and tag.startswith("{"):
        return tag.split("}", 1)[1]
    return str(tag)


def _xml_to_obj(el) -> Any:
    obj: Dict[str, Any] = {}
    for k, v in el.attrib.items():
        obj["@" + _local_tag(k)] = _coerce_scalar(v)
    children = list(el)
    for child in children:
        tag = _local_tag(child.tag)
        cval = _xml_to_obj(child)
        if tag in obj:
            if isinstance(obj[tag], list):
                obj[tag].append(cval)
            else:
                obj[tag] = [obj[tag], cval]
        else:
            obj[tag] = cval
    text = (el.text or "").strip()
    if text:
        if obj:
            obj["#text"] = _coerce_scalar(text)
        else:
            return _coerce_scalar(text)
    return obj if obj else None


# ======================================================================
# plist  (xml + binary, via plistlib)
# ======================================================================
def _e_plist(text: str) -> Tuple[Any, str]:
    return plistlib.loads(text.encode("utf-8", "replace")), ""


def _plist_bytes(data: bytes) -> Tuple[Any, str]:
    return plistlib.loads(data), "binary plist"


# ======================================================================
# Block-directive parser (nginx / apache / caddy / hcl / haproxy / linker)
# ======================================================================
def _e_directive(text: str) -> Tuple[Any, str]:
    tokens = _directive_tokenize(text)
    pos = [0]
    root, note = _directive_block(tokens, pos, top=True)
    return root, note


_DIR_TOKEN = re.compile(r"""(\{|\}|;|<[^>]*>|"[^"]*"|'[^']*'|[^\s;{}]+)""")


def _directive_tokenize(text: str) -> List[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "//")):
            continue
        # apache-style closing tag </Foo>
        for tok in _DIR_TOKEN.findall(line):
            out.append(tok)
        out.append("\n")  # soft line terminator (Apache/hosts-style directives)
    return out


def _directive_block(tokens, pos, top=False):
    block: Dict[str, Any] = {}
    approx = False
    args: List[str] = []
    while pos[0] < len(tokens):
        tok = tokens[pos[0]]
        if tok == "\n":  # soft line terminator: flush a pending line-directive
            pos[0] += 1
            if args:
                _dir_flush(block, args)
                args = []
            continue
        if tok == "}":
            pos[0] += 1
            break
        if tok.startswith("</"):  # apache close tag
            pos[0] += 1
            if not top:
                break
            continue
        if tok.startswith("<") and not tok.startswith("</"):  # apache open tag
            inner = tok[1:-1].strip().split(None, 1)
            name = inner[0]
            label = inner[1] if len(inner) > 1 else ""
            pos[0] += 1
            sub, _ = _directive_block(tokens, pos, top=False)
            key = f"{name} {label}".strip()
            _dir_assign(block, key, sub)
            continue
        if tok == "{":
            pos[0] += 1
            sub, _ = _directive_block(tokens, pos, top=False)
            key = " ".join(args) if args else "(block)"
            _dir_assign(block, key, sub)
            args = []
            continue
        if tok == ";":
            pos[0] += 1
            if args:
                _dir_flush(block, args)
                args = []
            continue
        args.append(_unquote(tok))
        pos[0] += 1
    # flush a trailing directive that had no terminating ';'
    if args:
        _dir_flush(block, args)
    return block, ("brace/line-directive parser" if not approx else "approx")


def _dir_flush(block: Dict[str, Any], args: List[str]) -> None:
    key = args[0]
    rest = args[1:]
    if rest and rest[0] == "=":  # HCL/Nomad style: key = value
        rest = rest[1:]
    val = " ".join(rest) if rest else ""
    _dir_assign(block, key, _coerce_scalar(val) if val else "")


def _dir_assign(block: Dict[str, Any], key: str, val: Any) -> None:
    if key in block:
        ex = block[key]
        if isinstance(ex, list):
            ex.append(val)
        else:
            block[key] = [ex, val]
    else:
        block[key] = val


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
        return tok[1:-1]
    return tok


# ======================================================================
# rulelist  (gitignore / codeowners / mailmap / apt list ...)
# ======================================================================
def _e_rulelist(text: str) -> Tuple[Any, str]:
    rules = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        rules.append(s)
    return {"rules": rules}, ""


# ======================================================================
# Dockerfile  (instruction parser)
# ======================================================================
_DOCKER_INSTR = re.compile(r"^(\w+)\s+(.*)$")


def _e_dockerfile(text: str) -> Tuple[Any, str]:
    instructions: List[Dict[str, Any]] = []
    directives: Dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    seen_instr = False
    while i < len(lines):
        line = lines[i]
        i += 1
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            if not seen_instr:
                m = re.match(r"^#\s*([\w.\-]+)\s*=\s*(.+)$", s)
                if m:
                    directives[m.group(1)] = m.group(2).strip()
            continue
        # join line continuations
        while s.endswith("\\") and i < len(lines):
            s = s[:-1].rstrip() + " " + lines[i].strip()
            i += 1
        m = _DOCKER_INSTR.match(s)
        if m:
            seen_instr = True
            instructions.append(
                {"instruction": m.group(1).upper(), "arguments": m.group(2).strip()}
            )
    root: Dict[str, Any] = {}
    if directives:
        root["parser_directives"] = directives
    root["instructions"] = instructions
    return root, ""


# ======================================================================
# starlark (bazel/buck/gn/meson/sbt/rockspec) -- assignments + call targets
# ======================================================================
def _e_starlark(text: str) -> Tuple[Any, str]:
    assignments: Dict[str, Any] = {}
    targets: List[Dict[str, Any]] = []
    loads: List[str] = []
    # top-level simple assignments  name = "value"/number/[..]
    for m in re.finditer(r"^([A-Za-z_]\w*)\s*=\s*(.+)$", text, re.M):
        val = m.group(2).strip()
        if val and val[0] not in "([{":
            assignments[m.group(1)] = _coerce_scalar(val.rstrip(","))
    # rule/function calls with a name = "..." kwarg
    for m in re.finditer(r"([A-Za-z_][\w.]*)\s*\(", text):
        fname = m.group(1)
        seg = text[m.end() : m.end() + 600]
        nm = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", seg)
        if fname == "load":
            lm = re.search(r"[\"']([^\"']+)[\"']", seg)
            if lm:
                loads.append(lm.group(1))
        elif nm:
            targets.append({"rule": fname, "name": nm.group(1)})
    root: Dict[str, Any] = {}
    if loads:
        root["loads"] = loads
    if assignments:
        root["variables"] = assignments
    if targets:
        root["targets"] = targets
    return root, "extracted assignments + named targets (Starlark, approx)"


# ======================================================================
# deb822  (RFC822 paragraphs)
# ======================================================================
def _e_deb822(text: str) -> Tuple[Any, str]:
    paragraphs: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    last_key = None
    for raw in text.splitlines():
        if not raw.strip():
            if cur:
                paragraphs.append(cur)
                cur = {}
                last_key = None
            continue
        if raw[0] in " \t" and last_key is not None:
            cur[last_key] = str(cur[last_key]) + "\n" + raw.strip()
            continue
        if raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^([!-9;-~]+)\s*:\s*(.*)$", raw)
        if m:
            last_key = m.group(1)
            cur[last_key] = m.group(2).strip()
    if cur:
        paragraphs.append(cur)
    if len(paragraphs) == 1:
        return paragraphs[0], "deb822"
    return {"paragraphs": paragraphs}, "deb822 (multiple stanzas)"


# ======================================================================
# Windows registry export (.reg)
# ======================================================================
def _e_reg(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    header = None
    cur = None
    lines = text.splitlines()
    i = 0
    if lines and lines[0].startswith("Windows Registry Editor"):
        header = lines[0].strip()
        i = 1
    while i < len(lines):
        line = lines[i]
        i += 1
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            key = s[1:-1]
            cur = root.setdefault(key, {})
            continue
        if cur is None:
            continue
        # join continued hex lines
        while s.endswith("\\") and i < len(lines):
            s = s[:-1] + lines[i].strip()
            i += 1
        m = re.match(r'^(@|"(?:[^"\\]|\\.)*")\s*=\s*(.*)$', s)
        if m:
            name = "@" if m.group(1) == "@" else _unescape_reg(m.group(1)[1:-1])
            cur[name] = _parse_reg_value(m.group(2).strip())
    out: Dict[str, Any] = {}
    if header:
        out["_format"] = header
    out.update(root)
    return out, "windows registry export"


def _unescape_reg(s: str) -> str:
    return s.replace("\\\\", "\\").replace('\\"', '"')


def _parse_reg_value(v: str) -> Any:
    if v.startswith('"') and v.endswith('"'):
        return _unescape_reg(v[1:-1])
    if v.startswith("dword:"):
        try:
            return int(v[6:], 16)
        except ValueError:
            return v
    if v.startswith("hex(b):") or v.startswith("qword:"):
        return {"type": "qword/binary", "raw": v.split(":", 1)[1][:256]}
    if v.startswith("hex"):
        m = re.match(r"hex(?:\(([0-9a-fA-F]+)\))?:(.*)$", v)
        if m:
            return {
                "type": f"REG_BINARY(type={m.group(1) or '3'})",
                "bytes": m.group(2).count(",") + (1 if m.group(2).strip() else 0),
            }
    return _coerce_scalar(v)


# ======================================================================
# crontab / anacrontab
# ======================================================================
def _e_crontab(text: str) -> Tuple[Any, str]:
    env: Dict[str, str] = {}
    jobs: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("@"):
            parts = s.split(None, 1)
            jobs.append(
                {"schedule": parts[0], "command": parts[1] if len(parts) > 1 else ""}
            )
            continue
        m = re.match(r"^(\S+)\s*=\s*(.*)$", s)
        if m and not re.match(r"^[\d*]", s):
            env[m.group(1)] = m.group(2).strip()
            continue
        fields = s.split(None, 5)
        if len(fields) >= 6:
            jobs.append(
                {
                    "minute": fields[0],
                    "hour": fields[1],
                    "dom": fields[2],
                    "month": fields[3],
                    "dow": fields[4],
                    "command": fields[5],
                }
            )
        elif len(fields) >= 4 and re.match(r"^\d", s):  # anacron: period delay job cmd
            jobs.append(
                {
                    "period": fields[0],
                    "delay": fields[1],
                    "job_identifier": fields[2],
                    "command": " ".join(fields[3:]),
                }
            )
    root: Dict[str, Any] = {}
    if env:
        root["environment"] = env
    root["jobs"] = jobs
    return root, ""


# ======================================================================
# fstab
# ======================================================================
def _e_fstab(text: str) -> Tuple[Any, str]:
    entries: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split()
        if len(f) >= 4:
            entries.append(
                {
                    "device": f[0],
                    "mount_point": f[1],
                    "fs_type": f[2],
                    "options": f[3],
                    "dump": _coerce_scalar(f[4]) if len(f) > 4 else 0,
                    "pass": _coerce_scalar(f[5]) if len(f) > 5 else 0,
                }
            )
    return {"entries": entries}, ""


# ======================================================================
# hosts
# ======================================================================
def _e_hosts(text: str) -> Tuple[Any, str]:
    entries: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.split("#", 1)[0].strip()
        if not s:
            continue
        f = s.split()
        if len(f) >= 2:
            entries.append({"address": f[0], "hostnames": f[1:]})
    return {"entries": entries}, ""


# ======================================================================
# htpasswd  (username -> algorithm; digest redacted -- credential material)
# ======================================================================
def _e_htpasswd(text: str) -> Tuple[Any, str]:
    users: Dict[str, Any] = {}
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        user, digest = s.split(":", 1)
        if digest.startswith("$apr1$"):
            algo = "md5-apr1"
        elif digest.startswith(("$2y$", "$2a$", "$2b$")):
            algo = "bcrypt"
        elif digest.startswith("{SHA}"):
            algo = "sha1"
        elif digest.startswith("$5$"):
            algo = "sha256-crypt"
        elif digest.startswith("$6$"):
            algo = "sha512-crypt"
        else:
            algo = "crypt/plain"
        users[user] = {
            "algorithm": algo,
            "digest_length": len(digest),
            "digest": "<redacted>",
        }
    return {"users": users}, "password digests redacted (credential material)"


# ======================================================================
# worldfile (.tfw/.jgw)  -- 6 affine-transform numbers
# ======================================================================
def _e_worldfile(text: str) -> Tuple[Any, str]:
    nums = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        try:
            nums.append(float(s))
        except ValueError:
            nums.append(s)
    keys = [
        "pixel_x_size",
        "rotation_row",
        "rotation_col",
        "pixel_y_size",
        "upper_left_x",
        "upper_left_y",
    ]
    root = {keys[i]: nums[i] for i in range(min(len(keys), len(nums)))}
    if len(nums) > 6:
        root["_extra"] = nums[6:]
    return root, "affine world-file transform"


# ======================================================================
# CSV  (adtxt / modbus / partitions)
# ======================================================================
def _e_csv(text: str) -> Tuple[Any, str]:
    # strip comment lines beginning with '#'
    lines = [
        ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not lines:
        return {"rows": []}, ""
    sample = "\n".join(lines[:50])
    try:
        dialect = _csvmod.Sniffer().sniff(sample, delimiters=",;\t|")
        delim = dialect.delimiter
    except Exception:
        delim = ","
    reader = list(_csvmod.reader(io.StringIO("\n".join(lines)), delimiter=delim))
    if not reader:
        return {"rows": []}, ""
    header = reader[0]
    looks_header = all(not _INT_RE.match(c.strip()) for c in header if c.strip())
    rows = reader[1:] if looks_header else reader
    cap = 1000
    if looks_header:
        out = [dict(zip(header, r)) for r in rows[:cap]]
        return {"columns": header, "rows": out, "row_count": len(rows)}, ""
    return {
        "rows": [list(r) for r in rows[:cap]],
        "row_count": len(rows),
    }, "headerless CSV"


# ======================================================================
# Fortran namelist  (&group var=val, ... /)   |  MODFLOW columnar name file
# ======================================================================
def _e_namelist(text: str) -> Tuple[Any, str]:
    if "&" in text:
        groups: Dict[str, Any] = {}
        for m in re.finditer(r"&(\w+)(.*?)(?:/|\$end|&end)", text, re.S | re.I):
            name = m.group(1)
            body = m.group(2)
            d: Dict[str, Any] = {}
            for am in re.finditer(
                r"(\w+)\s*=\s*([^=]*?)(?=,?\s*\w+\s*=|\s*$)", body, re.S
            ):
                val = am.group(2).strip().rstrip(",").strip()
                vals = [x for x in re.split(r"[,\s]+", val) if x]
                d[am.group(1)] = (
                    _coerce_scalar(vals[0])
                    if len(vals) == 1
                    else [_coerce_scalar(x) for x in vals]
                )
            groups[name] = d
        return {"groups": groups}, "fortran namelist"
    # MODFLOW name file: "FTYPE UNIT FNAME"
    records = []
    for raw in text.splitlines():
        s = raw.split("#", 1)[0].strip()
        if not s or s.startswith("!"):
            continue
        f = s.split()
        if len(f) >= 3:
            records.append(
                {"ftype": f[0], "unit": _coerce_scalar(f[1]), "fname": " ".join(f[2:])}
            )
    return {"packages": records}, "MODFLOW name-file (columnar)"


# ======================================================================
# GIMP palette (.gpl)
# ======================================================================
def _e_gimp_palette(text: str) -> Tuple[Any, str]:
    lines = text.splitlines()
    if not lines or "GIMP Palette" not in lines[0]:
        return _e_rulelist(text)[0], "not a GIMP palette header (approx)"
    meta: Dict[str, Any] = {}
    colors: List[Dict[str, Any]] = []
    for raw in lines[1:]:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^(Name|Columns):\s*(.*)$", s)
        if m:
            meta[m.group(1).lower()] = _coerce_scalar(m.group(2))
            continue
        cm = re.match(r"^(\d+)\s+(\d+)\s+(\d+)(?:\s+(.*))?$", s)
        if cm:
            colors.append(
                {
                    "r": int(cm.group(1)),
                    "g": int(cm.group(2)),
                    "b": int(cm.group(3)),
                    "name": (cm.group(4) or "").strip() or None,
                }
            )
    return {"metadata": meta, "colors": colors, "color_count": len(colors)}, ""


# ======================================================================
# Apple .strings  (binary plist, or "key" = "value";)
# ======================================================================
def _e_strings(text: str) -> Tuple[Any, str]:
    root: Dict[str, Any] = {}
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', text):
        root[_unescape_c(m.group(1))] = _unescape_c(m.group(2))
    if root:
        return root, ""
    # maybe old-style plist dict
    return plistlib.loads(text.encode("utf-8", "replace")), "plist-format strings"


def _unescape_c(s: str) -> str:
    return (
        s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


# ======================================================================
# DNS zone file
# ======================================================================
def _e_zone(text: str) -> Tuple[Any, str]:
    directives: Dict[str, Any] = {}
    records: List[Dict[str, Any]] = []
    last_name = "@"
    for raw in text.splitlines():
        s = raw.split(";", 1)[0].rstrip()
        if not s.strip():
            continue
        if s.startswith("$"):
            parts = s.split(None, 1)
            directives[parts[0].lstrip("$")] = (
                parts[1].strip() if len(parts) > 1 else ""
            )
            continue
        f = s.split()
        if raw[0] in " \t":  # inherits previous owner name
            f = [last_name] + f
        # locate class/type
        idx = 0
        name = f[0]
        last_name = name
        rest = f[1:]
        ttl = None
        if rest and _INT_RE.match(rest[0]):
            ttl = int(rest[0])
            rest = rest[1:]
        rclass = None
        if rest and rest[0].upper() in ("IN", "CH", "HS"):
            rclass = rest[0].upper()
            rest = rest[1:]
        rtype = rest[0] if rest else None
        rdata = " ".join(rest[1:]) if len(rest) > 1 else ""
        records.append(
            {"name": name, "ttl": ttl, "class": rclass, "type": rtype, "rdata": rdata}
        )
    return {"directives": directives, "records": records}, "DNS zone"


# ======================================================================
# Valve KeyValues (.vdf / steam .acf)
# ======================================================================
def _e_vdf(text: str) -> Tuple[Any, str]:
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|\{|\}', text)
    pos = [0]

    def parse_block() -> Dict[str, Any]:
        block: Dict[str, Any] = {}
        while pos[0] < len(tokens):
            tok = tokens[pos[0]]
            if tok == "}":
                pos[0] += 1
                break
            key = _vdf_unquote(tok)
            pos[0] += 1
            if pos[0] >= len(tokens):
                block[key] = ""
                break
            nxt = tokens[pos[0]]
            if nxt == "{":
                pos[0] += 1
                block[key] = parse_block()
            else:
                block[key] = _coerce_scalar(_vdf_unquote(nxt))
                pos[0] += 1
        return block

    # top level: pairs, possibly with a single root key
    root = parse_block()
    return root, "valve keyvalues"


def _vdf_unquote(tok: str) -> str:
    if tok.startswith('"') and tok.endswith('"'):
        return _unescape_c(tok[1:-1])
    return tok


# ======================================================================
# s-expression reader (KiCad .kicad_mod/.kicad_sym)
# ======================================================================
def _e_sexpr(text: str) -> Tuple[Any, str]:
    tokens = re.findall(r'\(|\)|"(?:[^"\\]|\\.)*"|[^\s()]+', text)
    pos = [0]

    def parse():
        result = []
        while pos[0] < len(tokens):
            tok = tokens[pos[0]]
            pos[0] += 1
            if tok == "(":
                result.append(parse())
            elif tok == ")":
                return result
            elif tok.startswith('"'):
                result.append(_unescape_c(tok[1:-1]))
            else:
                result.append(_coerce_scalar(tok))
        return result

    top = parse()
    root = top[0] if len(top) == 1 else top
    return _sexpr_to_obj(root), "s-expression"


def _sexpr_to_obj(node: Any) -> Any:
    """(tag a b (c d)...) -> {'_tag': tag, 'args':[...], <child-tag>:...}."""
    if not isinstance(node, list):
        return node
    if not node:
        return []
    head = node[0]
    if isinstance(head, str):
        obj: Dict[str, Any] = {"_tag": head}
        args = []
        for child in node[1:]:
            if isinstance(child, list) and child and isinstance(child[0], str):
                tag = child[0]
                cval = _sexpr_to_obj(child)
                if tag in obj:
                    if isinstance(obj[tag], list) and obj.get("_multi_" + tag):
                        obj[tag].append(cval)
                    else:
                        obj[tag] = [obj[tag], cval]
                        obj["_multi_" + tag] = True
                else:
                    obj[tag] = cval
            else:
                args.append(_sexpr_to_obj(child) if isinstance(child, list) else child)
        if args:
            obj["_args"] = args
        return {k: v for k, v in obj.items() if not k.startswith("_multi_")}
    return [_sexpr_to_obj(x) for x in node]


# ======================================================================
# gettext .po
# ======================================================================
def _e_gettext(text: str) -> Tuple[Any, str]:
    entries: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    mode = None
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.strip():
            if cur:
                entries.append(cur)
                cur = {}
                mode = None
            continue
        if s.startswith("#"):
            cur.setdefault("comments", []).append(s)
            continue
        m = re.match(r'^(msgid|msgstr|msgctxt|msgid_plural)\s+"(.*)"$', s)
        if m:
            mode = m.group(1)
            cur[mode] = _unescape_c(m.group(2))
            continue
        m = re.match(r'^"(.*)"$', s)
        if m and mode:
            cur[mode] = str(cur.get(mode, "")) + _unescape_c(m.group(1))
    if cur:
        entries.append(cur)
    return {"entries": entries, "entry_count": len(entries)}, "gettext PO"


# ======================================================================
# IDF (EnergyPlus)  ClassName, field, field, ...;
# ======================================================================
def _e_idf(text: str) -> Tuple[Any, str]:
    text = re.sub(r"!.*", "", text)
    objects: List[Dict[str, Any]] = []
    for chunk in text.split(";"):
        parts = [p.strip() for p in chunk.split(",")]
        parts = [p for p in parts if p != ""]
        if not parts:
            continue
        objects.append({"class": parts[0], "fields": parts[1:]})
    return {"objects": objects, "object_count": len(objects)}, "EnergyPlus IDF"


# ======================================================================
# Abaqus .inp   *KEYWORD, param=val   + data lines
# ======================================================================
def _e_abaqus(text: str) -> Tuple[Any, str]:
    blocks: List[Dict[str, Any]] = []
    cur = None
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.strip() or s.startswith("**"):
            continue
        if s.startswith("*"):
            body = s[1:]
            parts = [p.strip() for p in body.split(",")]
            kw = parts[0]
            params: Dict[str, Any] = {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k.strip()] = _coerce_scalar(v.strip())
                elif p:
                    params[p] = True
            cur = {"keyword": kw, "parameters": params, "data_lines": 0}
            blocks.append(cur)
        elif cur is not None:
            cur["data_lines"] += 1
    return {"blocks": blocks, "block_count": len(blocks)}, "Abaqus input deck"


# ======================================================================
# sfdisk dump
# ======================================================================
def _e_sfdisk(text: str) -> Tuple[Any, str]:
    header: Dict[str, Any] = {}
    partitions: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        # A partition line is `device : key=val, key=val, ...` -- decide by the
        # presence of `=` in the value (RHS of the colon), not by ordering, so a
        # partition record is never mistaken for a `key: value` header field.
        m = re.match(r"^(\S+)\s*:\s*(.*)$", s)
        if m and "=" in m.group(2):
            dev = m.group(1)
            fields: Dict[str, Any] = {"device": dev}
            for kv in m.group(2).split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    fields[k.strip()] = _coerce_scalar(v.strip())
            partitions.append(fields)
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            header[k.strip()] = _coerce_scalar(v.strip())
    return {"header": header, "partitions": partitions}, "sfdisk dump"


# ======================================================================
# Delphi form (.dfm text form)
# ======================================================================
def _e_dfm(text: str) -> Tuple[Any, str]:
    lines = text.splitlines()
    pos = [0]

    def parse_object() -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        while pos[0] < len(lines):
            s = lines[pos[0]].strip()
            pos[0] += 1
            if not s:
                continue
            if s.lower() == "end":
                break
            m = re.match(r"^(?:object|inherited|inline)\s+(\w+):\s*(\w+)", s, re.I)
            if m:
                child = parse_object()
                child["_type"] = m.group(2)
                obj.setdefault("children", {})[m.group(1)] = child
                continue
            pm = re.match(r"^(\w[\w.]*)\s*=\s*(.*)$", s)
            if pm:
                obj[pm.group(1)] = _coerce_scalar(pm.group(2))
        return obj

    root: Dict[str, Any] = {}
    while pos[0] < len(lines):
        s = lines[pos[0]].strip()
        m = re.match(r"^(?:object|inherited)\s+(\w+):\s*(\w+)", s, re.I)
        if m:
            pos[0] += 1
            o = parse_object()
            o["_type"] = m.group(2)
            root[m.group(1)] = o
        else:
            pos[0] += 1
    return root, "Delphi form (text)" if root else "no object blocks (approx)"


# ======================================================================
# GROMACS topology (.top)   [ section ] + data lines
# ======================================================================
def _e_gromacs(text: str) -> Tuple[Any, str]:
    sections: List[Dict[str, Any]] = []
    includes: List[str] = []
    cur = None
    for raw in text.splitlines():
        s = raw.split(";", 1)[0].strip()
        if not s:
            continue
        if s.startswith("#include"):
            includes.append(s.split(None, 1)[1].strip() if " " in s else s)
            continue
        if s.startswith("#"):
            continue
        m = re.match(r"^\[\s*(\w+)\s*\]$", s)
        if m:
            cur = {"section": m.group(1), "entries": []}
            sections.append(cur)
            continue
        if cur is not None:
            cur["entries"].append(s.split())
    return {"includes": includes, "sections": sections}, "GROMACS topology"


# ======================================================================
# SPICE meta-kernel (.tm)   \begindata KEY = ( ... ) \begintext
# ======================================================================
def _e_spice_kernel(text: str) -> Tuple[Any, str]:
    data: Dict[str, Any] = {}
    in_data = False
    buf = ""
    for raw in text.splitlines():
        s = raw.strip()
        if s == "\\begindata":
            in_data = True
            continue
        if s == "\\begintext":
            in_data = False
            continue
        if in_data and s:
            buf += " " + s
    for m in re.finditer(r"([A-Z0-9_+]+)\s*=\s*\(([^)]*)\)", buf):
        vals = re.findall(r"'([^']*)'|([^\s,]+)", m.group(2))
        flat = [a or b for a, b in vals]
        data[m.group(1)] = [_coerce_scalar(x) for x in flat]
    for m in re.finditer(r"([A-Z0-9_+]+)\s*=\s*'([^']*)'", buf):
        data.setdefault(m.group(1), _coerce_scalar(m.group(2)))
    return {"kernel_variables": data}, "SPICE meta-kernel"


# ======================================================================
# klc (Windows keyboard layout source) -- tab-delimited sections
# ======================================================================
def _e_klc(text: str) -> Tuple[Any, str]:
    meta: Dict[str, Any] = {}
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s or s.startswith("//"):
            continue
        m = re.match(
            r"^(KBD|COPYRIGHT|COMPANY|LOCALENAME|LOCALEID|VERSION|SHIFTSTATE)\s+(.*)$",
            s,
        )
        if m:
            meta[m.group(1)] = m.group(2).strip().strip('"')
    return (
        _e_rulelist(text)[0] | {"metadata": meta} if meta else _e_rulelist(text)[0]
    ), "Windows keyboard layout (headers + raw rows)"


# ======================================================================
# Engine dispatch table (family -> parser)
# ======================================================================
_ENGINES = {
    "json": _e_json,
    "toml": _e_toml,
    "yaml": _e_yaml,
    "xml": _e_xml,
    "plist": _e_plist,
    "ini": _e_ini,
    "properties": _e_properties,
    "directive": _e_directive,
    "rulelist": _e_rulelist,
    "dockerfile": _e_dockerfile,
    "starlark": _e_starlark,
    "kv_dsl": _e_kv,
    "deb822": _e_deb822,
    "reg": _e_reg,
    "crontab": _e_crontab,
    "fstab": _e_fstab,
    "sexpr": _e_sexpr,
    "gettext": _e_gettext,
    "hosts": _e_hosts,
    "htpasswd": _e_htpasswd,
    "worldfile": _e_worldfile,
    "csv": _e_csv,
    "namelist": _e_namelist,
    "gimp_palette": _e_gimp_palette,
    "strings": _e_strings,
    "zone": _e_zone,
    "vdf": _e_vdf,
    "acf": _e_vdf,
    "xresources": _e_xresources,
    "ppd": _e_ppd,
    "sdp": _e_sdp,
    "sfz": _e_sfz,
    "ninja": _e_ninja,
    "kconfig": _e_kconfig,
    "ruby_dsl": _e_ruby_dsl,
    "vimscript": _e_vimscript,
    "idf": _e_idf,
    "abaqus": _e_abaqus,
    "sfdisk": _e_sfdisk,
    "dfm": _e_dfm,
    "gromacs": _e_gromacs,
    "spice_kernel": _e_spice_kernel,
    "klc": _e_klc,
}
