# FG-Dist Pentool

> Desktop Security Workbench — **beta**

A standalone desktop application that brings **100+ penetration testing tools** into one unified, modern UI. Built with PyQt6 for Linux (Ubuntu/Debian/Mint).

---

## Features

- **90 security tools** across 10 categories: Recon, Scanning, Exploitation, Web Testing, Network, Wireless, Reverse Engineering, Static Analysis, OSINT, and more
- **Embedded terminal** with root mode (sudo by default), command queue, and session logging
- **Interactive wiki** with per-tool docs, examples, copy/run buttons, and category filters
- **Theme profiles**: Neon, Stealth, Arctic, Light — with auto day/night mode
- **One-click installer** that resolves dependencies and creates command shims automatically
- **Desktop launcher** integration for quick access

---

## Quick Start

### Prerequisites

- Ubuntu / Debian / Linux Mint
- Python 3.12+
- `sudo` access

### Install

```bash
git clone https://github.com/YOUR_USERNAME/FG-Dist_Pentool.git
cd FG-Dist_Pentool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install PyQt6

# Install all 90 tools (takes ~10 min)
sudo bash install_tools.sh

# Launch the app
bash run_desktop.sh
```

### Desktop Launcher

Inside the app, click **🚀 launcher** to create a desktop entry.

---

## Tool Categories

| Category | Tools |
|----------|-------|
| **Recon & OSINT** | theHarvester, sherlock, holehe, amass, subfinder, gau, httpx, gospider, spiderfoot, recon-ng, ... |
| **Scanning & Enumeration** | nmap, masscan, naabu, nikto, nuclei, wapiti, wpscan, sslscan, testssl.sh, ... |
| **Exploitation** | sqlmap, hydra, john, hashcat, metasploit, bettercap, ettercap, aircrack-ng, ... |
| **Web Testing** | gobuster, ffuf, wfuzz, dirsearch, arjun, crlfuzz, Gxss, ... |
| **Network Tools** | tcpdump, wireshark, scapy, mitmproxy, netcat, dnschef, impacket, ... |
| **Reverse Engineering** | radare2, binwalk, apktool, peda, ... |
| **Static Analysis** | bandit, brakeman, ... |
| **Frameworks** | metasploit, bettercap, recon-ng, spiderfoot, ... |
| **Utilities** | tor, seclists, cowsay, lolcat, ... |

---

## Project Structure

```
FG-Dist_Pentool/
├── desktop_app.py          # Main PyQt6 application
├── install_tools.sh        # One-click installer for all 90 tools
├── run_desktop.sh          # Launcher script
├── fg-dist-pentool-beta.desktop  # Desktop entry template
├── assets/                 # Icons and branding
├── logs/                   # Installation logs (gitignored)
├── reports/                # Terminal session exports (gitignored)
└── venv/                   # Python virtual environment (gitignored)
```

---

## Sharing

The project works on any **Ubuntu/Debian-based** system out of the box.  
For other distros (Arch, Fedora), the installer needs adaptation for their package managers.

---

## License

Educational / Security Research use only. Use responsibly and only on systems you have permission to test.
