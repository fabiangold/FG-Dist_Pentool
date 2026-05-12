#!/usr/bin/env bash
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

export PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH"
export GOPATH="$HOME/go"
export GOBIN="$HOME/go/bin"

mkdir -p "$HOME/go/bin" "$HOME/.local/bin" "$HOME/.local/share" "$HOME/.local/opt"

LOG_DIR="$DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install_$(date +%Y%m%d_%H%M%S).log"

OK=0
WARN=0
FAIL=0

say() { printf "%s\n" "$*" | tee -a "$LOG_FILE"; }
ok() { OK=$((OK+1)); say "[ok] $*"; }
warn() { WARN=$((WARN+1)); say "[warn] $* (continuing)"; }
fail() { FAIL=$((FAIL+1)); say "[fail] $*"; }

run_step() {
  local title="$1"; shift
  say "\n==> $title"
  if "$@" >>"$LOG_FILE" 2>&1; then ok "$title"; return 0; fi
  warn "$title"; return 1
}

retry() {
  local tries="$1"; shift; local n=1
  until "$@"; do
    [ "$n" -ge "$tries" ] && return 1
    n=$((n+1)); sleep 2
  done
}

is_cmd() { command -v "$1" >/dev/null 2>&1; }
cmd_ok() { command -v "$1" >/dev/null 2>&1; }

create_shim() {
  local shim_name="$1" target_cmd="$2"
  local shim_path="$HOME/.local/bin/$shim_name"
  printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$target_cmd" > "$shim_path"
  chmod +x "$shim_path"
  ok "shim created: $shim_name"
}

create_script_shim() {
  local shim_name="$1" script_path="$2"
  local shim_path="$HOME/.local/bin/$shim_name"
  printf '#!/usr/bin/env bash\nexec %s "$@"\n' "bash $script_path" > "$shim_path"
  chmod +x "$shim_path"
  ok "shim created: $shim_name -> $script_path"
}

say "[*] FG-Dist Pentool installer"
say "[*] log: $LOG_FILE"

# ──────────────────────────────────────────────────────────────
# PART 1: system packages (sudo)
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 1: system packages"
say "=============================================="

run_step "apt update" sudo apt-get update -y

APT_PKGS=(
  nmap masscan dnsutils netcat-openbsd
  hydra john hashcat aircrack-ng medusa cewl
  tor ettercap-common ettercap-graphical
  wireshark tcpdump radare2 binwalk
  dirb sslscan nikto whatweb netdiscover
  cowsay lolcat gobuster ffuf
  wafw00f dnsrecon apktool smbmap nbtscan
  sqlmap reaver dirsearch mitmproxy
  python3-pip golang-go ruby-full ruby-dev
  jq git curl build-essential libpcap-dev
  pkg-config libssl-dev gdb unzip
)

run_step "apt install base packages" sudo apt-get install -y "${APT_PKGS[@]}"

# metasploit
if ! is_cmd msfconsole; then
  run_step "install metasploit" bash -lc \
    "curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
     -o /tmp/msfinstall && chmod +x /tmp/msfinstall && sudo /tmp/msfinstall"
else
  ok "metasploit already installed"
fi

# sn1per
if [ ! -d "/opt/sn1per" ]; then
  run_step "clone sn1per" sudo git clone --depth 1 https://github.com/1N3/Sn1per.git /opt/sn1per
  run_step "install sn1per" sudo bash /opt/sn1per/install.sh
else
  ok "sn1per already present"
fi

# SecLists
if [ ! -d "/usr/share/seclists" ]; then
  run_step "clone SecLists" sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
else
  ok "SecLists already present"
fi

# testssl.sh
if [ ! -d "/opt/testssl.sh" ]; then
  run_step "clone testssl.sh" sudo git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh
else
  ok "testssl.sh source already present"
fi
if [ -x "/opt/testssl.sh/testssl.sh" ] && ! is_cmd testssl.sh; then
  run_step "link testssl.sh" sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
fi

# wpscan (gem)
if ! is_cmd wpscan; then
  run_step "install wpscan (gem)" sudo gem install wpscan
else
  ok "wpscan already installed"
fi

run_step "install brakeman (gem)" sudo gem install brakeman

# ──────────────────────────────────────────────────────────────
# PART 2: pip packages (user)
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 2: pip packages (user)"
say "=============================================="

PIP_PKGS=(
  bandit pwntools scapy impacket commix wfuzz
  knockpy sublist3r theharvester sslyze wapiti3
  arjun jsbeautifier pycryptodome git-dumper
  name-that-hash sherlock holehe nexfil RsaCtfTool
)

run_step "pip install user tools" pip3 install --user --break-system-packages "${PIP_PKGS[@]}"

# ──────────────────────────────────────────────────────────────
# PART 3: go tools
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 3: go tools"
say "=============================================="

GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  github.com/projectdiscovery/tlsx/cmd/tlsx@latest
  github.com/ffuf/ffuf/v2@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/tomnomnom/httprobe@latest
  github.com/tomnomnom/meg@latest
  github.com/tomnomnom/unfurl@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/tomnomnom/gf@latest
  github.com/haccer/subjack@latest
  github.com/owasp-amass/amass/v3/cmd/amass@latest
  github.com/jaeles-project/gospider@latest
  github.com/sensepost/gowitness@latest
  github.com/KathanP19/Gxss@latest
  github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
  github.com/edoardottt/scilla/cmd/scilla@latest
  github.com/harleo/asnip@latest
  github.com/bettercap/bettercap@latest
)

for mod in "${GO_TOOLS[@]}"; do
  say "\n==> go install $mod"
  if retry 2 go install "$mod" >>"$LOG_FILE" 2>&1; then
    ok "go install $mod"
  else
    warn "go install $mod"
  fi
done

# ──────────────────────────────────────────────────────────────
# PART 4: git-clone tools (user-space, no sudo needed)
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 4: git-clone tools"
say "=============================================="

# enum4linux-ng
if ! cmd_ok enum4linux-ng; then
  if [ ! -d "$HOME/.local/opt/enum4linux-ng" ]; then
    run_step "clone enum4linux-ng" git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git "$HOME/.local/opt/enum4linux-ng"
  fi
  if [ -f "$HOME/.local/opt/enum4linux-ng/enum4linux-ng.py" ]; then
    create_shim "enum4linux-ng" "python3 $HOME/.local/opt/enum4linux-ng/enum4linux-ng.py"
  fi
else
  ok "enum4linux-ng already present"
fi

# spiderfoot
if ! cmd_ok spiderfoot; then
  if [ ! -d "$HOME/.local/opt/spiderfoot" ]; then
    run_step "clone spiderfoot" git clone --depth 1 https://github.com/smicallef/spiderfoot.git "$HOME/.local/opt/spiderfoot"
    run_step "install spiderfoot deps" pip3 install --user --break-system-packages -r "$HOME/.local/opt/spiderfoot/requirements.txt"
  fi
  if [ -f "$HOME/.local/opt/spiderfoot/sfcli.py" ]; then
    shim_path="$HOME/.local/bin/spiderfoot"
    printf '#!/usr/bin/env bash\ncd %s && exec python3 sfcli.py "$@"\n' "$HOME/.local/opt/spiderfoot" > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: spiderfoot"
  fi
else
  ok "spiderfoot already present"
fi

# recon-ng
if ! cmd_ok recon-ng; then
  if [ ! -d "$HOME/.local/opt/recon-ng" ]; then
    run_step "clone recon-ng" git clone --depth 1 https://github.com/lanmaster53/recon-ng.git "$HOME/.local/opt/recon-ng"
  fi
  if [ -f "$HOME/.local/opt/recon-ng/recon-ng" ]; then
    shim_path="$HOME/.local/bin/recon-ng"
    printf '#!/usr/bin/env bash\nexec python3 %s/recon-ng "$@"\n' "$HOME/.local/opt/recon-ng" > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: recon-ng"
  fi
else
  ok "recon-ng already present"
fi

# metagoofil
if ! cmd_ok metagoofil; then
  if [ ! -d "$HOME/.local/opt/metagoofil" ]; then
    run_step "clone metagoofil" git clone --depth 1 https://github.com/laramies/metagoofil.git "$HOME/.local/opt/metagoofil"
  fi
  if [ -f "$HOME/.local/opt/metagoofil/metagoofil.py" ]; then
    shim_path="$HOME/.local/bin/metagoofil"
    printf '#!/usr/bin/env bash\nexec python3 %s/metagoofil.py "$@"\n' "$HOME/.local/opt/metagoofil" > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: metagoofil"
  fi
else
  ok "metagoofil already present"
fi

# massdns
if ! cmd_ok massdns; then
  if [ ! -d "/tmp/massdns" ]; then
    run_step "clone massdns" git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns
  fi
  run_step "build massdns" bash -c "cd /tmp/massdns && make && cp bin/massdns $HOME/.local/bin/"
else
  ok "massdns already present"
fi

# dnsenum
if ! cmd_ok dnsenum; then
  if [ ! -d "/tmp/dnsenum" ]; then
    run_step "clone dnsenum" git clone --depth 1 https://github.com/fwaeytens/dnsenum /tmp/dnsenum
  fi
  if [ -f "/tmp/dnsenum/dnsenum.pl" ]; then
    shim_path="$HOME/.local/bin/dnsenum"
    printf '#!/usr/bin/env bash\nexec perl /tmp/dnsenum/dnsenum.pl "$@"\n' > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: dnsenum"
  fi
else
  ok "dnsenum already present"
fi

# dnsmap
if ! cmd_ok dnsmap; then
  if [ ! -d "/tmp/dnsmap" ]; then
    run_step "clone dnsmap" git clone --depth 1 https://github.com/makefu/dnsmap /tmp/dnsmap
  fi
  run_step "build dnsmap" bash -c "cd /tmp/dnsmap && make && cp src/dnsmap $HOME/.local/bin/"
else
  ok "dnsmap already present"
fi

# dnschef
if ! cmd_ok dnschef; then
  if [ ! -d "/tmp/dnschef" ]; then
    run_step "clone dnschef" git clone --depth 1 https://github.com/iphelix/dnschef.git /tmp/dnschef
  fi
  if [ -f "/tmp/dnschef/dnschef.py" ]; then
    shim_path="$HOME/.local/bin/dnschef"
    printf '#!/usr/bin/env bash\nexec python3 /tmp/dnschef/dnschef.py "$@"\n' > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: dnschef"
  fi
else
  ok "dnschef already present"
fi

# evilgrade
if ! cmd_ok evilgrade; then
  if [ ! -d "$HOME/.local/opt/evilgrade" ]; then
    run_step "clone evilgrade" git clone --depth 1 https://github.com/infobyte/evilgrade.git "$HOME/.local/opt/evilgrade"
  fi
  if [ -f "$HOME/.local/opt/evilgrade/evilgrade" ]; then
    shim_path="$HOME/.local/bin/evilgrade"
    printf '#!/usr/bin/env bash\nexec %s/evilgrade "$@"\n' "$HOME/.local/opt/evilgrade" > "$shim_path"
    chmod +x "$shim_path"
    ok "shim created: evilgrade"
  fi
else
  ok "evilgrade already present"
fi

# jadx
if ! cmd_ok jadx; then
  if [ ! -d "$HOME/.local/opt/jadx" ]; then
    run_step "download jadx" bash -c 'curl -fsSL https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip -o /tmp/jadx.zip && unzip -o /tmp/jadx.zip -d $HOME/.local/opt/jadx'
  fi
  if [ -x "$HOME/.local/opt/jadx/bin/jadx" ]; then
    ln -sf "$HOME/.local/opt/jadx/bin/jadx" "$HOME/.local/bin/jadx"
    ln -sf "$HOME/.local/opt/jadx/bin/jadx-gui" "$HOME/.local/bin/jadx-gui"
    ok "jadx installed"
  fi
else
  ok "jadx already present"
fi

# peda
if [ ! -d "$HOME/peda" ]; then
  run_step "clone peda" git clone --depth 1 https://github.com/longld/peda.git "$HOME/peda"
else
  ok "peda already present"
fi

# ──────────────────────────────────────────────────────────────
# PART 5: shims for python tools without CLI entry points
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 5: shims & fixups"
say "=============================================="

# theHarvester
if ! cmd_ok theHarvester; then
  if python3 -c "import theHarvester" 2>/dev/null; then
    create_shim "theHarvester" "python3 -m theHarvester"
  fi
else
  ok "theHarvester already present"
fi

# bandit
if ! cmd_ok bandit; then
  if python3 -c "import bandit" 2>/dev/null; then
    create_shim "bandit" "python3 -m bandit.cli.main"
  fi
else
  ok "bandit already present"
fi

# impacket-smbexec
if ! cmd_ok impacket-smbexec; then
  if python3 -c "import impacket" 2>/dev/null; then
    create_shim "impacket-smbexec" "python3 -m impacket.smbexec"
  fi
else
  ok "impacket-smbexec already present"
fi

# sublist3r
if ! cmd_ok sublist3r; then
  if python3 -c "import sublist3r" 2>/dev/null; then
    create_shim "sublist3r" "python3 -m sublist3r"
  fi
else
  ok "sublist3r already present"
fi

# knockpy
if ! cmd_ok knockpy; then
  if python3 -c "import knockpy" 2>/dev/null; then
    create_shim "knockpy" "python3 -m knockpy"
  fi
else
  ok "knockpy already present"
fi

# git_dumper
if ! cmd_ok git_dumper; then
  if python3 -c "import git_dumper" 2>/dev/null; then
    create_shim "git_dumper" "python3 -m git_dumper"
  elif cmd_ok git-dumper; then
    create_shim "git_dumper" "git-dumper"
  fi
else
  ok "git_dumper already present"
fi

# Gxss
if cmd_ok Gxss; then
  ok "Gxss already present"
elif cmd_ok gxss; then
  create_shim "Gxss" "gxss"
fi

# RsaCtfTool
if cmd_ok RsaCtfTool; then
  ok "RsaCtfTool already present"
elif cmd_ok rsactftool; then
  create_shim "RsaCtfTool" "rsactftool"
elif python3 -c "import RsaCtfTool" 2>/dev/null; then
  create_shim "RsaCtfTool" "python3 -m RsaCtfTool"
fi

# wapiti
if cmd_ok wapiti; then
  ok "wapiti already present"
elif cmd_ok wapiti3; then
  create_shim "wapiti" "wapiti3"
fi

# seclists
if [ -d "/usr/share/seclists" ] && ! cmd_ok seclists; then
  create_shim "seclists" "ls /usr/share/seclists"
fi

# sn1per shim
if [ -x "/opt/sn1per/sniper" ] && ! cmd_ok sn1per; then
  create_shim "sn1per" "bash /opt/sn1per/sniper"
fi

# ──────────────────────────────────────────────────────────────
# PART 6: verification
# ──────────────────────────────────────────────────────────────
say "\n=============================================="
say " PART 6: command verification"
say "=============================================="

EXPECTED=(
  nmap masscan naabu netdiscover nbtscan smbmap enum4linux-ng nikto nuclei wapiti wpscan
  sslscan sslyze testssl.sh tlsx sqlmap hydra john hashcat medusa cewl commix msfconsole
  bettercap ettercap aircrack-ng reaver gobuster ffuf dirb wfuzz dirsearch
  arjun crlfuzz qsreplace gf Gxss scilla nth RsaCtfTool tcpdump wireshark scapy
  impacket-smbexec mitmproxy nc dnschef evilgrade r2 binwalk apktool gdb
  bandit brakeman python3 theHarvester sherlock holehe nexfil spiderfoot recon-ng
  metagoofil amass subfinder sublist3r gau waybackurls httpx httprobe dnsx dnsrecon dnsenum
  knockpy shuffledns massdns whatweb wafw00f gowitness gospider meg unfurl subjack dnsmap
  asnip git_dumper cowsay lolcat tor seclists sn1per
)

missing_tmp="$LOG_DIR/missing_commands_$(date +%Y%m%d_%H%M%S).txt"
> "$missing_tmp"
for c in "${EXPECTED[@]}"; do
  if cmd_ok "$c"; then
    ok "verified command: $c"
  else
    warn "missing command: $c"
    echo "$c" >> "$missing_tmp"
  fi
done

if [ -s "$missing_tmp" ]; then
  say "\n[!] Missing commands list: $missing_tmp"
else
  ok "all expected commands are available"
fi

if ! grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  ok "added go/local bin PATH to ~/.bashrc"
else
  ok "PATH already configured in ~/.bashrc"
fi

say "\n=============================================="
say " INSTALL SUMMARY"
say "=============================================="
say "[ok]   $OK"
say "[warn] $WARN"
say "[fail] $FAIL"
say "log: $LOG_FILE"

if [ "$FAIL" -gt 0 ]; then
  say "\n[!] completed with failures. review log."
  exit 1
fi

say "\n[✓] installation completed"
say "[i] open a new terminal or run: source ~/.bashrc"
