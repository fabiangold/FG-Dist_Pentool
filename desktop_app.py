#!/usr/bin/env python3
"""Pentest UI Desktop App — polished PyQt6 GUI"""

import json, os, shlex, shutil, subprocess, sys, threading, time
from datetime import datetime
from functools import partial
from urllib.parse import quote, unquote

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve, QVariantAnimation, QSize
from PyQt6.QtGui import QFont, QPalette, QColor, QShortcut, QPainter, QLinearGradient, QBrush, QPen, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QFrame, QGridLayout,
    QTextEdit, QTextBrowser, QSizePolicy, QStackedWidget, QGraphicsOpacityEffect,
    QDialog,
    QCheckBox,
    QSplashScreen,
    QComboBox,
    QTabWidget,
    QMenu,
)
from PyQt6.QtGui import QAction

# ────────────────────────────────────────────────────────────
#  DATA
# ────────────────────────────────────────────────────────────

TOOL_WIKI = {
    "nmap": {"url":"https://nmap.org/docs.html","examples":["nmap -sV -sC -p- <target>","nmap -sS -A -T4 <target>","nmap -p 80,443 --script vuln <target>"],"desc":"Network exploration tool and security/port scanner.","req":["sudo"]},
    "masscan": {"url":"https://github.com/robertdavidgraham/masscan","examples":["masscan -p1-65535 --rate=1000 <target>","masscan -p80,443 <target/24>"],"desc":"High-speed TCP port scanner.","req":["sudo"]},
    "naabu": {"url":"https://github.com/projectdiscovery/naabu","examples":["naabu -host <target>","naabu -list hosts.txt -top-ports 1000"],"desc":"Fast port scanner written in Go."},
    "netdiscover": {"url":"https://github.com/netdiscover-scanner/netdiscover","examples":["sudo netdiscover -r 192.168.1.0/24","sudo netdiscover -i eth0 -P"],"desc":"ARP-based network scanner.","req":["sudo"]},
    "nbtscan": {"url":"https://github.com/resurrecting-open-source-projects/nbtscan","examples":["nbtscan 192.168.1.0/24","nbtscan -v -s : <target>"],"desc":"NBT (NetBIOS) name scanner."},
    "smbmap": {"url":"https://github.com/ShawnDEvans/smbmap","examples":["smbmap -H <target>","smbmap -u guest -p '' -H <target>"],"desc":"SMB enumeration tool."},
    "enum4linux": {"url":"https://github.com/cddmp/enum4linux-ng","examples":["enum4linux-ng -A <target>","enum4linux-ng -u user -p pass <target>"],"desc":"Windows/Samba enumeration tool."},
    "nikto": {"url":"https://github.com/sullo/nikto","examples":["nikto -h http://<target>","nikto -h https://<target> -ssl -port 443"],"desc":"Web server vulnerability scanner."},
    "nuclei": {"url":"https://github.com/projectdiscovery/nuclei","examples":["nuclei -u https://<target>","nuclei -l urls.txt -t cves/"],"desc":"Template-based vulnerability scanner."},
    "wapiti": {"url":"https://github.com/wapiti-scanner/wapiti","examples":["wapiti -u https://<target>","wapiti -u https://<target> --scope folder"],"desc":"Black-box web vulnerability scanner."},
    "wpscan": {"url":"https://github.com/wpscanteam/wpscan","examples":["wpscan --url https://<target>","wpscan --url https://<target> --enumerate u"],"desc":"WordPress security scanner."},
    "sslscan": {"url":"https://github.com/rbsec/sslscan","examples":["sslscan <target>:443","sslscan --no-heartbleed <target>"],"desc":"SSL/TLS protocol scanner."},
    "sslyze": {"url":"https://github.com/nabla-c0d3/sslyze","examples":["sslyze <target>:443","sslyze --regular <target>"],"desc":"SSL/TLS misconfiguration scanner."},
    "testssl": {"url":"https://github.com/drwetter/testssl.sh","examples":["testssl.sh https://<target>","testssl.sh --parallel <target>:443"],"desc":"TLS/SSL protocol checker."},
    "tlsx": {"url":"https://github.com/projectdiscovery/tlsx","examples":["tlsx -u <target>","tlsx -l hosts.txt -p 443"],"desc":"Fast TLS certificate info tool."},
    "sqlmap": {"url":"https://github.com/sqlmapproject/sqlmap","examples":["sqlmap -u 'http://<target>/page?id=1' --batch","sqlmap -r request.txt --dbs"],"desc":"Automatic SQL injection detection and exploitation."},
    "hydra": {"url":"https://github.com/vanhauser-thc/thc-hydra","examples":["hydra -l admin -P words.txt ssh://<target>","hydra -L users.txt -P pass.txt <target> http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'"],"desc":"Parallelized network login cracker."},
    "john": {"url":"https://github.com/openwall/john","examples":["john --wordlist=words.txt hash.txt","john --show hash.txt","john --incremental hash.txt"],"desc":"John the Ripper password cracker."},
    "hashcat": {"url":"https://hashcat.net/hashcat/","examples":["hashcat -m 0 -a 0 hash.txt words.txt","hashcat -m 1000 -a 3 hash.txt ?a?a?a?a?a?a"],"desc":"GPU-accelerated password recovery tool."},
    "medusa": {"url":"http://foofus.net/goons/jmk/medusa/medusa.html","examples":["medusa -h <target> -u admin -P words.txt -M ssh","medusa -H hosts.txt -U users.txt -P pass.txt -M ftp"],"desc":"Parallel brute-force password cracker."},
    "cewl": {"url":"https://github.com/digininja/CeWL","examples":["cewl https://<target> -w words.txt","cewl https://<target> -d 3 -m 5 -w words.txt"],"desc":"Custom wordlist generator."},
    "commix": {"url":"https://github.com/commixproject/commix","examples":["commix -u 'http://<target>/page?cmd=test'","commix -r request.txt"],"desc":"Command injection exploitation tool."},
    "metasploit": {"url":"https://www.metasploit.com/","examples":["msfconsole -q","msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=4444 -f elf > shell.elf"],"desc":"Penetration testing framework."},
    "bettercap": {"url":"https://www.bettercap.org/","examples":["sudo bettercap -eval 'net.probe on'","sudo bettercap -eval 'set arp.spoof.targets 192.168.1.100; arp.spoof on'"],"desc":"Modular MITM framework."},
    "ettercap": {"url":"https://www.ettercap-project.org/","examples":["sudo ettercap -G","sudo ettercap -T -M arp /<target>// /<gateway>//"],"desc":"Comprehensive MITM attack suite."},

    "gobuster": {"url":"https://github.com/OJ/gobuster","examples":["gobuster dir -u https://<target> -w /usr/share/wordlists/dirb/common.txt","gobuster dns -d <domain> -w subdomains.txt"],"desc":"Directory/file and DNS brute-force tool."},
    "ffuf": {"url":"https://github.com/ffuf/ffuf","examples":["ffuf -u https://<target>/FUZZ -w words.txt","ffuf -u https://<target>/path?param=FUZZ -w params.txt -fs 1234"],"desc":"Fast web fuzzer."},
    "dirb": {"url":"https://github.com/v0re/dirb","examples":["dirb http://<target>","dirb https://<target> -X .php,.html"],"desc":"Web content scanner."},
    "wfuzz": {"url":"https://github.com/xmendez/wfuzz","examples":["wfuzz -w words.txt https://<target>/FUZZ","wfuzz -z file,words.txt -z file,params.txt https://<target>/page?param=FUZZ&other=FUZ2Z"],"desc":"Web application fuzzer."},
    "dirsearch": {"url":"https://github.com/maurosoria/dirsearch","examples":["dirsearch -u https://<target>","dirsearch -u https://<target> -e php,html -x 403,404"],"desc":"Advanced web path scanner."},
    "arjun": {"url":"https://github.com/s0md3v/Arjun","examples":["arjun -u https://<target>/api/endpoint","arjun -u https://<target> --get"],"desc":"HTTP parameter discovery tool."},
    "crlfuzz": {"url":"https://github.com/dwisiswant0/crlfuzz","examples":["crlfuzz -u https://<target>","crlfuzz -l urls.txt -o results.txt"],"desc":"CRLF injection scanner."},
    "qsreplace": {"url":"https://github.com/tomnomnom/qsreplace","examples":["cat urls.txt | qsreplace 'test'","cat urls.txt | qsreplace '<script>alert(1)</script>'"],"desc":"Query string replacement fuzzer."},
    "gf": {"url":"https://github.com/tomnomnom/gf","examples":["gf xss < urls.txt","gf sqli < urls.txt","gf redirect < urls.txt"],"desc":"Pattern matching wrapper for grep."},
    "gxss": {"url":"https://github.com/KathanP19/Gxss","examples":["cat urls.txt | Gxss -c 100 -p Xss","echo '<target>' | Gxss"],"desc":"Reflected XSS detector."},
    "scilla": {"url":"https://github.com/edoardottt/scilla","examples":["scilla -info <target>","scilla -enum <target>"],"desc":"Information gathering tool."},
    "name-that-hash": {"url":"https://github.com/HashPals/Name-That-Hash","examples":["nth -t '$hash_string'","nth -f hashes.txt"],"desc":"Hash type identifier."},
    "rsactftool": {"url":"https://github.com/sourcekris/RsaCtfTool","examples":["RsaCtfTool -n <n> -e <e> --uncipher <ciphertext>","RsaCtfTool --publickey key.pub --private"],"desc":"RSA attack and decryption tool."},
    "tcpdump": {"url":"https://www.tcpdump.org/","examples":["sudo tcpdump -i eth0","sudo tcpdump -i eth0 port 80 -w capture.pcap"],"desc":"Command-line packet analyzer."},
    "wireshark": {"url":"https://www.wireshark.org/","examples":["sudo wireshark","tshark -r capture.pcap -Y 'http.request'"],"desc":"Industry-standard network protocol analyzer."},
    "scapy": {"url":"https://scapy.net/","examples":["scapy","python3 -c \"from scapy.all import *; sr1(IP(dst='<target>')/ICMP())\""],"desc":"Python-based packet manipulation tool."},
    "impacket": {"url":"https://github.com/fortra/impacket","examples":["impacket-smbexec <domain>/<user>:<pass>@<target>","impacket-secretsdump <domain>/<user>:<pass>@<target>"],"desc":"Network protocol toolkit."},
    "mitmproxy": {"url":"https://mitmproxy.org/","examples":["mitmproxy --mode transparent","mitmdump -r capture.flow"],"desc":"Interactive HTTPS proxy."},
    "netcat": {"url":"https://nc110.sourceforge.io/","examples":["nc -lvnp 4444","nc <target> 80 < request.txt"],"desc":"Versatile networking utility."},
    "dnschef": {"url":"https://github.com/iphelix/dnschef","examples":["dnschef --fakeip <redir_ip> --interface eth0","dnschef --logfile dns.log --fakeip 127.0.0.1"],"desc":"DNS proxy for network testing."},
    "evilgrade": {"url":"https://github.com/infobyte/evilgrade","examples":["evilgrade","evilgrade -c config.txt"],"desc":"Fake update injection framework."},
    "radare2": {"url":"https://rada.re/n/","examples":["r2 -d ./binary","r2 ./binary","r2 -c 'aaa; afl' ./binary"],"desc":"Reverse engineering framework."},
    "binwalk": {"url":"https://github.com/ReFirmLabs/binwalk","examples":["binwalk firmware.bin","binwalk -Me firmware.bin"],"desc":"Firmware analysis tool."},
    "apktool": {"url":"https://ibotpeaches.github.io/Apktool/","examples":["apktool d app.apk","apktool b app/"],"desc":"Android APK reverse engineering tool."},
    "jadx": {"url":"https://github.com/skylot/jadx","examples":["jadx app.apk","jadx-gui app.apk"],"desc":"DEX to Java decompiler."},
    "peda": {"url":"https://github.com/longld/peda","examples":["echo 'source ~/peda/peda.py' > ~/.gdbinit","gdb -q ./binary"],"desc":"Python Exploit Development Assistance for GDB."},
    "bandit": {"url":"https://github.com/PyCQA/bandit","examples":["bandit -r myproject/","bandit -f json -o results.json myproject/"],"desc":"Python security linter."},
    "brakeman": {"url":"https://github.com/presidentbeef/brakeman","examples":["brakeman /path/to/rails/app","brakeman -o report.html /path/to/rails/app"],"desc":"Rails security scanner."},
    "pwntools": {"url":"https://github.com/Gallopsled/pwntools","examples":["python3 -c \"from pwn import *; print(ELLIPTIC_CURVE('secp256k1'))\""],"desc":"CTF exploit development library."},
    "theHarvester": {"url":"https://github.com/laramies/theHarvester","examples":["theHarvester -d <domain> -b google","theHarvester -d <domain> -b all -l 500"],"desc":"Email, subdomain, name OSINT tool."},
    "sherlock": {"url":"https://github.com/sherlock-project/sherlock","examples":["sherlock <username>","sherlock <username> --output results.txt"],"desc":"Username OSINT across 400+ networks."},
    "holehe": {"url":"https://github.com/megadose/holehe","examples":["holehe <email>","holehe <email> --only-used"],"desc":"Email OSINT tool."},
    "nexfil": {"url":"https://github.com/thewhiteh4t/nexfil","examples":["nexfil -u <username>","nexfil -u <username> -l 100"],"desc":"Username OSINT search tool."},
    "spiderfoot": {"url":"https://github.com/smicallef/spiderfoot","examples":["spiderfoot -s <target> -o results.html","spiderfoot -l 127.0.0.1:5001"],"desc":"Automated OSINT collection tool."},
    "recon-ng": {"url":"https://github.com/lanmaster53/recon-ng","examples":["recon-ng","recon-ng -r script.rc"],"desc":"Web reconnaissance framework."},
    "metagoofil": {"url":"https://github.com/laramies/metagoofil","examples":["metagoofil -d <domain> -t pdf,doc -l 200 -o output/"],"desc":"Metadata harvester."},
    "amass": {"url":"https://github.com/owasp-amass/amass","examples":["amass enum -d <domain>","amass intel -whois -d <domain>"],"desc":"Attack surface mapping and asset discovery."},
    "subfinder": {"url":"https://github.com/projectdiscovery/subfinder","examples":["subfinder -d <domain>","subfinder -d <domain> -o subs.txt"],"desc":"Passive subdomain discovery tool."},
    "sublist3r": {"url":"https://github.com/aboul3la/Sublist3r","examples":["sublist3r -d <domain>","sublist3r -d <domain> -p 80,443"],"desc":"OSINT-based subdomain enumeration."},
    "gau": {"url":"https://github.com/lc/gau","examples":["gau <domain>","gau --subs <domain>"],"desc":"Get All URLs from passive sources."},
    "waybackurls": {"url":"https://github.com/tomnomnom/waybackurls","examples":["waybackurls <domain>","cat domains.txt | waybackurls > urls.txt"],"desc":"Fetch URLs from Wayback Machine."},
    "httpx": {"url":"https://github.com/projectdiscovery/httpx","examples":["httpx -l hosts.txt","httpx -u https://<target> -status-code -title"],"desc":"HTTP probing and response analysis."},
    "httprobe": {"url":"https://github.com/tomnomnom/httprobe","examples":["cat domains.txt | httprobe","cat domains.txt | httprobe -c 50"],"desc":"Probe for working HTTP/HTTPS servers."},
    "dnsx": {"url":"https://github.com/projectdiscovery/dnsx","examples":["dnsx -d <domain> -a -aaaa -cname","echo '<target>' | dnsx -a -resp"],"desc":"Multi-purpose DNS toolkit."},
    "dnsrecon": {"url":"https://github.com/darkoperator/dnsrecon","examples":["dnsrecon -d <domain>","dnsrecon -d <domain> -t axfr"],"desc":"DNS enumeration script."},
    "dnsenum": {"url":"https://github.com/fwaeytens/dnsenum","examples":["dnsenum <domain>","dnsenum --enum <domain> -f subdomains.txt"],"desc":"DNS enumeration tool."},
    "knockpy": {"url":"https://github.com/guelfoweb/knock","examples":["knockpy <domain>","knockpy <domain> --wordlist subdomains.txt"],"desc":"Subdomain enumeration tool."},
    "shuffledns": {"url":"https://github.com/projectdiscovery/shuffledns","examples":["shuffledns -d <domain> -w subdomains.txt -r resolvers.txt"],"desc":"DNS bruteforce resolver."},
    "massdns": {"url":"https://github.com/blechschmidt/massdns","examples":["massdns -r resolvers.txt -t A subdomains.txt > results.txt"],"desc":"High-performance DNS resolver."},
    "whatweb": {"url":"https://github.com/urbanadventurer/WhatWeb","examples":["whatweb https://<target>","whatweb --aggression 3 https://<target>"],"desc":"Web technology fingerprinting."},
    "wafw00f": {"url":"https://github.com/EnableSecurity/wafw00f","examples":["wafw00f https://<target>","wafw00f https://<target> -a"],"desc":"WAF identification tool."},
    "gowitness": {"url":"https://github.com/sensepost/gowitness","examples":["gowitness file -f urls.txt","gowitness scan -p https://<target>"],"desc":"Web screenshot tool (Go)."},
    "sn1per": {"url":"https://github.com/1N3/Sn1per","examples":["bash /opt/sn1per/sniper -t <target>","bash /opt/sn1per/sniper -t <target> -re"],"desc":"Automated pentest scanner."},
    "gospider": {"url":"https://github.com/jaeles-project/gospider","examples":["gospider -s https://<target>","gospider -S sites.txt -c 30 -d 1"],"desc":"Web spider for asset discovery."},
    "meg": {"url":"https://github.com/tomnomnom/meg","examples":["meg -d 1000 paths.txt hosts.txt","meg /robots.txt hosts.txt"],"desc":"URL batch fetching tool."},
    "unfurl": {"url":"https://github.com/tomnomnom/unfurl","examples":["echo 'https://<target>/path?id=1' | unfurl format %d%p%q","cat urls.txt | unfurl paths"],"desc":"URL extraction and analysis tool."},
    "subjack": {"url":"https://github.com/haccer/subjack","examples":["subjack -w subs.txt -t 100 -timeout 30 -o results.txt","subjack -d <domain> -v"],"desc":"Subdomain takeover detection."},
    "dnsmap": {"url":"https://github.com/makefu/dnsmap","examples":["dnsmap <domain>","dnsmap <domain> -w words.txt"],"desc":"DNS network mapper."},
    "asnip": {"url":"https://github.com/harleo/asnip","examples":["asnip -t <target>","asnip -t <target> -o results.txt"],"desc":"IP to ASN lookup tool."},
    "tor": {"url":"https://www.torproject.org/","examples":["sudo systemctl start tor","export http_proxy=socks5://127.0.0.1:9050"],"desc":"Tor anonymity network."},
    "seclists": {"url":"https://github.com/danielmiessler/SecLists","examples":["ls /usr/share/seclists/Discovery/","cat /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt"],"desc":"Wordlist collection for security testing."},
    "git-dumper": {"url":"https://github.com/arthaud/git-dumper","examples":["git_dumper https://<target>/.git/ output/","git_dumper -f 5 https://<target>/.git/ output/"],"desc":"Dump exposed .git repositories."},
    "cowsay": {"url":"https://github.com/tnalpgge/rank-amateur-cowsay","examples":["cowsay 'hello world'","echo 'test' | cowsay"],"desc":"Configurable speaking cow."},
    "lolcat": {"url":"https://github.com/busyloop/lolcat","examples":["echo 'text' | lolcat","command | lolcat"],"desc":"Rainbow text colorizer."},
    "crackmapexec": {"url":"https://github.com/Porchetta-Industries/CrackMapExec","examples":["nxc smb <target> -u user -p pass","nxc smb <target> -u user -H <hash> --shares"],"desc":"Swiss Army knife for pentesting networks."},
    "bloodhound": {"url":"https://github.com/BloodHoundAD/BloodHound","examples":"bloodhound-python -d <domain> -u user -p pass -c All","desc":"Active Directory attack path mapping."},
    "frida": {"url":"https://frida.re/","examples":["frida -U -f com.app -l script.js --no-pause","frida-trace -U -i 'open*'"],"desc":"Dynamic instrumentation toolkit."},
    "jwt_tool": {"url":"https://github.com/ticarpi/jwt_tool","examples":["python3 jwt_tool.py <jwt> -X c","python3 jwt_tool.py <jwt> -I -hc kid -hv ' OR 1=1--"],"desc":"JWT testing and exploitation toolkit."},
    "xsstrike": {"url":"https://github.com/s0md3v/XSStrike","examples":["python3 xsstrike.py -u '<url>'","python3 xsstrike.py -u '<url>' --fuzzer"],"desc":"Advanced XSS detection suite."},
    "chisel": {"url":"https://github.com/jpillora/chisel","examples":["chisel server --reverse","chisel client <server:port> R:socks"],"desc":"Fast TCP/UDP tunnel over HTTP."},
    "responder": {"url":"https://github.com/lgandx/Responder","examples":["sudo responder -I eth0 -wrf"],"desc":"LLMNR/NBT-NS poisoner and credential harvester."},
    "setoolkit": {"url":"https://github.com/trustedsec/social-engineer-toolkit","examples":["sudo setoolkit"],"desc":"Social-Engineer Toolkit for phishing attacks."},
    "linpeas": {"url":"https://github.com/peass-ng/PEASS-ng","examples":["./linpeas.sh","curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash"],"desc":"Linux Privilege Escalation Awesome Script."},
    "pacu": {"url":"https://github.com/RhinoSecurityLabs/pacu","examples":["python3 cli.py","run <module> --keyword-args {'region':'us-east-1'}"],"desc":"AWS exploitation framework."},
}

CATEGORIES = {
    "Recon & OSINT": {
        "theHarvester": {"wiki":"theHarvester","desc":"Email, subdomain & name OSINT"},
        "sherlock": {"wiki":"sherlock","desc":"Username OSINT across social networks"},
        "holehe": {"wiki":"holehe","desc":"Email OSINT / account existence check"},
        "nexfil": {"wiki":"nexfil","desc":"Username OSINT tool"},
        "spiderfoot": {"wiki":"spiderfoot","desc":"Automated OSINT and data collection"},
        "recon-ng": {"wiki":"recon-ng","desc":"Web-based reconnaissance framework"},
        "metagoofil": {"wiki":"metagoofil","desc":"Metadata harvester with email extraction"},
        "amass": {"wiki":"amass","desc":"Attack-surface mapping and asset discovery"},
        "subfinder": {"wiki":"subfinder","desc":"Passive subdomain discovery tool"},
        "sublist3r": {"wiki":"sublist3r","desc":"OSINT-based subdomain enumeration"},
        "gau": {"wiki":"gau","desc":"Get all URLs from passive sources"},
        "waybackurls": {"wiki":"waybackurls","desc":"Fetch URLs from Wayback Machine"},
        "httpx": {"wiki":"httpx","desc":"HTTP probing and response analysis"},
        "httprobe": {"wiki":"httprobe","desc":"Probe for working HTTP/HTTPS servers"},
        "dnsx": {"wiki":"dnsx","desc":"DNS lookup and resolution tool"},
        "dnsrecon": {"wiki":"dnsrecon","desc":"DNS enumeration script"},
        "dnsenum": {"wiki":"dnsenum","desc":"DNS enumeration with zone transfer"},
        "knockpy": {"wiki":"knockpy","desc":"Subdomain enumeration via wordlist"},
        "shuffledns": {"wiki":"shuffledns","desc":"DNS bruteforce resolver"},
        "massdns": {"wiki":"massdns","desc":"Bulk DNS resolver"},
        "whatweb": {"wiki":"whatweb","desc":"Web scanner and fingerprinter"},
        "wafw00f": {"wiki":"wafw00f","desc":"WAF identification and fingerprinting"},
        "gowitness": {"wiki":"gowitness","desc":"Web screenshot tool (Go)"},
        "sn1per": {"wiki":"sn1per","desc":"Automated pentest scanner"},
        "gospider": {"wiki":"gospider","desc":"Web spider for asset discovery"},
        "meg": {"wiki":"meg","desc":"URL batch fetching tool"},
        "unfurl": {"wiki":"unfurl","desc":"URL entropy and analysis"},
        "subjack": {"wiki":"subjack","desc":"Subdomain takeover detection"},
        "dnsmap": {"wiki":"dnsmap","desc":"DNS network mapper"},
        "asnip": {"wiki":"asnip","desc":"IP to ASN lookup tool"},
    },
    "Scanning & Enumeration": {
        "nmap": {"wiki":"nmap","desc":"Network discovery and port scanner"},
        "masscan": {"wiki":"masscan","desc":"High-speed TCP port scanner"},
        "naabu": {"wiki":"naabu","desc":"Fast port scanner for asset discovery"},
        "netdiscover": {"wiki":"netdiscover","desc":"ARP-based network scanner"},
        "nbtscan": {"wiki":"nbtscan","desc":"NetBIOS name scanner"},
        "smbmap": {"wiki":"smbmap","desc":"SMB enumeration tool"},
        "enum4linux": {"wiki":"enum4linux","desc":"Windows/Samba enumeration"},
        "nikto": {"wiki":"nikto","desc":"Web server vulnerability scanner"},
        "nuclei": {"wiki":"nuclei","desc":"Template-based vulnerability scanner"},
        "wapiti": {"wiki":"wapiti","desc":"Black-box web vulnerability scanner"},
        "wpscan": {"wiki":"wpscan","desc":"WordPress vulnerability scanner"},
        "sslscan": {"wiki":"sslscan","desc":"SSL/TLS certificate scanner"},
        "sslyze": {"wiki":"sslyze","desc":"SSL/TLS misconfiguration scanner"},
        "testssl": {"wiki":"testssl","desc":"SSL/TLS protocol checker"},
        "tlsx": {"wiki":"tlsx","desc":"TLS certificate info tool"},
    },
    "Exploitation": {
        "sqlmap": {"wiki":"sqlmap","desc":"SQL injection detection & exploitation"},
        "hydra": {"wiki":"hydra","desc":"Password brute-forcing"},
        "john": {"wiki":"john","desc":"Password cracker"},
        "hashcat": {"wiki":"hashcat","desc":"Advanced hash cracking tool"},
        "medusa": {"wiki":"medusa","desc":"Parallel brute-force password cracker"},
        "cewl": {"wiki":"cewl","desc":"Custom wordlist generator"},
        "commix": {"wiki":"commix","desc":"Command injection exploitation"},
        "metasploit": {"wiki":"metasploit","desc":"Exploit development framework"},
        "bettercap": {"wiki":"bettercap","desc":"MITM framework and monitor"},
        "ettercap": {"wiki":"ettercap","desc":"MITM attack suite"},
        "aircrack-ng": {"wiki":"aircrack-ng","desc":"Wifi security testing suite"},
        "reaver": {"wiki":"reaver","desc":"WPS brute-force tool"},
    },
    "Web Testing": {
        "gobuster": {"wiki":"gobuster","desc":"Directory/file DNS busting"},
        "ffuf": {"wiki":"ffuf","desc":"Fast web fuzzer"},
        "dirb": {"wiki":"dirb","desc":"Web content scanner"},
        "wfuzz": {"wiki":"wfuzz","desc":"Web application fuzzer"},
        "dirsearch": {"wiki":"dirsearch","desc":"Directory brute-forcer"},
        "arjun": {"wiki":"arjun","desc":"HTTP parameter discovery"},
        "crlfuzz": {"wiki":"crlfuzz","desc":"CRLF injection scanner"},
        "qsreplace": {"wiki":"qsreplace","desc":"Query string replacement fuzzer"},
        "gf": {"wiki":"gf","desc":"Pattern matching for grep"},
        "gxss": {"wiki":"gxss","desc":"Reflected XSS detector"},
        "scilla": {"wiki":"scilla","desc":"Information gathering tool"},
    },
    "Network Tools": {
        "tcpdump": {"wiki":"tcpdump","desc":"CLI packet analyzer"},
        "wireshark": {"wiki":"wireshark","desc":"GUI packet analyzer"},
        "scapy": {"wiki":"scapy","desc":"Python packet manipulation"},
        "impacket": {"wiki":"impacket","desc":"Network protocol toolkit"},
        "mitmproxy": {"wiki":"mitmproxy","desc":"HTTPS intercepting proxy"},
        "netcat": {"wiki":"netcat","desc":"TCP/IP swiss army knife"},
        "dnschef": {"wiki":"dnschef","desc":"DNS proxy for network testing"},
        "evilgrade": {"wiki":"evilgrade","desc":"Fake update injection framework"},
    },
    "Password & Hash": {
        "john": {"wiki":"john","desc":"Password cracker (JtR)"},
        "hashcat": {"wiki":"hashcat","desc":"GPU-powered hash cracker"},
        "hydra": {"wiki":"hydra","desc":"Online password brute-force"},
        "medusa": {"wiki":"medusa","desc":"Parallel password cracker"},
        "cewl": {"wiki":"cewl","desc":"Custom wordlist spider"},
        "name-that-hash": {"wiki":"name-that-hash","desc":"Hash type identifier"},
        "rsactftool": {"wiki":"rsactftool","desc":"RSA attack & decryption tool"},
    },
    "Wireless": {
        "aircrack-ng": {"wiki":"aircrack-ng","desc":"Wifi auditing suite"},
        "reaver": {"wiki":"reaver","desc":"WPS brute-force attack"},
        "ettercap": {"wiki":"ettercap","desc":"MITM on wireless networks"},
    },
    "Reverse Engineering": {
        "radare2": {"wiki":"radare2","desc":"Reverse engineering framework"},
        "binwalk": {"wiki":"binwalk","desc":"Firmware analysis tool"},
        "apktool": {"wiki":"apktool","desc":"Android APK reverse engineering"},
        "peda": {"wiki":"peda","desc":"GDB exploit assistance"},
    },
    "Static Analysis": {
        "bandit": {"wiki":"bandit","desc":"Python security linter"},
        "brakeman": {"wiki":"brakeman","desc":"Rails security scanner"},
        "wpscan": {"wiki":"wpscan","desc":"WordPress vulnerability scanner"},
        "sqlmap": {"wiki":"sqlmap","desc":"SQL injection detection"},
    },
    "Frameworks": {
        "metasploit": {"wiki":"metasploit","desc":"Metasploit exploit framework"},
        "bettercap": {"wiki":"bettercap","desc":"MITM and monitoring framework"},
        "recon-ng": {"wiki":"recon-ng","desc":"Web recon framework"},
        "spiderfoot": {"wiki":"spiderfoot","desc":"OSINT automation framework"},
        "pwntools": {"wiki":"pwntools","desc":"CTF exploit development library"},
    },
    "CTF Tools": {
        "pwntools": {"wiki":"pwntools","desc":"CTF exploit library"},
        "rsactftool": {"wiki":"rsactftool","desc":"RSA CTF solver"},
        "binwalk": {"wiki":"binwalk","desc":"Firmware extraction for CTFs"},
        "radare2": {"wiki":"radare2","desc":"Binary analysis for CTFs"},
    },
    "OSINT Tools": {
        "theHarvester": {"wiki":"theHarvester","desc":"Email, subdomain OSINT"},
        "sherlock": {"wiki":"sherlock","desc":"Username search OSINT"},
        "holehe": {"wiki":"holehe","desc":"Email account OSINT"},
        "nexfil": {"wiki":"nexfil","desc":"Username OSINT"},
        "spiderfoot": {"wiki":"spiderfoot","desc":"OSINT automation"},
        "recon-ng": {"wiki":"recon-ng","desc":"Recon framework"},
        "metagoofil": {"wiki":"metagoofil","desc":"Metadata OSINT"},
        "amass": {"wiki":"amass","desc":"Attack surface OSINT"},
    },
    "Utilities": {
        "tor": {"wiki":"tor","desc":"Tor anonymity network"},
        "seclists": {"wiki":"seclists","desc":"Wordlist collection"},
        "git-dumper": {"wiki":"git-dumper","desc":"Git repository dumper"},
        "cowsay": {"wiki":"cowsay","desc":"Mascot utility"},
        "lolcat": {"wiki":"lolcat","desc":"Rainbow text output"},
    },
    "Cloud & Post-Ex": {
        "crackmapexec": {"wiki":"crackmapexec","desc":"Network pentesting Swiss Army knife"},
        "bloodhound": {"wiki":"bloodhound","desc":"AD attack path mapping"},
        "responder": {"wiki":"responder","desc":"LLMNR/NBT-NS poisoner"},
        "chisel": {"wiki":"chisel","desc":"Fast TCP/UDP tunnel over HTTP"},
        "linpeas": {"wiki":"linpeas","desc":"Linux PrivEsc enumeration"},
        "pacu": {"wiki":"pacu","desc":"AWS exploitation framework"},
    },
    "Advanced Web": {
        "jwt_tool": {"wiki":"jwt_tool","desc":"JWT testing and exploitation"},
        "xsstrike": {"wiki":"xsstrike","desc":"Advanced XSS detection suite"},
        "frida": {"wiki":"frida","desc":"Dynamic instrumentation toolkit"},
        "setoolkit": {"wiki":"setoolkit","desc":"Social-Engineer Toolkit"},
    },
}

TOOL_CMDS = {
    "nmap":"sudo nmap","masscan":"sudo masscan","naabu":"naabu",
    "netdiscover":"sudo netdiscover","nbtscan":"nbtscan","smbmap":"smbmap",
    "enum4linux":"enum4linux-ng","nikto":"nikto","nuclei":"nuclei",
    "wapiti":"wapiti","wpscan":"wpscan","sslscan":"sslscan",
    "sslyze":"sslyze","testssl":"testssl.sh","tlsx":"tlsx",
    "sqlmap":"sqlmap","hydra":"hydra","john":"john","hashcat":"hashcat",
    "medusa":"medusa","cewl":"cewl","commix":"commix",
    "metasploit":"sudo msfconsole","bettercap":"sudo bettercap",
    "ettercap":"sudo ettercap -G",
    "aircrack-ng":"sudo aircrack-ng","reaver":"sudo reaver",
    "gobuster":"gobuster","ffuf":"ffuf",
    "dirb":"dirb","wfuzz":"wfuzz","dirsearch":"dirsearch","arjun":"arjun",
    "crlfuzz":"crlfuzz","qsreplace":"qsreplace","gf":"gf",
    "gxss":"Gxss","scilla":"scilla",
    "name-that-hash":"nth","rsactftool":"RsaCtfTool",
    "tcpdump":"sudo tcpdump","wireshark":"sudo wireshark","scapy":"scapy",
    "impacket":"impacket-smbexec","mitmproxy":"mitmproxy","netcat":"nc",
    "dnschef":"dnschef","evilgrade":"evilgrade","radare2":"r2",
    "binwalk":"binwalk","apktool":"apktool",
    "peda":"gdb","bandit":"bandit","brakeman":"brakeman",
    "pwntools":"python3",
    "theHarvester":"theHarvester","sherlock":"sherlock","holehe":"holehe",
    "nexfil":"nexfil","spiderfoot":"spiderfoot","recon-ng":"recon-ng",
    "metagoofil":"metagoofil","amass":"amass","subfinder":"subfinder",
    "sublist3r":"sublist3r","gau":"gau","waybackurls":"waybackurls",
    "httpx":"httpx","httprobe":"httprobe","dnsx":"dnsx",
    "dnsrecon":"dnsrecon","dnsenum":"dnsenum","knockpy":"knockpy",
    "shuffledns":"shuffledns","massdns":"massdns","whatweb":"whatweb",
    "wafw00f":"wafw00f",
    "gowitness":"gowitness","sn1per":"bash /opt/sn1per/sniper",
    "gospider":"gospider","meg":"meg","unfurl":"unfurl",
    "subjack":"subjack","dnsmap":"dnsmap","asnip":"asnip",
    "tor":"sudo systemctl start tor",
    "seclists":"ls /usr/share/seclists","git-dumper":"git_dumper",
    "cowsay":"cowsay","lolcat":"lolcat",
    "crackmapexec":"nxc",
    "bloodhound":"bloodhound-python",
    "frida":"frida",
    "jwt_tool":"python3 jwt_tool.py",
    "xsstrike":"python3 xsstrike.py",
    "chisel":"chisel",
    "responder":"sudo responder",
    "setoolkit":"sudo setoolkit",
    "linpeas":"./linpeas.sh",
    "pacu":"python3 cli.py",
}

TOOL_CATEGORY = {}
for cat, tools in CATEGORIES.items():
    for name, t in tools.items():
        TOOL_CATEGORY[t["wiki"]] = cat

# ────────────────────────────────────────────────────────────
#  THEME — modern dark with neon accents
# ────────────────────────────────────────────────────────────

THEMES = {
    "Neon": {
        "bg":"#0d0d14","surface":"#14141f","card":"#1a1a28",
        "border":"#252538","green":"#00ff88","blue":"#7dcfff",
        "purple":"#bb9af7","yellow":"#f7c948","orange":"#ff9e3b",
        "red":"#ff5370","fg":"#e0e0e0","dim":"#6c7086",
        "soft":"#8a8fa8","text":"#c0caf5","surface2":"#1e1e32",
    },
    "Stealth": {
        "bg":"#0b0f10","surface":"#12181a","card":"#162023",
        "border":"#253035","green":"#39d98a","blue":"#6ccff6",
        "purple":"#8e9afc","yellow":"#f1c40f","orange":"#f39c12",
        "red":"#e74c3c","fg":"#dfe7e9","dim":"#7f8c8d",
        "soft":"#95a5a6","text":"#d0dde0","surface2":"#1c2629",
    },
    "Arctic": {
        "bg":"#0f1220","surface":"#151a2d","card":"#1b2238",
        "border":"#2b3555","green":"#5eead4","blue":"#93c5fd",
        "purple":"#c4b5fd","yellow":"#fde68a","orange":"#fdba74",
        "red":"#fca5a5","fg":"#e5e7eb","dim":"#94a3b8",
        "soft":"#a5b4fc","text":"#cbd5e1","surface2":"#222b45",
    },
    "Light": {
        "bg":"#f5f7fb","surface":"#ffffff","card":"#eef2f8",
        "border":"#cfd8e6","green":"#10b981","blue":"#2563eb",
        "purple":"#7c3aed","yellow":"#ca8a04","orange":"#ea580c",
        "red":"#dc2626","fg":"#0f172a","dim":"#64748b",
        "soft":"#475569","text":"#0f172a","surface2":"#e2e8f0",
    },
}


def _config_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ui_config.json")


def load_ui_config():
    p = _config_path()
    if not os.path.exists(p):
        return {"theme": "Neon", "font_scale": 100, "auto_day_night": False, "icon_style": "minimal"}
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        if d.get("theme") not in THEMES:
            d["theme"] = "Neon"
        if not isinstance(d.get("font_scale"), int):
            d["font_scale"] = 100
        if d["font_scale"] < 85 or d["font_scale"] > 160:
            d["font_scale"] = 100
        if not isinstance(d.get("auto_day_night"), bool):
            d["auto_day_night"] = False
        if d.get("icon_style") not in ("minimal", "cyber"):
            d["icon_style"] = "minimal"
        return d
    except Exception:
        return {"theme": "Neon", "font_scale": 100, "auto_day_night": False, "icon_style": "minimal"}


def save_ui_config(cfg):
    try:
        with open(_config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


UI_CONFIG = load_ui_config()


def effective_theme_name(cfg):
    if cfg.get("auto_day_night", False):
        hr = datetime.now().hour
        return "Stealth" if (hr >= 20 or hr < 7) else "Light"
    return cfg.get("theme", "Neon")


def get_icon_path():
    base = os.path.dirname(os.path.abspath(__file__))
    style = UI_CONFIG.get("icon_style", "minimal")
    if style == "cyber":
        p = os.path.join(base, "assets", "fgdist_icon.svg")
    else:
        p = os.path.join(base, "assets", "fgdist_icon_minimal.svg")
    if os.path.exists(p):
        return p
    fallback = os.path.join(base, "assets", "fgdist_icon.svg")
    return fallback


C = THEMES.get(effective_theme_name(UI_CONFIG), THEMES["Neon"]).copy()

RUN_CMD_HANDLER = None


def run_command(cmd):
    handler = RUN_CMD_HANDLER or launch_terminal
    return handler(cmd)

def apply_theme(app):
    app.setStyle("Fusion")
    p = QPalette()
    for role, color in {
        QPalette.ColorRole.Window: QColor(C["bg"]),
        QPalette.ColorRole.WindowText: QColor(C["fg"]),
        QPalette.ColorRole.Base: QColor(C["surface"]),
        QPalette.ColorRole.AlternateBase: QColor(C["card"]),
        QPalette.ColorRole.Text: QColor(C["fg"]),
        QPalette.ColorRole.Button: QColor(C["surface"]),
        QPalette.ColorRole.ButtonText: QColor(C["fg"]),
        QPalette.ColorRole.Highlight: QColor(C["green"]),
        QPalette.ColorRole.HighlightedText: QColor(C["bg"]),
    }.items():
        p.setColor(role, color)
    app.setPalette(p)

_BTN = (f"QPushButton{{background:transparent;border:1px solid {C['green']}44;"
        f"color:{C['green']};border-radius:8px;padding:8px 16px;font-size:12px;font-family:monospace;}}"
        f"QPushButton:hover{{background:{C['green']}18;border-color:{C['green']};}}")

_BTN_P = (f"QPushButton{{background:{C['green']};border:none;border-radius:6px;"
          f"padding:10px 22px;font-size:13px;font-weight:bold;color:{C['bg']};font-family:monospace;}}"
          f"QPushButton:hover{{background:#00cc6e;}}")

_BTN_O = (f"QPushButton{{background:transparent;border:1px solid {C['orange']}44;"
          f"color:{C['orange']};border-radius:8px;padding:8px 16px;font-size:12px;font-family:monospace;}}"
          f"QPushButton:hover{{background:{C['orange']}18;border-color:{C['orange']};}}")


def rebuild_theme_tokens():
    global _BTN, _BTN_P, _BTN_O
    _BTN = (f"QPushButton{{background:transparent;border:1px solid {C['green']}44;"
            f"color:{C['green']};border-radius:8px;padding:8px 16px;font-size:12px;font-family:monospace;}}"
            f"QPushButton:hover{{background:{C['green']}18;border-color:{C['green']};}}")
    _BTN_P = (f"QPushButton{{background:{C['green']};border:none;border-radius:6px;"
              f"padding:10px 22px;font-size:13px;font-weight:bold;color:{C['bg']};font-family:monospace;}}"
              f"QPushButton:hover{{background:#00cc6e;}}")
    _BTN_O = (f"QPushButton{{background:transparent;border:1px solid {C['orange']}44;"
              f"color:{C['orange']};border-radius:8px;padding:8px 16px;font-size:12px;font-family:monospace;}}"
              f"QPushButton:hover{{background:{C['orange']}18;border-color:{C['orange']};}}")


def apply_theme_profile(name):
    theme = THEMES.get(name, THEMES["Neon"])
    C.clear()
    C.update(theme)
    rebuild_theme_tokens()

# ────────────────────────────────────────────────────────────
#  HELPERS
# ────────────────────────────────────────────────────────────

def find_terminal():
    for name in ["x-terminal-emulator","gnome-terminal","lxterminal","xfce4-terminal","konsole","xterm"]:
        p = shutil.which(name)
        if p:
            return p
    return ""

def launch_terminal(full_cmd):
    home = os.path.expanduser('~')
    bash_c = f"cd {home}; echo '$ {full_cmd}'; {full_cmd}; echo; read -p 'Press Enter to close...'"
    term = find_terminal()
    if not term:
        return False
    try:
        bn = os.path.basename(term)
        if "gnome-terminal" in bn:
            subprocess.Popen([term, "--", "bash", "-c", bash_c])
        elif "konsole" in bn:
            subprocess.Popen([term, "-e", "bash", "-c", bash_c])
        elif "xterm" in bn:
            subprocess.Popen([term, "-e", "bash", "-c", bash_c])
        else:
            subprocess.Popen([term, "-e", f"bash -c {shlex.quote(bash_c)}"])
        return True
    except Exception:
        return False

def check_installed(wiki_key):
    if wiki_key == "peda":
        return os.path.exists(os.path.expanduser("~/peda/peda.py"))
    cmd = TOOL_CMDS.get(wiki_key, "")
    if not cmd:
        return False
    parts = shlex.split(cmd)
    base = parts[0]
    if base.startswith("sudo "):
        base = base.split()[-1]
    base = base.split("/")[-1]
    if base in ("msfconsole",):
        return shutil.which("msfconsole") is not None
    if base.startswith("python") or base.startswith("bash"):
        return True
    if os.path.exists(parts[0].replace("sudo ", "")):
        return True
    return shutil.which(base) is not None

# ────────────────────────────────────────────────────────────
#  HELP FETCHER (thread-safe)
# ────────────────────────────────────────────────────────────

class HelpFetcher(QObject):
    finished = pyqtSignal(str)
    def fetch(self, key):
        def run():
            cmd = TOOL_CMDS.get(key, "")
            if not cmd:
                self.finished.emit("no command configured"); return
            parts = shlex.split(cmd)
            candidates = []
            if parts[0] == "sudo" and len(parts) > 1: candidates.append(parts[1])
            candidates.append(parts[0])
            candidates = list(dict.fromkeys(candidates))
            output = ""
            for base in candidates:
                for flag in ["--help","-h"]:
                    try:
                        r = subprocess.run(shlex.split(f"{base} {flag}"), capture_output=True, text=True, timeout=8)
                        out = (r.stdout or "") + (r.stderr or "")
                        if out.strip(): output = out.strip()[:4000]; break
                    except: continue
                if output: break
            if not output:
                for base in candidates:
                    try:
                        r = subprocess.run(["man", base], capture_output=True, text=True, timeout=8)
                        if r.stdout.strip(): output = r.stdout.strip()[:3000]; break
                    except: continue
            self.finished.emit(output if output else "no help output available")
        threading.Thread(target=run, daemon=True).start()

# ────────────────────────────────────────────────────────────
#  ANIMATED CATEGORY BODY
# ────────────────────────────────────────────────────────────

class AnimatedBody(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._open = True
        self._content = QVBoxLayout(self)
        self._content.setContentsMargins(0,0,0,0)
        self._content.setSpacing(4)
        self._anim = QVariantAnimation(self)
        self._anim.valueChanged.connect(self._on_anim)
        self._anim.finished.connect(self._on_finish)

    def set_open(self, open_, animate=True):
        if open_ == self._open:
            return
        self._open = open_
        if not animate:
            self.setVisible(open_)
            return
        if open_:
            self.setVisible(True)
            self._anim.setDuration(200)
            self._anim.setStartValue(0)
            self._anim.setEndValue(self._full_height())
            self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._anim.start()
        else:
            self._anim.setDuration(150)
            self._anim.setStartValue(self.height())
            self._anim.setEndValue(0)
            self._anim.setEasingCurve(QEasingCurve.Type.InCubic)
            self._anim.start()

    def _full_height(self):
        self.setMaximumHeight(16777215)
        if self.layout() is not None:
            self.layout().activate()
        h = self.sizeHint().height()
        return max(h, 10)

    def _on_anim(self, val):
        self.setMaximumHeight(int(val))

    def _on_finish(self):
        if not self._open:
            self.setVisible(False)
            self.setMaximumHeight(0)
        else:
            self.setMaximumHeight(16777215)

# ────────────────────────────────────────────────────────────
#  DETAIL PANEL
# ────────────────────────────────────────────────────────────

class DetailPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.key = ""
        self._fetcher = HelpFetcher()
        self._fetcher.finished.connect(self._on_help)
        self.setStyleSheet(f"background:{C['surface']};border:1px solid {C['green']}44;border-radius:12px;padding:18px;")
        self.setVisible(False)
        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)

        l = QVBoxLayout(self)
        l.setContentsMargins(18,18,18,18); l.setSpacing(10)

        top = QHBoxLayout()
        self._title = QLabel()
        self._title.setStyleSheet(f"font-size:18px;color:{C['green']};font-family:monospace;font-weight:bold;")
        self._cat = QLabel()
        self._cat.setStyleSheet(f"font-size:12px;color:{C['dim']};font-family:monospace;")
        close = QPushButton("Close details")
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setMinimumWidth(120)
        close.setFixedHeight(32)
        close.setStyleSheet(
            f"QPushButton{{background:{C['surface2']};border:1px solid {C['red']}55;border-radius:8px;"
            f"color:{C['red']};font-size:12px;font-family:monospace;padding:4px 10px;}}"
            f"QPushButton:hover{{background:{C['red']}22;border-color:{C['red']};color:{C['fg']};}}"
        )
        close.clicked.connect(self._close)
        top.addWidget(self._title); top.addWidget(self._cat); top.addStretch(); top.addWidget(close)
        l.addLayout(top)

        self._close_hint = QLabel("Tip: press Esc, click the same tool again, or use Close details")
        self._close_hint.setStyleSheet(f"font-size:10px;color:{C['dim']};font-family:monospace;")
        l.addWidget(self._close_hint)

        self._desc = QLabel()
        self._desc.setWordWrap(True)
        self._desc.setStyleSheet(f"font-size:13px;color:{C['text']};padding:14px;background:{C['bg']};border-radius:8px;border-left:3px solid {C['green']};font-family:monospace;line-height:1.5;")
        l.addWidget(self._desc)

        self._ex_lbl = QLabel("USAGE EXAMPLES")
        self._ex_lbl.setStyleSheet(f"font-size:10px;color:{C['dim']};letter-spacing:2px;margin-top:4px;font-family:monospace;")
        l.addWidget(self._ex_lbl)
        self._ex_c = QVBoxLayout()
        l.addLayout(self._ex_c)

        self._cmd_lbl = QLabel("COMMAND")
        self._cmd_lbl.setStyleSheet(f"font-size:10px;color:{C['dim']};letter-spacing:2px;margin-top:4px;font-family:monospace;")
        l.addWidget(self._cmd_lbl)
        cmd_row = QHBoxLayout()
        self._cmd_text = QLabel()
        self._cmd_text.setStyleSheet(f"font-size:12px;color:{C['soft']};font-family:monospace;padding:9px 12px;background:{C['bg']};border:1px solid {C['border']};border-radius:6px;")
        self._args = QLineEdit()
        self._args.setPlaceholderText("args…")
        self._args.setStyleSheet(f"QLineEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:6px;padding:8px 10px;color:{C['fg']};font-size:12px;font-family:monospace;min-width:180px;}}QLineEdit:focus{{border:1px solid {C['green']}88;}}")
        cmd_row.addWidget(self._cmd_text); cmd_row.addWidget(self._args)
        l.addLayout(cmd_row)

        act = QHBoxLayout()
        self._run_btn = QPushButton("▶  run"); self._run_btn.setStyleSheet(_BTN_P); self._run_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._run_btn.clicked.connect(self._run)
        self._help_btn = QPushButton("load help"); self._help_btn.setStyleSheet(_BTN); self._help_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._help_btn.clicked.connect(self._help)
        act.addWidget(self._run_btn); act.addWidget(self._help_btn); act.addStretch()
        l.addLayout(act)
        self._help_out = QTextEdit()
        self._help_out.setReadOnly(True)
        self._help_out.setStyleSheet(f"QTextEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:8px;padding:12px;font-size:12px;color:{C['text']};font-family:monospace;max-height:240px;}}")
        self._help_out.setVisible(False)
        l.addWidget(self._help_out)

    def _close(self):
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(150)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.0)
        self._anim.valueChanged.connect(lambda v: self._opacity.setOpacity(v))
        self._anim.finished.connect(lambda: self.setVisible(False))
        self._anim.start()

    def show_tool(self, key):
        self.key = key
        w = TOOL_WIKI.get(key, {})
        self._title.setText(f"> {key}")
        self._cat.setText(f"  {TOOL_CATEGORY.get(key,'')}")
        self._desc.setText(w.get("desc",""))
        while self._ex_c.count():
            it = self._ex_c.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        for ex in w.get("examples",[]):
            row = QHBoxLayout()
            label = QLabel(f"$ {ex}")
            label.setStyleSheet(f"font-size:10px;color:{C['fg']};font-family:monospace;padding:7px 10px;background:{C['bg']};border:1px solid {C['border']};border-radius:6px;")
            label.setWordWrap(True)
            cp = QPushButton("copy"); cp.setStyleSheet(_BTN); cp.setCursor(Qt.CursorShape.PointingHandCursor)
            cp.clicked.connect(partial(self._copy, ex))
            er = QPushButton("▶ run"); er.setStyleSheet(_BTN_O); er.setCursor(Qt.CursorShape.PointingHandCursor)
            er.clicked.connect(partial(self._run_example, ex))
            row.addWidget(label); row.addWidget(cp); row.addWidget(er)
            w2 = QWidget(); w2.setLayout(row); self._ex_c.addWidget(w2)
        self._cmd_text.setText(TOOL_CMDS.get(key,"—"))
        self._args.clear()
        self._help_out.setVisible(False); self._help_out.clear()
        self.setVisible(True)
        self._opacity.setOpacity(1.0)

    def _copy(self, t): QApplication.clipboard().setText(t)
    def _run(self):
        a = self._args.text().strip(); c = TOOL_CMDS.get(self.key,""); f = f"{c} {a}".strip()
        if f: run_command(f)
    def _run_example(self, ex):
        f = f"{TOOL_CMDS.get(self.key,'')} {ex}".strip(); run_command(f)
    def _help(self):
        self._help_out.setVisible(True); self._help_out.setText("loading…"); self._fetcher.fetch(self.key)
    def _on_help(self, t): self._help_out.setText(t)

# ────────────────────────────────────────────────────────────
#  TOOL CARD
# ────────────────────────────────────────────────────────────

class ToolCard(QFrame):
    clicked = pyqtSignal(str)
    context_menu_requested = pyqtSignal(str, object)
    def __init__(self, key, name, desc):
        super().__init__()
        self.key = key; self._name = name; self._selected = False; self._status = "idle"
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFrameStyle(QFrame.Shape.NoFrame)
        installed = check_installed(key)
        badge = f'<span style="color:{C["green"]};">●</span>' if installed else f'<span style="color:{C["dim"]};">○</span>'
        
        req_tags = ""
        cmd = TOOL_CMDS.get(key, "")
        if cmd.startswith("sudo ") or "sudo " in cmd: req_tags += '<span style="color:#ff9e3b;font-size:9px;">🔒</span> '
        if "wlan" in cmd or "wifi" in desc.lower() or "aircrack" in key.lower() or "wifite" in key.lower(): req_tags += '<span style="color:#7dcfff;font-size:9px;">📡</span> '
        if "gui" in cmd.lower() or "ettercap -G" in cmd: req_tags += '<span style="color:#bb9af7;font-size:9px;">🖥️</span> '
        if "aws" in desc.lower() or "cloud" in desc.lower() or "pacu" in key: req_tags += '<span style="color:#f7c948;font-size:9px;">☁️</span> '

        html = (
            f'<div style="font-size:13px;color:{C["blue"]};margin-bottom:2px;">&gt; {name} {badge}</div>'
            f'<div style="font-size:11px;color:{C["soft"]};">{desc[:85]}{"…" if len(desc)>85 else ""}</div>'
            f'<div style="margin-top:4px;font-size:10px;">{req_tags}<span id="status" style="color:{C["dim"]};">idle</span></div>'
        )
        self._label = QLabel(html)
        self._label.setWordWrap(True)
        self._label.setTextFormat(Qt.TextFormat.RichText)
        self._set_style("default")
        l = QVBoxLayout(self); l.setContentsMargins(0,0,0,0); l.addWidget(self._label)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def _show_context_menu(self, pos):
        self.context_menu_requested.emit(self.key, pos)

    def _set_style(self, state):
        m = {
            "default": (C["card"], C["border"]),
            "hover": (C["surface"], f"{C['green']}55"),
            "selected": (C["surface2"], C["green"]),
            "running": (f"{C['orange']}22", C["orange"]),
        }
        bg, bd = m.get(state, m["default"])
        self._label.setStyleSheet(
            f"QLabel{{background:{bg};border:1px solid {bd};border-radius:10px;padding:12px 14px;font-family:monospace;min-height:92px;}}"
        )

    def set_status(self, status):
        self._status = status
        if status == "running":
            self._set_style("running")
            self._label.setText(self._label.text().replace('<span id="status" style="color:#6c7086;">idle</span>', '<span id="status" style="color:#ff9e3b;">⟳ running...</span>').replace('<span id="status" style="color:#00ff88;">✓ done</span>', '<span id="status" style="color:#ff9e3b;">⟳ running...</span>'))
        elif status == "idle":
            self._set_style("selected" if self._selected else "default")
            self._label.setText(self._label.text().replace('<span id="status" style="color:#ff9e3b;">⟳ running...</span>', '<span id="status" style="color:#00ff88;">✓ done</span>').replace('<span id="status" style="color:#6c7086;">idle</span>', '<span id="status" style="color:#6c7086;">idle</span>'))

    def set_selected(self, s):
        self._selected = s
        if self._status != "running":
            self._set_style("selected" if s else "default")
    def mousePressEvent(self, e): self.clicked.emit(self.key)
    def enterEvent(self, e):
        if not self._selected and self._status != "running": self._set_style("hover")
    def leaveEvent(self, e):
        if not self._selected and self._status != "running": self._set_style("default")

# ────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FG-Dist Pentool beta")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(1280, 820)
        self.resize(1600, 980)

        self._selected_key = None
        self._all_cards = []
        self._wiki_mode = False
        self._log_tail_stop = None

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(24,24,24,24)
        outer.setSpacing(14)

        # ── header / branding ──
        header_box = QFrame()
        header_box.setStyleSheet(
            f"QFrame{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C['surface2']}, stop:1 {C['surface']});"
            f"border:1px solid {C['border']};border-radius:12px;}}"
        )
        hdr = QHBoxLayout(header_box)
        hdr.setContentsMargins(14, 10, 14, 10)
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        icon_lbl = QLabel()
        icon_lbl.setFixedSize(36, 36)
        app_icon_path = get_icon_path()
        if os.path.exists(app_icon_path):
            pm = QPixmap(app_icon_path)
            if not pm.isNull():
                icon_lbl.setPixmap(pm.scaled(36, 36, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))

        brand_col = QVBoxLayout()
        title = QLabel("FG-Dist Pentool beta")
        title.setStyleSheet(f"font-size:26px;color:{C['green']};font-family:monospace;font-weight:bold;letter-spacing:0.5px;")
        subtitle = QLabel("Desktop Security Workbench")
        subtitle.setStyleSheet(f"font-size:11px;color:{C['soft']};font-family:monospace;letter-spacing:1px;")
        brand_col.addWidget(title)
        brand_col.addWidget(subtitle)
        brand_row.addWidget(icon_lbl)
        brand_row.addLayout(brand_col)
        hdr.addLayout(brand_row)
        hdr.addStretch()

        app_badge = QLabel("BETA")
        app_badge.setStyleSheet(
            f"QLabel{{background:{C['orange']}22;border:1px solid {C['orange']}66;border-radius:8px;"
            f"color:{C['orange']};font-size:10px;font-family:monospace;padding:4px 10px;font-weight:bold;}}"
        )
        hdr.addWidget(app_badge)

        self._macros_btn = QPushButton("⚡ macros"); self._macros_btn.setStyleSheet(_BTN); self._macros_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._macros_btn.clicked.connect(self._show_macros_dialog)
        self._report_btn = QPushButton("📊 report"); self._report_btn.setStyleSheet(_BTN); self._report_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._report_btn.clicked.connect(self._generate_report)
        self._wiki_btn = QPushButton("📖 wiki"); self._wiki_btn.setStyleSheet(_BTN_O); self._wiki_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._wiki_btn.clicked.connect(self._toggle_wiki)
        self._help_btn = QPushButton("❓ help"); self._help_btn.setStyleSheet(_BTN); self._help_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._help_btn.clicked.connect(lambda: self._maybe_show_onboarding(force=True))
        self._launcher_btn = QPushButton("🚀 launcher"); self._launcher_btn.setStyleSheet(_BTN); self._launcher_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._launcher_btn.clicked.connect(self._install_desktop_launcher)
        self._settings_btn = QPushButton("⚙ settings"); self._settings_btn.setStyleSheet(_BTN); self._settings_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._settings_btn.clicked.connect(self._open_settings_dialog)
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(list(THEMES.keys()))
        self._theme_combo.setCurrentText(UI_CONFIG.get("theme", "Neon"))
        self._theme_combo.setStyleSheet(
            f"QComboBox{{background:{C['surface']};border:1px solid {C['border']};border-radius:8px;padding:6px 10px;color:{C['fg']};font-size:12px;font-family:monospace;min-width:120px;}}"
            f"QComboBox::drop-down{{border:0;}}"
        )
        self._theme_combo.currentTextChanged.connect(self._set_theme_from_ui)
        self._install_btn = QPushButton("⬇ install missing"); self._install_btn.setStyleSheet(_BTN); self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._install_btn.clicked.connect(self._install_missing)
        self._refresh_btn = QPushButton("↻ refresh"); self._refresh_btn.setStyleSheet(_BTN); self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._refresh_btn.clicked.connect(self._refresh_status)
        self._term_toggle_btn = QPushButton("⌨ terminal"); self._term_toggle_btn.setStyleSheet(_BTN); self._term_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor); self._term_toggle_btn.clicked.connect(self._toggle_terminal)
        hdr.addWidget(self._macros_btn); hdr.addWidget(self._report_btn); hdr.addWidget(self._wiki_btn); hdr.addWidget(self._help_btn); hdr.addWidget(self._launcher_btn); hdr.addWidget(self._settings_btn); hdr.addWidget(self._theme_combo); hdr.addWidget(self._install_btn); hdr.addWidget(self._refresh_btn); hdr.addWidget(self._term_toggle_btn)
        self._stats = QLabel()
        self._stats.setStyleSheet(f"font-size:12px;color:{C['dim']};font-family:monospace;padding:4px 0;")
        hdr.addWidget(self._stats)
        self._update_stats()
        outer.addWidget(header_box)

        # ── target bar + search ──
        bar = QHBoxLayout()
        tgt = QLabel("🎯 target"); tgt.setStyleSheet(f"font-size:12px;color:{C['dim']};font-family:monospace;")
        self._target_history = QComboBox()
        self._target_history.setEditable(True)
        self._target_history.lineEdit().setPlaceholderText("192.168.1.1  ·  example.com")
        self._target_history.setStyleSheet(f"QComboBox{{background:{C['surface']};border:1px solid {C['border']};border-radius:10px;padding:8px 12px;color:{C['yellow']};font-size:13px;font-family:monospace;min-width:240px;}}QComboBox:focus{{border:1px solid {C['green']}88;}}QComboBox::drop-down{{border:0;}}")
        self._target_history.lineEdit().returnPressed.connect(self._save_current_target)
        self._target_history.activated.connect(self._on_target_selected)
        self._load_target_history()
        clr = QPushButton("✕"); clr.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['dim']};font-size:12px;}}QPushButton:hover{{color:{C['fg']};}}"); clr.setCursor(Qt.CursorShape.PointingHandCursor); clr.clicked.connect(self._target_history.lineEdit().clear)
        bar.addWidget(tgt); bar.addWidget(self._target_history); bar.addWidget(clr)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  filter tools by name or category…")
        self._search.setStyleSheet(f"QLineEdit{{background:{C['surface']};border:1px solid {C['border']};border-radius:10px;padding:10px 14px;color:{C['fg']};font-size:13px;font-family:monospace;}}QLineEdit:focus{{border:1px solid {C['green']}88;}}")
        self._search.textChanged.connect(self._on_search)
        bar.addWidget(self._search)
        outer.addLayout(bar)

        usage_hint = QLabel("FG-Dist workflow: Open tool card | Close: Esc / same card / Close details | Run in embedded terminal")
        usage_hint.setStyleSheet(f"font-size:11px;color:{C['dim']};font-family:monospace;padding:2px 2px;")
        outer.addWidget(usage_hint)

        # ── stacked widget: tools / wiki ──
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("QStackedWidget{background:transparent;}")

        # page 0 — tools grid
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(f"QScrollArea{{border:none;background:transparent;}}QScrollBar:vertical{{width:5px;background:{C['bg']};}}QScrollBar::handle:vertical{{background:{C['dim']}66;border-radius:3px;}}QScrollBar::add-line:vertical{{height:0;}}QScrollBar::sub-line:vertical{{height:0;}}")
        self._sw = QWidget()
        self._sl = QVBoxLayout(self._sw)
        self._sl.setContentsMargins(0,0,0,0); self._sl.setSpacing(3)
        self._scroll.setWidget(self._sw)
        self._stack.addWidget(self._scroll)

        # page 1 — wiki view
        self._wiki_scroll = QScrollArea()
        self._wiki_scroll.setWidgetResizable(True)
        self._wiki_scroll.setStyleSheet(f"QScrollArea{{border:none;background:transparent;}}QScrollBar:vertical{{width:5px;background:{C['bg']};}}QScrollBar::handle:vertical{{background:{C['dim']}66;border-radius:3px;}}QScrollBar::add-line:vertical{{height:0;}}QScrollBar::sub-line:vertical{{height:0;}}")
        self._wiki_sw = QWidget()
        self._wiki_sl = QVBoxLayout(self._wiki_sw)
        self._wiki_sl.setContentsMargins(0,0,0,0); self._wiki_sl.setSpacing(4)
        self._wiki_scroll.setWidget(self._wiki_sw)
        self._stack.addWidget(self._wiki_scroll)

        # page 2 — results viewer
        self._results_scroll = QScrollArea()
        self._results_scroll.setWidgetResizable(True)
        self._results_scroll.setStyleSheet(f"QScrollArea{{border:none;background:transparent;}}QScrollBar:vertical{{width:5px;background:{C['bg']};}}QScrollBar::handle:vertical{{background:{C['dim']}66;border-radius:3px;}}QScrollBar::add-line:vertical{{height:0;}}QScrollBar::sub-line:vertical{{height:0;}}")
        self._results_sw = QWidget()
        self._results_sl = QVBoxLayout(self._results_sw)
        self._results_sl.setContentsMargins(0,0,0,0); self._results_sl.setSpacing(6)
        self._results_scroll.setWidget(self._results_sw)
        self._stack.addWidget(self._results_scroll)

        outer.addWidget(self._stack, stretch=1)

        # ── detail panel ──
        self._detail = DetailPanel()
        outer.addWidget(self._detail)

        # ── embedded terminal (tabbed) ──
        self._term_visible = True
        self._root_mode = True
        term_box = QFrame()
        term_box.setStyleSheet(f"QFrame{{background:{C['surface']};border:1px solid {C['border']};border-radius:10px;}}")
        term_l = QVBoxLayout(term_box)
        term_l.setContentsMargins(10, 10, 10, 10)
        term_l.setSpacing(8)
        term_top = QHBoxLayout()
        term_title = QLabel("terminal")
        term_title.setStyleSheet(f"font-size:12px;color:{C['green']};font-family:monospace;")
        term_top.addWidget(term_title)
        term_top.addStretch()
        self._root_btn = QPushButton("🔒 root")
        self._root_btn.setCheckable(True)
        self._root_btn.setChecked(self._root_mode)
        self._root_btn.setStyleSheet(_BTN)
        self._root_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._root_btn.clicked.connect(self._toggle_root)
        self._new_term_tab_btn = QPushButton("+ tab")
        self._new_term_tab_btn.setStyleSheet(_BTN)
        self._new_term_tab_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._new_term_tab_btn.clicked.connect(self._add_terminal_tab)
        clear_btn = QPushButton("clear")
        clear_btn.setStyleSheet(_BTN)
        clear_btn.clicked.connect(self._clear_active_terminal)
        stop_btn = QPushButton("stop")
        stop_btn.setStyleSheet(_BTN_O)
        stop_btn.clicked.connect(self._stop_terminal_cmd)
        install_live_btn = QPushButton("install + live log")
        install_live_btn.setStyleSheet(_BTN)
        install_live_btn.clicked.connect(self._install_missing)
        health_btn = QPushButton("health")
        health_btn.setStyleSheet(_BTN)
        health_btn.clicked.connect(self._show_health_dashboard)
        save_btn = QPushButton("save session")
        save_btn.setStyleSheet(_BTN)
        save_btn.clicked.connect(self._save_terminal_session)
        term_top.addWidget(self._root_btn)
        term_top.addWidget(self._new_term_tab_btn)
        term_top.addWidget(clear_btn)
        term_top.addWidget(stop_btn)
        term_top.addWidget(install_live_btn)
        term_top.addWidget(health_btn)
        term_top.addWidget(save_btn)
        term_l.addLayout(term_top)

        self._term_tabs = QTabWidget()
        self._term_tabs.setTabsClosable(True)
        self._term_tabs.tabCloseRequested.connect(self._close_terminal_tab)
        self._term_tabs.setStyleSheet(
            f"QTabWidget::pane{{border:1px solid {C['border']};border-radius:6px;}}"
            f"QTabBar::tab{{background:{C['surface2']};color:{C['dim']};padding:6px 14px;margin-right:2px;border-radius:4px 4px 0 0;font-family:monospace;font-size:11px;}}"
            f"QTabBar::tab:selected{{background:{C['bg']};color:{C['fg']};}}"
            f"QTabBar::tab:hover{{background:{C['card']};color:{C['fg']};}}"
        )
        term_l.addWidget(self._term_tabs)
        self._term_tab_index = 0
        self._add_terminal_tab("Terminal 1")

        self._term_box = term_box
        outer.addWidget(term_box)

        global RUN_CMD_HANDLER
        RUN_CMD_HANDLER = self._run_in_terminal

        QShortcut(Qt.Key.Key_Escape, self).activated.connect(self._close_detail)
        self._sw.mousePressEvent = lambda e: (self._close_detail(), QWidget.mousePressEvent(self._sw, e))

        self._cat_pairs = []
        self._build()
        self._build_wiki()

        # sticky quick-close button (always visible while details are open)
        self._quick_close_btn = QPushButton("Close details")
        self._quick_close_btn.setParent(self)
        self._quick_close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._quick_close_btn.setStyleSheet(
            f"QPushButton{{background:{C['surface2']};border:1px solid {C['red']}66;border-radius:10px;"
            f"color:{C['red']};font-size:12px;font-family:monospace;padding:7px 12px;}}"
            f"QPushButton:hover{{background:{C['red']}22;border-color:{C['red']};color:{C['fg']};}}"
        )
        self._quick_close_btn.clicked.connect(self._close_detail)
        self._quick_close_btn.hide()
        self._position_quick_close_btn()

        self._maybe_show_onboarding(force=False)

    # ── helpers ──

    def _load_target_history(self):
        hist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".target_history.json")
        try:
            if os.path.exists(hist_path):
                with open(hist_path, "r", encoding="utf-8") as f:
                    history = json.load(f)
                self._target_history.addItems(history)
        except Exception:
            pass

    def _save_current_target(self):
        target = self._target_history.lineEdit().text().strip()
        if not target: return
        hist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".target_history.json")
        history = []
        try:
            if os.path.exists(hist_path):
                with open(hist_path, "r", encoding="utf-8") as f:
                    history = json.load(f)
        except Exception:
            pass
        if target in history:
            history.remove(target)
        history.insert(0, target)
        history = history[:20]
        try:
            with open(hist_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass
        self._target_history.clear()
        self._target_history.addItems(history)
        self._target_history.lineEdit().setText(target)

    def _on_target_selected(self, idx):
        target = self._target_history.itemText(idx)
        self._target_history.lineEdit().setText(target)
        self._save_current_target()

    def _close_detail(self):
        if self._selected_key:
            for c in self._all_cards:
                if c.key == self._selected_key: c.set_selected(False)
            self._selected_key = None
            self._detail.hide()
            self._quick_close_btn.hide()

    def _position_quick_close_btn(self):
        m = 18
        w = 160
        h = 38
        self._quick_close_btn.setFixedSize(w, h)
        x = max(m, self.width() - w - m)
        y = max(m, 86)
        self._quick_close_btn.move(x, y)
        self._quick_close_btn.raise_()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_quick_close_btn()

    def _maybe_show_onboarding(self, force=False):
        marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".onboarding_seen")
        if (not force) and os.path.exists(marker):
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Welcome to FG-Dist Pentool beta")
        dlg.resize(640, 360)
        lay = QVBoxLayout(dlg)

        title = QLabel("FG-Dist Quick Start")
        title.setStyleSheet(f"font-size:18px;color:{C['green']};font-family:monospace;font-weight:bold;")
        lay.addWidget(title)

        tips = QTextEdit()
        tips.setReadOnly(True)
        tips.setStyleSheet(
            f"QTextEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:8px;padding:10px;"
            f"color:{C['fg']};font-family:monospace;font-size:12px;}}"
        )
        tips.setPlainText(
            "1) Click any tool card to open full details\n"
            "2) Close details with: Esc, clicking the same card, or Close details button\n"
            "3) Use the embedded terminal (root mode by default — commands run with sudo)\n"
            "4) Toggle terminal visibility with ▼ hide / ▲ show\n"
            "5) Use '+ queue' and 'run queue' for multi-step workflows\n"
            "6) Use 'install missing' to install all tools at once\n"
            "7) Use 'health' for installed/missing/broken overview"
        )
        lay.addWidget(tips)

        dont_show = QCheckBox("Don't show this again")
        dont_show.setChecked(True)
        dont_show.setStyleSheet(f"color:{C['soft']};font-family:monospace;font-size:11px;")
        lay.addWidget(dont_show)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        got_it = QPushButton("Got it")
        got_it.setStyleSheet(_BTN_P)
        got_it.clicked.connect(dlg.accept)
        btn_row.addWidget(got_it)
        lay.addLayout(btn_row)

        dlg.exec()

        if dont_show.isChecked():
            try:
                with open(marker, "w", encoding="utf-8") as f:
                    f.write("seen\n")
            except Exception:
                pass

    def _set_theme_from_ui(self, theme_name):
        if theme_name not in THEMES:
            return
        if UI_CONFIG.get("theme") == theme_name and not UI_CONFIG.get("auto_day_night", False):
            return
        UI_CONFIG["theme"] = theme_name
        save_ui_config(UI_CONFIG)
        apply_theme_profile(effective_theme_name(UI_CONFIG))
        app = QApplication.instance()
        if app is not None:
            apply_theme(app)
        self._append_terminal(f"[theme] switched to {effective_theme_name(UI_CONFIG)}. applying live...\n")
        self._reopen_with_theme()

    def _open_settings_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Settings")
        dlg.resize(520, 320)
        lay = QVBoxLayout(dlg)

        title = QLabel("FG-Dist Settings")
        title.setStyleSheet(f"font-size:18px;color:{C['green']};font-family:monospace;font-weight:bold;")
        lay.addWidget(title)

        theme_row = QHBoxLayout()
        theme_lbl = QLabel("Theme")
        theme_lbl.setStyleSheet(f"font-size:12px;color:{C['text']};font-family:monospace;")
        theme_combo = QComboBox()
        theme_combo.addItems(list(THEMES.keys()))
        theme_combo.setCurrentText(UI_CONFIG.get("theme", "Neon"))
        theme_combo.setStyleSheet(
            f"QComboBox{{background:{C['surface']};border:1px solid {C['border']};border-radius:8px;padding:6px 10px;color:{C['fg']};font-size:12px;font-family:monospace;min-width:140px;}}"
            f"QComboBox::drop-down{{border:0;}}"
        )
        theme_row.addWidget(theme_lbl)
        theme_row.addStretch()
        theme_row.addWidget(theme_combo)
        lay.addLayout(theme_row)

        preview_row = QHBoxLayout()
        preview_row.setSpacing(8)
        for tname, tcolors in THEMES.items():
            b = QPushButton(tname)
            b.setStyleSheet(
                f"QPushButton{{background:{tcolors['surface']};border:1px solid {tcolors['green']}66;"
                f"border-radius:8px;color:{tcolors['fg']};font-family:monospace;font-size:11px;padding:8px 10px;}}"
                f"QPushButton:hover{{border-color:{tcolors['blue']};}}"
            )
            b.clicked.connect(lambda checked, n=tname: theme_combo.setCurrentText(n))
            preview_row.addWidget(b)
        lay.addLayout(preview_row)

        scale_row = QHBoxLayout()
        scale_lbl = QLabel("Font scale")
        scale_lbl.setStyleSheet(f"font-size:12px;color:{C['text']};font-family:monospace;")
        scale_combo = QComboBox()
        scales = ["90%", "100%", "110%", "125%", "140%"]
        scale_combo.addItems(scales)
        current_scale = int(UI_CONFIG.get("font_scale", 100))
        if current_scale not in (90, 100, 110, 125, 140):
            current_scale = 100
        scale_combo.setCurrentText(f"{current_scale}%")
        scale_combo.setStyleSheet(
            f"QComboBox{{background:{C['surface']};border:1px solid {C['border']};border-radius:8px;padding:6px 10px;color:{C['fg']};font-size:12px;font-family:monospace;min-width:140px;}}"
            f"QComboBox::drop-down{{border:0;}}"
        )
        scale_row.addWidget(scale_lbl)
        scale_row.addStretch()
        scale_row.addWidget(scale_combo)
        lay.addLayout(scale_row)

        icon_row = QHBoxLayout()
        icon_lbl = QLabel("Icon style")
        icon_lbl.setStyleSheet(f"font-size:12px;color:{C['text']};font-family:monospace;")
        icon_combo = QComboBox()
        icon_combo.addItems(["minimal", "cyber"])
        icon_combo.setCurrentText(UI_CONFIG.get("icon_style", "minimal"))
        icon_combo.setStyleSheet(
            f"QComboBox{{background:{C['surface']};border:1px solid {C['border']};border-radius:8px;padding:6px 10px;color:{C['fg']};font-size:12px;font-family:monospace;min-width:140px;}}"
            f"QComboBox::drop-down{{border:0;}}"
        )
        icon_row.addWidget(icon_lbl)
        icon_row.addStretch()
        icon_row.addWidget(icon_combo)
        lay.addLayout(icon_row)

        auto_dn = QCheckBox("Auto day/night theme (Light by day, Stealth by night)")
        auto_dn.setChecked(bool(UI_CONFIG.get("auto_day_night", False)))
        auto_dn.setStyleSheet(f"color:{C['soft']};font-family:monospace;font-size:11px;")
        lay.addWidget(auto_dn)

        reset_onboarding = QCheckBox("Show onboarding on next launch")
        reset_onboarding.setChecked(False)
        reset_onboarding.setStyleSheet(f"color:{C['soft']};font-family:monospace;font-size:11px;")
        lay.addWidget(reset_onboarding)

        btns = QHBoxLayout()
        btns.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setStyleSheet(_BTN)
        cancel.clicked.connect(dlg.reject)
        apply_btn = QPushButton("Apply")
        apply_btn.setStyleSheet(_BTN_P)
        apply_btn.clicked.connect(dlg.accept)
        btns.addWidget(cancel)
        btns.addWidget(apply_btn)
        lay.addLayout(btns)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        selected_theme = theme_combo.currentText()
        selected_scale = int(scale_combo.currentText().replace("%", ""))
        UI_CONFIG["theme"] = selected_theme
        UI_CONFIG["font_scale"] = selected_scale
        UI_CONFIG["auto_day_night"] = auto_dn.isChecked()
        UI_CONFIG["icon_style"] = icon_combo.currentText()
        save_ui_config(UI_CONFIG)

        marker = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".onboarding_seen")
        if reset_onboarding.isChecked() and os.path.exists(marker):
            try:
                os.remove(marker)
            except Exception:
                pass

        apply_theme_profile(effective_theme_name(UI_CONFIG))
        app = QApplication.instance()
        if app is not None:
            apply_theme(app)
        self._append_terminal(
            f"[settings] theme={effective_theme_name(UI_CONFIG)}, scale={selected_scale}%, "
            f"auto_day_night={UI_CONFIG['auto_day_night']}, icon_style={UI_CONFIG['icon_style']} applied\n"
        )
        self._reopen_with_theme()

    def _reopen_with_theme(self):
        g = self.geometry()
        old = self
        new_win = MainWindow()
        new_win.setGeometry(g)
        new_win.show()
        old.close()

    def _install_desktop_launcher(self):
        app_dir = os.path.dirname(os.path.abspath(__file__))
        desktop_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "applications")
        os.makedirs(desktop_dir, exist_ok=True)
        desktop_path = os.path.join(desktop_dir, "fg-dist-pentool-beta.desktop")
        icon_path = get_icon_path()
        exec_path = os.path.join(app_dir, "run_desktop.sh")

        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Version=1.0\n"
            "Name=FG-Dist Pentool beta\n"
            "Comment=Desktop Security Workbench\n"
            f"Exec={exec_path}\n"
            f"Path={app_dir}\n"
            f"Icon={icon_path}\n"
            "Terminal=false\n"
            "Categories=Development;Security;Utility;\n"
            "StartupNotify=true\n"
        )
        try:
            with open(desktop_path, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(desktop_path, 0o755)
            self._append_terminal(f"[launcher] installed: {desktop_path}\n")
        except Exception as e:
            self._append_terminal(f"[launcher] failed: {e}\n")

    def _update_stats(self):
        total = len(TOOL_WIKI)
        installed = sum(1 for k in TOOL_WIKI if check_installed(k))
        self._stats.setText(f'<span style="color:{C["green"]};">● {installed}</span>  / {total}')

    def _refresh_status(self):
        self._close_detail(); self._update_stats(); self._rebuild()
        # rebuild wiki too
        while self._wiki_sl.count(): w = self._wiki_sl.takeAt(0); (w.widget() and w.widget().deleteLater())
        self._build_wiki()

    def _rebuild(self):
        for h, b in self._cat_pairs: b.setParent(None); h.setParent(None)
        self._cat_pairs.clear(); self._all_cards.clear(); self._build()

    def _install_missing(self):
        d = os.path.dirname(os.path.abspath(__file__))
        s = os.path.join(d, "install_tools.sh")
        if not os.path.exists(s):
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Error", f"install_tools.sh not found at:\n{s}"); return
        self._start_installer_with_live_log(s)

    def _start_installer_with_live_log(self, script_path):
        d = os.path.dirname(script_path)
        logs_dir = os.path.join(d, "logs")
        os.makedirs(logs_dir, exist_ok=True)

        existing = set()
        try:
            existing = set(os.listdir(logs_dir))
        except Exception:
            pass

        self._append_terminal("\n[installer] opening system terminal for sudo prompts...\n")
        self._append_terminal("[installer] waiting for log file and streaming output here...\n")

        launched = launch_terminal(f"bash '{script_path}'")
        if not launched:
            self._append_terminal("[error] could not open external terminal\n")
            return

        self._stop_log_tail()
        stop_event = threading.Event()
        self._log_tail_stop = stop_event

        def tail_worker():
            log_path = None
            deadline = time.time() + 300
            while time.time() < deadline and not stop_event.is_set() and log_path is None:
                try:
                    files = [f for f in os.listdir(logs_dir) if f.startswith("install_") and f.endswith(".log")]
                    files.sort(key=lambda fn: os.path.getmtime(os.path.join(logs_dir, fn)), reverse=True)
                    for fn in files:
                        if fn not in existing:
                            log_path = os.path.join(logs_dir, fn)
                            break
                    if log_path is None and files:
                        # fallback: follow newest file if installer reused existing naming pattern
                        newest = os.path.join(logs_dir, files[0])
                        if os.path.getsize(newest) > 0:
                            log_path = newest
                except Exception:
                    pass
                if log_path is None:
                    time.sleep(0.5)

            if log_path is None:
                QTimer.singleShot(0, lambda: self._append_terminal("[installer] no log file appeared in time\n"))
                return

            QTimer.singleShot(0, lambda p=log_path: self._append_terminal(f"[installer] following {p}\n"))

            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    while not stop_event.is_set():
                        line = f.readline()
                        if line:
                            QTimer.singleShot(0, lambda ln=line: self._append_terminal(ln))
                            if "[✓] installation completed" in line or "[!] completed with failures" in line:
                                break
                        else:
                            time.sleep(0.2)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._append_terminal(f"[installer] log tail error: {e}\n"))
                return

            QTimer.singleShot(0, lambda: self._append_terminal("[installer] log streaming finished\n"))

        threading.Thread(target=tail_worker, daemon=True).start()

    def _stop_log_tail(self):
        if self._log_tail_stop is not None:
            self._log_tail_stop.set()
            self._log_tail_stop = None

    def _append_terminal(self, text):
        idx = self._term_tabs.currentIndex()
        if idx < 0: return
        widget = self._term_tabs.widget(idx)
        if not widget: return
        out = widget.findChild(QTextEdit, "term_out")
        if out:
            out.insertPlainText(text)
            sb = out.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _get_active_terminal(self):
        idx = self._term_tabs.currentIndex()
        if idx < 0: return None, None, None
        widget = self._term_tabs.widget(idx)
        if not widget: return None, None, None
        out = widget.findChild(QTextEdit, "term_out")
        inp = widget.findChild(QLineEdit, "term_in")
        return widget, out, inp

    def _clear_active_terminal(self):
        _, out, _ = self._get_active_terminal()
        if out: out.clear()

    def _add_terminal_tab(self, name=None):
        self._term_tab_index += 1
        tab_name = name or f"Terminal {self._term_tab_index}"
        tab_widget = QWidget()
        tab_widget._queue = []
        tab_widget._queue_running = False
        tab_widget._proc = None
        lay = QVBoxLayout(tab_widget)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(6)

        out = QTextEdit()
        out.setObjectName("term_out")
        out.setReadOnly(True)
        out.setMinimumHeight(200)
        out.setStyleSheet(
            f"QTextEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:6px;padding:8px;color:{C['fg']};font-family:monospace;font-size:12px;}}"
        )
        lay.addWidget(out)

        term_in_row = QHBoxLayout()
        inp = QLineEdit()
        inp.setObjectName("term_in")
        inp.setPlaceholderText("run command (root by default)…")
        inp.setStyleSheet(
            f"QLineEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:8px;padding:9px 12px;color:{C['fg']};font-family:monospace;font-size:12px;}}"
        )
        inp.returnPressed.connect(lambda: self._run_from_input())
        run_btn = QPushButton("▶ run")
        run_btn.setStyleSheet(_BTN_P)
        run_btn.clicked.connect(lambda: self._run_from_input())
        q_add_btn = QPushButton("+ queue")
        q_add_btn.setStyleSheet(_BTN)
        q_add_btn.clicked.connect(lambda: self._queue_from_input())
        q_run_btn = QPushButton("run queue")
        q_run_btn.setStyleSheet(_BTN_O)
        q_run_btn.clicked.connect(lambda: self._run_queue())
        term_in_row.addWidget(inp)
        term_in_row.addWidget(run_btn)
        term_in_row.addWidget(q_add_btn)
        term_in_row.addWidget(q_run_btn)
        lay.addLayout(term_in_row)

        queue_lbl = QLabel("queue: 0")
        queue_lbl.setObjectName("queue_lbl")
        queue_lbl.setStyleSheet(f"font-size:11px;color:{C['dim']};font-family:monospace;")
        lay.addWidget(queue_lbl)

        tab_idx = self._term_tabs.addTab(tab_widget, tab_name)
        self._term_tabs.setCurrentIndex(tab_idx)
        inp.setFocus()

    def _close_terminal_tab(self, idx):
        if self._term_tabs.count() <= 1:
            return
        widget = self._term_tabs.widget(idx)
        if widget:
            proc = getattr(widget, "_proc", None)
            if proc and proc.poll() is None:
                try: proc.terminate()
                except: pass
        self._term_tabs.removeTab(idx)

    def _toggle_terminal(self):
        self._term_visible = not self._term_visible
        self._term_box.setVisible(self._term_visible)
        self._term_toggle_btn.setText("▲ show" if not self._term_visible else "▼ hide")

    def _toggle_root(self):
        self._root_mode = self._root_btn.isChecked()
        self._root_btn.setText("🔓 root" if self._root_mode else "🔒 user")
        self._update_terminal_placeholders()

    def _update_terminal_placeholders(self):
        txt = "run command (root by default)…" if self._root_mode else "run command (user mode)…"
        for i in range(self._term_tabs.count()):
            w = self._term_tabs.widget(i)
            if w:
                inp = w.findChild(QLineEdit, "term_in")
                if inp: inp.setPlaceholderText(txt)

    def _update_queue_label(self):
        _, _, _ = self._get_active_terminal()
        for i in range(self._term_tabs.count()):
            w = self._term_tabs.widget(i)
            if w:
                lbl = w.findChild(QLabel, "queue_lbl")
                if lbl:
                    state = "running" if getattr(w, "_queue_running", False) else "idle"
                    q = getattr(w, "_queue", [])
                    lbl.setText(f"queue: {len(q)} ({state})")

    def _stop_terminal_cmd(self):
        self._stop_log_tail()
        for i in range(self._term_tabs.count()):
            w = self._term_tabs.widget(i)
            if w:
                w._queue_running = False
                proc = getattr(w, "_proc", None)
                if proc and proc.poll() is None:
                    try: proc.terminate()
                    except: pass
        _, out, _ = self._get_active_terminal()
        if out: out.insertPlainText("\n[stopped]\n")

    def _run_from_input(self):
        _, _, inp = self._get_active_terminal()
        if not inp: return
        cmd = inp.text().strip()
        if not cmd: return
        target = self._target_history.lineEdit().text().strip()
        if target:
            cmd = cmd.replace("<target>", target).replace("<domain>", target)
        self._run_in_terminal(cmd)

    def _queue_from_input(self):
        _, _, inp = self._get_active_terminal()
        if not inp: return
        cmd = inp.text().strip()
        if not cmd: return
        target = self._target_history.lineEdit().text().strip()
        if target:
            cmd = cmd.replace("<target>", target).replace("<domain>", target)
        idx = self._term_tabs.currentIndex()
        w = self._term_tabs.widget(idx)
        if not hasattr(w, "_queue"): w._queue = []
        w._queue.append(cmd)
        self._append_terminal(f"[queue] added: {cmd}\n")
        inp.clear()
        self._update_queue_label()

    def _run_queue(self):
        idx = self._term_tabs.currentIndex()
        w = self._term_tabs.widget(idx)
        if not w: return
        if getattr(w, "_queue_running", False):
            self._append_terminal("[queue] already running\n")
            return
        if not hasattr(w, "_queue") or not w._queue:
            self._append_terminal("[queue] empty\n")
            return
        w._queue_running = True
        self._update_queue_label()
        self._append_terminal(f"[queue] starting {len(w._queue)} command(s)\n")
        self._run_next_queued()

    def _run_next_queued(self):
        idx = self._term_tabs.currentIndex()
        w = self._term_tabs.widget(idx)
        if not w: return
        if not getattr(w, "_queue_running", False): return
        if getattr(w, "_proc", None) and w._proc.poll() is None: return
        if not w._queue:
            w._queue_running = False
            self._update_queue_label()
            self._append_terminal("[queue] finished\n")
            return
        cmd = w._queue.pop(0)
        self._update_queue_label()
        self._run_in_terminal(cmd, on_done=lambda code: self._run_next_queued())

    def _run_in_terminal(self, cmd, on_done=None):
        if not cmd: return False
        idx = self._term_tabs.currentIndex()
        w = self._term_tabs.widget(idx)
        if not w: return False
        _, out, _ = self._get_active_terminal()
        if getattr(w, "_proc", None) and w._proc.poll() is None:
            if out: out.insertPlainText("\n[busy] stop current command first\n")
            return False

        # root mode: prepend sudo if not already present
        if self._root_mode and not cmd.startswith("sudo "):
            run_cmd = f"sudo {cmd}"
        else:
            run_cmd = cmd

        if out: out.insertPlainText(f"\n$ {run_cmd}\n")

        # Track live status for tool cards
        tool_key = self._find_tool_key_for_command(cmd)
        if tool_key:
            self._set_tool_status(tool_key, "running")

        try:
            w._proc = subprocess.Popen(
                ["bash", "-lc", run_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            if out: out.insertPlainText(f"[error] {e}\n")
            return False

        def reader(proc, widget, tk=tool_key):
            try:
                for line in iter(proc.stdout.readline, ""):
                    QTimer.singleShot(0, lambda ln=line: self._append_terminal(ln))
            finally:
                proc.wait()
                code = proc.returncode
                def finish(code=code, cb=on_done, w=widget, key=tk):
                    if out: out.insertPlainText(f"\n[done] exit={code}\n")
                    if key: self._set_tool_status(key, "idle")
                    if cb: cb(code)
                QTimer.singleShot(0, finish)

        threading.Thread(target=reader, args=(w._proc, w), daemon=True).start()
        return True

    def _find_tool_key_for_command(self, cmd):
        base = cmd.split()[0].lower() if cmd else ""
        for key, val in TOOL_CMDS.items():
            if val.lower().startswith(base) or key.lower() == base:
                return key
        return None

    def _set_tool_status(self, key, status):
        for card in self._all_cards:
            if card.key == key:
                card.set_status(status)
                break

    def _save_terminal_session(self):
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(reports_dir, f"terminal_session_{ts}.log")
        try:
            with open(path, "w", encoding="utf-8") as f:
                for i in range(self._term_tabs.count()):
                    w = self._term_tabs.widget(i)
                    if w:
                        out = w.findChild(QTextEdit, "term_out")
                        if out:
                            f.write(f"--- {self._term_tabs.tabText(i)} ---\n")
                            f.write(out.toPlainText())
                            f.write("\n\n")
            self._append_terminal(f"[saved] {path}\n")
        except Exception as e:
            self._append_terminal(f"[error] save failed: {e}\n")

    def _show_health_dashboard(self):
        rows = []
        installed = 0
        missing = 0
        broken = 0

        for key in sorted(TOOL_WIKI.keys(), key=lambda s: s.lower()):
            cmd = TOOL_CMDS.get(key, "")
            ok = check_installed(key)
            state = "installed"
            if ok:
                installed += 1
                if cmd.startswith("python3 ") or cmd.startswith("bash "):
                    script_path = cmd.split(" ", 1)[1]
                    if script_path.startswith("/") and not os.path.exists(script_path):
                        state = "broken"
                        broken += 1
            else:
                state = "missing"
                missing += 1
            rows.append((key, TOOL_CATEGORY.get(key, ""), state, cmd))

        dlg = QDialog(self)
        dlg.setWindowTitle("Tool Health Dashboard")
        dlg.resize(980, 700)
        lay = QVBoxLayout(dlg)
        summary = QLabel(f"installed: {installed}   missing: {missing}   broken: {broken}")
        summary.setStyleSheet(f"font-size:13px;color:{C['green']};font-family:monospace;")
        lay.addWidget(summary)
        out = QTextEdit()
        out.setReadOnly(True)
        out.setStyleSheet(
            f"QTextEdit{{background:{C['bg']};border:1px solid {C['border']};border-radius:8px;padding:10px;color:{C['fg']};font-family:monospace;font-size:12px;}}"
        )
        lines = ["name | category | state | command", "-" * 120]
        for name, cat, st, cmd in rows:
            lines.append(f"{name} | {cat} | {st} | {cmd}")
        out.setPlainText("\n".join(lines))
        lay.addWidget(out)
        dlg.exec()

    def _load_favorites(self):
        fav_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".favorites.json")
        try:
            if os.path.exists(fav_path):
                with open(fav_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception: pass
        return []

    def _save_favorites(self, favs):
        fav_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".favorites.json")
        try:
            with open(fav_path, "w", encoding="utf-8") as f:
                json.dump(favs, f, indent=2)
        except Exception: pass

    def _toggle_favorite(self, key):
        favs = self._load_favorites()
        if key in favs:
            favs.remove(key)
        else:
            favs.insert(0, key)
        self._save_favorites(favs)
        self._rebuild()

    def _show_macros_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Quick Macros")
        dlg.resize(500, 400)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel("Select a macro to run on the current target:"))
        
        macros = {
            "Quick Recon": ["nmap -sV -sC -p- <target>", "nuclei -u https://<target>", "gowitness file -f urls.txt"],
            "Web App Audit": ["nmap -p 80,443 --script vuln <target>", "sqlmap -u 'http://<target>/page?id=1' --batch", "nuclei -u https://<target> -t cves/"],
            "AD Internal": ["nxc smb <target> -u user -p pass", "bloodhound-python -d <domain> -u user -p pass -c All", "responder -I eth0 -wrf"],
            "WiFi Audit": ["sudo airodump-ng wlan0mon", "sudo wifite2", "sudo reaver -i wlan0mon -b <BSSID> -vv"],
        }

        for name, cmds in macros.items():
            btn = QPushButton(f"▶ {name}")
            btn.setStyleSheet(_BTN_P)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, c=cmds: (self._run_macro(c), dlg.accept()))
            lay.addWidget(btn)
            
            desc = QLabel(" → " + "\n → ".join(cmds))
            desc.setStyleSheet(f"color:{C['dim']};font-size:10px;font-family:monospace;padding-left:10px;")
            desc.setWordWrap(True)
            lay.addWidget(desc)

        lay.addStretch()
        dlg.exec()

    def _run_macro(self, cmds):
        target = self._target_history.lineEdit().text().strip() or "<target>"
        idx = self._term_tabs.currentIndex()
        w = self._term_tabs.widget(idx)
        if not w: return
        if not hasattr(w, "_queue"): w._queue = []
        for cmd in cmds:
            safe_cmd = cmd.replace("<target>", target).replace("<domain>", target).replace("<BSSID>", target)
            w._queue.append(safe_cmd)
        self._append_terminal(f"[macro] added {len(cmds)} commands to queue\n")
        self._run_queue()

    def _generate_report(self):
        target = self._target_history.lineEdit().text().strip() or "unknown"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        path = os.path.join(reports_dir, f"report_{target}_{ts}.md")
        
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# FG-Dist Pentool Report\n")
                f.write(f"**Target:** {target}  \n**Date:** {ts}\n\n")
                f.write("## Terminal Sessions\n\n")
                for i in range(self._term_tabs.count()):
                    w = self._term_tabs.widget(i)
                    if w:
                        out = w.findChild(QTextEdit, "term_out")
                        if out:
                            f.write(f"### {self._term_tabs.tabText(i)}\n```\n{out.toPlainText()}\n```\n\n")
            self._append_terminal(f"[report] saved to {path}\n")
        except Exception as e:
            self._append_terminal(f"[error] report failed: {e}\n")

    # ── tools grid ──

    def _build(self):
        # Favorites section
        favs = self._load_favorites()
        if favs:
            fav_header = QLabel("⭐  Favorites")
            fav_header.setStyleSheet(f"font-size:13px;color:{C['yellow']};font-family:monospace;padding:8px 12px;background:{C['surface']};border:1px solid {C['border']};border-radius:8px;")
            self._sl.addWidget(fav_header)
            
            fav_grid = QGridLayout()
            fav_grid.setContentsMargins(4,4,4,4); fav_grid.setSpacing(5)
            fav_cols = 3
            for idx, key in enumerate(favs):
                if key in TOOL_WIKI:
                    t = TOOL_WIKI[key]
                    card = ToolCard(key, key, t.get("desc",""))
                    card.clicked.connect(self._on_click)
                    card.context_menu_requested.connect(self._show_tool_context_menu)
                    fav_grid.addWidget(card, idx // fav_cols, idx % fav_cols)
                    self._all_cards.append(card)
            self._sl.addWidget(QWidget()) # spacer
            fav_widget = QWidget()
            fav_widget.setLayout(fav_grid)
            self._sl.addWidget(fav_widget)

        for cat, tools in CATEGORIES.items():
            open_ = cat in ("Recon & OSINT","Scanning & Enumeration","Exploitation","Web Testing")
            header = QPushButton()
            header._open = open_
            header.setCursor(Qt.CursorShape.PointingHandCursor)
            header.setStyleSheet(
                f"QPushButton{{text-align:left;background:{C['surface']};border:1px solid {C['border']};"
                f"border-radius:10px;padding:12px 16px;font-size:13px;color:{C['text']};font-family:monospace;}}"
                f"QPushButton:hover{{border:1px solid {C['green']}66;}}"
            )
            header.setText(f"{'▾' if open_ else '▸'}  {cat}  [{len(tools)}]")

            body = AnimatedBody()
            body.set_open(open_, animate=False)
            grid = QGridLayout()
            body._content.addLayout(grid)
            grid.setContentsMargins(4,4,4,4); grid.setSpacing(5)
            items = list(tools.items())
            cols = 3
            for idx, (name, t) in enumerate(items):
                card = ToolCard(t["wiki"], name, t["desc"])
                card.clicked.connect(self._on_click)
                card.context_menu_requested.connect(self._show_tool_context_menu)
                grid.addWidget(card, idx // cols, idx % cols)
                self._all_cards.append(card)

            header.clicked.connect(lambda checked, h=header, b=body: (
                setattr(h, '_open', not h._open),
                h.setText(f"{'▾' if h._open else '▸'}  {h.text()[2:]}"),
                b.set_open(h._open)
            ))
            self._sl.addWidget(header)
            self._sl.addWidget(body)
            self._cat_pairs.append((header, body))

    def _show_tool_context_menu(self, key, pos):
        menu = QMenu(self)
        is_fav = key in self._load_favorites()
        fav_action = QAction("⭐ Remove from Favorites" if is_fav else "☆ Add to Favorites", self)
        fav_action.triggered.connect(lambda: self._toggle_favorite(key))
        menu.addAction(fav_action)
        
        run_action = QAction("▶ Run", self)
        run_action.triggered.connect(lambda: self._run_in_terminal(TOOL_CMDS.get(key, key)))
        menu.addAction(run_action)
        
        copy_action = QAction("📋 Copy Command", self)
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(TOOL_CMDS.get(key, key)))
        menu.addAction(copy_action)
        
        docs_action = QAction("📄 Open Docs", self)
        url = TOOL_WIKI.get(key, {}).get("url")
        if url:
            docs_action.triggered.connect(lambda: self._open_url(url))
        else:
            docs_action.setEnabled(False)
        menu.addAction(docs_action)
        
        menu.exec(self.mapToGlobal(pos))

    def _on_click(self, key):
        if self._selected_key == key: self._close_detail(); return
        for c in self._all_cards: c.set_selected(c.key == key)
        self._selected_key = key; self._detail.show_tool(key)
        self._quick_close_btn.show()
        self._position_quick_close_btn()

    def _filter(self):
        q = self._search.text().lower().strip()
        for h, b in self._cat_pairs:
            if not q:
                h.setVisible(True); b.setVisible(getattr(h, '_open', True))
                for c in b.findChildren(ToolCard): c.setVisible(True)
                continue
            found = False
            for c in b.findChildren(ToolCard):
                m = q in c.key.lower() or q in c._name.lower()
                c.setVisible(m)
                if m: found = True
            if found: b.setVisible(True); h.setVisible(True)
            else: b.setVisible(False); h.setVisible(False)

    # ── wiki view ──

    def _toggle_wiki(self):
        self._wiki_mode = not self._wiki_mode
        self._close_detail()
        self._stack.setCurrentIndex(1 if self._wiki_mode else 0)
        self._wiki_btn.setText("📖 tools" if self._wiki_mode else "📖 wiki")
        self._search.clear()
        if hasattr(self, '_wiki_search'):
            self._wiki_search.clear()
        if hasattr(self, '_wiki_active_cat'):
            self._wiki_active_cat = ""
            for btn in self._wiki_cat_btns:
                btn.setStyleSheet(_BTN_P if btn.text() == "all" else _BTN)
            for group in self._wiki_cat_groups.values():
                group.setVisible(True)
        self._quick_close_btn.hide()

    def _build_wiki(self):
        # wiki search bar
        wiki_search = QLineEdit()
        wiki_search.setPlaceholderText("🔍  search all tools by name, description, or example…")
        wiki_search.setStyleSheet(
            f"QLineEdit{{background:{C['surface']};border:1px solid {C['border']};border-radius:8px;"
            f"padding:8px 12px;color:{C['fg']};font-size:12px;font-family:monospace;}}"
            f"QLineEdit:focus{{border:1px solid {C['green']}88;}}"
        )
        wiki_search.textChanged.connect(self._filter_wiki)
        self._wiki_search = wiki_search
        self._wiki_sl.addWidget(wiki_search)

        # category filter buttons
        cat_bar = QHBoxLayout()
        cat_bar.setSpacing(6)
        all_btn = QPushButton("all")
        all_btn.setStyleSheet(_BTN_P)
        all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        all_btn.clicked.connect(lambda: self._filter_wiki_by_cat(""))
        cat_bar.addWidget(all_btn)
        self._wiki_cat_btns = [all_btn]
        for cat in CATEGORIES:
            btn = QPushButton(cat)
            btn.setStyleSheet(_BTN)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, c=cat: self._filter_wiki_by_cat(c))
            cat_bar.addWidget(btn)
            self._wiki_cat_btns.append(btn)
        cat_bar.addStretch()
        cat_wrap = QWidget()
        cat_wrap.setLayout(cat_bar)
        self._wiki_sl.addWidget(cat_wrap)

        # tool cards container
        self._wiki_cards_container = QWidget()
        self._wiki_cards_layout = QVBoxLayout(self._wiki_cards_container)
        self._wiki_cards_layout.setContentsMargins(0, 0, 0, 0)
        self._wiki_cards_layout.setSpacing(4)
        self._wiki_sl.addWidget(self._wiki_cards_container)

        self._wiki_cat_groups = {}
        for cat, tools in CATEGORIES.items():
            group = QWidget()
            gl = QVBoxLayout(group)
            gl.setContentsMargins(0, 8, 0, 4)
            gl.setSpacing(4)

            cat_header = QLabel(f"▸  {cat}  ({len(tools)} tools)")
            cat_header.setStyleSheet(
                f"font-size:13px;color:{C['text']};font-family:monospace;padding:8px 12px;"
                f"background:{C['surface']};border:1px solid {C['border']};border-radius:8px;"
            )
            gl.addWidget(cat_header)

            for name, t in tools.items():
                wk = t["wiki"]; w = TOOL_WIKI.get(wk, {}); cmd = TOOL_CMDS.get(wk, "")
                installed = check_installed(wk)
                badge_color = C["green"] if installed else C["dim"]
                badge_text = "● installed" if installed else "○ missing"

                card = QFrame()
                card.setStyleSheet(
                    f"QFrame{{background:{C['card']};border:1px solid {C['border']};border-radius:8px;}}"
                )
                cl = QVBoxLayout(card)
                cl.setContentsMargins(12, 10, 12, 10)
                cl.setSpacing(6)

                # name + badge row
                top_row = QHBoxLayout()
                name_lbl = QLabel(f'<span style="color:{C["blue"]};font-size:13px;font-weight:bold;font-family:monospace;">{name}</span>')
                name_lbl.setTextFormat(Qt.TextFormat.RichText)
                top_row.addWidget(name_lbl)
                top_row.addStretch()
                status_lbl = QLabel(f'<span style="color:{badge_color};font-size:10px;font-family:monospace;">{badge_text}</span>')
                status_lbl.setTextFormat(Qt.TextFormat.RichText)
                top_row.addWidget(status_lbl)

                if w.get("url"):
                    docs_btn = QPushButton("docs →")
                    docs_btn.setStyleSheet(
                        f"QPushButton{{background:transparent;border:1px solid {C['blue']}44;color:{C['blue']};"
                        f"border-radius:4px;padding:2px 8px;font-size:10px;font-family:monospace;}}"
                    )
                    docs_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                    docs_btn.clicked.connect(lambda checked, u=w["url"]: self._open_url(u))
                    top_row.addWidget(docs_btn)
                cl.addLayout(top_row)

                # description
                desc_lbl = QLabel(w.get("desc", ""))
                desc_lbl.setStyleSheet(
                    f"font-size:11px;color:{C['text']};font-family:monospace;padding:6px 10px;"
                    f"background:{C['bg']};border-radius:6px;border-left:3px solid {C['green']};"
                )
                desc_lbl.setWordWrap(True)
                cl.addWidget(desc_lbl)

                # command
                if cmd:
                    cmd_lbl = QLabel(f'<span style="color:{C["soft"]};font-family:monospace;font-size:10px;">CMD  </span>'
                                     f'<span style="color:{C["fg"]};font-family:monospace;font-size:10px;">{cmd}</span>')
                    cmd_lbl.setTextFormat(Qt.TextFormat.RichText)
                    cmd_lbl.setStyleSheet(f"padding:4px 10px;background:{C['bg']};border-radius:4px;")
                    cl.addWidget(cmd_lbl)

                # examples
                for ex in w.get("examples", []):
                    ex_row = QHBoxLayout()
                    ex_lbl = QLabel(f'<span style="color:{C["fg"]};font-family:monospace;font-size:10px;">$ {ex}</span>')
                    ex_lbl.setTextFormat(Qt.TextFormat.RichText)
                    ex_lbl.setWordWrap(True)
                    ex_row.addWidget(ex_lbl)
                    ex_row.addStretch()
                    cp_btn = QPushButton("copy")
                    cp_btn.setStyleSheet(
                        f"QPushButton{{background:transparent;border:1px solid {C['green']}44;color:{C['green']};"
                        f"border-radius:4px;padding:2px 6px;font-size:9px;font-family:monospace;}}"
                    )
                    cp_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                    cp_btn.clicked.connect(lambda checked, t=ex: QApplication.clipboard().setText(t))
                    ex_row.addWidget(cp_btn)
                    run_btn = QPushButton("▶")
                    run_btn.setStyleSheet(
                        f"QPushButton{{background:transparent;border:1px solid {C['orange']}44;color:{C['orange']};"
                        f"border-radius:4px;padding:2px 6px;font-size:9px;font-family:monospace;}}"
                    )
                    run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                    run_btn.clicked.connect(lambda checked, t=ex: run_command(t))
                    ex_row.addWidget(run_btn)
                    cl.addLayout(ex_row)

                gl.addWidget(card)

            self._wiki_cat_groups[cat] = group
            self._wiki_cards_layout.addWidget(group)

        self._wiki_cards_layout.addStretch()
        self._wiki_active_cat = ""

    def _open_url(self, url):
        import webbrowser
        webbrowser.open(url)

    def _filter_wiki_by_cat(self, cat):
        self._wiki_active_cat = cat
        for btn in self._wiki_cat_btns:
            is_active = (cat == "" and btn.text() == "all") or btn.text() == cat
            btn.setStyleSheet(_BTN_P if is_active else _BTN)
        for c, group in self._wiki_cat_groups.items():
            group.setVisible(cat == "" or c == cat)
        self._filter_wiki()

    def _filter_wiki(self):
        q = ""
        if hasattr(self, '_wiki_search'):
            q = self._wiki_search.text().lower().strip()
        for cat, group in self._wiki_cat_groups.items():
            if self._wiki_active_cat and cat != self._wiki_active_cat:
                group.setVisible(False)
                continue
            group.setVisible(True)
            if not q:
                for i in range(group.layout().count()):
                    w = group.layout().itemAt(i).widget()
                    if w: w.setVisible(True)
            else:
                for i in range(group.layout().count()):
                    w = group.layout().itemAt(i).widget()
                    if w and hasattr(w, 'toPlainText'):
                        w.setVisible(q in w.toPlainText().lower())
                    elif w and hasattr(w, 'text'):
                        w.setVisible(q in w.text().lower())

    def _on_search(self):
        if self._wiki_mode:
            if hasattr(self, '_wiki_search'):
                self._wiki_search.setText(self._search.text())
        else:
            self._filter()

# ────────────────────────────────────────────────────────────
#  ENTRY
# ────────────────────────────────────────────────────────────

apply_theme_profile(effective_theme_name(UI_CONFIG))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        app.setDesktopFileName("fg-dist-pentool-beta")
        app.setApplicationName("FG-Dist Pentool beta")
        app.setApplicationDisplayName("FG-Dist Pentool beta")
    except Exception:
        pass
    apply_theme(app)
    splash_pm = QPixmap(680, 320)
    splash_pm.fill(QColor(C["bg"]))
    p = QPainter(splash_pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    grad = QLinearGradient(0, 0, 680, 320)
    grad.setColorAt(0.0, QColor(C["surface2"]))
    grad.setColorAt(1.0, QColor(C["surface"]))
    p.fillRect(0, 0, 680, 320, QBrush(grad))
    p.setPen(QPen(QColor(C["green"]), 2))
    p.drawRoundedRect(12, 12, 656, 296, 14, 14)
    p.setPen(QColor(C["green"]))
    p.setFont(QFont("JetBrains Mono", 24, QFont.Weight.Bold))
    p.drawText(36, 125, "FG-Dist Pentool beta")
    p.setPen(QColor(C["soft"]))
    p.setFont(QFont("JetBrains Mono", 11))
    p.drawText(38, 160, "Desktop Security Workbench")
    p.setPen(QColor(C["dim"]))
    p.drawText(38, 286, f"Theme: {effective_theme_name(UI_CONFIG)}  |  loading modules...")
    icon_path = get_icon_path()
    if os.path.exists(icon_path):
        icon_pm = QPixmap(icon_path)
        if not icon_pm.isNull():
            icon_pm = icon_pm.scaled(88, 88, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            p.drawPixmap(560, 32, icon_pm)
    p.end()
    splash = QSplashScreen(splash_pm)
    splash.show()
    app.processEvents()
    base_font = 10.0
    scale = max(85, min(160, int(UI_CONFIG.get("font_scale", 100))))
    font_size = max(8, int(round(base_font * scale / 100.0)))
    font = QFont("JetBrains Mono", font_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)
    win = MainWindow()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    time.sleep(0.7)
    splash.finish(win)
    win.show()
    sys.exit(app.exec())
