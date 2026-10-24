# imap_config.py
# Loads IMAP server config from central PMJ imap database
# + lookup_imap_config() with parent domain fallback
import json
import os
import sys

# Central IMAP database path
# Production (Linux/VPS): /opt/pmj/imap/
# Development (Windows): C:\Users\Administrator\Desktop\PMJ\imap\
if sys.platform == "win32":
    IMAP_DB_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "PMJ", "imap")
else:
    IMAP_DB_DIR = "/opt/pmj/imap"

# Fallback: jika central dir belum ada, pakai local
if not os.path.isdir(IMAP_DB_DIR):
    IMAP_DB_DIR = os.path.dirname(os.path.abspath(__file__))

IMAP_CONFIG_PATH = os.path.join(IMAP_DB_DIR, "imap_config.json")
IMAP_SUCCESS_PATH = os.path.join(IMAP_DB_DIR, "imap_success.json")

# Load config: prioritaskan central database, fallback ke local repo jika kosong
DEFAULT_IMAP_CONFIG = {}
if os.path.exists(IMAP_CONFIG_PATH):
    try:
        with open(IMAP_CONFIG_PATH, "r", encoding="utf-8") as _f:
            DEFAULT_IMAP_CONFIG = json.load(_f)
    except Exception:
        DEFAULT_IMAP_CONFIG = {}

_local_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "imap_config.json")
if not DEFAULT_IMAP_CONFIG and os.path.exists(_local_cfg_path):
    try:
        with open(_local_cfg_path, "r", encoding="utf-8") as _f:
            DEFAULT_IMAP_CONFIG = json.load(_f)
        if DEFAULT_IMAP_CONFIG and os.path.isdir(IMAP_DB_DIR) and IMAP_CONFIG_PATH != _local_cfg_path:
            try:
                with open(IMAP_CONFIG_PATH, "w", encoding="utf-8") as _f:
                    json.dump(DEFAULT_IMAP_CONFIG, _f, indent=2)
            except Exception:
                pass
    except Exception:
        pass

# Country-code TLDs yang punya 2 bagian (ne.jp, co.uk, com.br, dll)
_CC_TLDS = {
    "ne.jp", "or.jp", "co.jp", "ac.jp", "gr.jp", "go.jp", "ad.jp", "ed.jp",
    "co.uk", "org.uk", "me.uk", "ac.uk",
    "co.id", "or.id", "ac.id", "go.id", "sch.id", "my.id", "web.id",
    "co.za", "org.za", "ac.za",
    "co.kr", "ac.kr", "or.kr",
    "co.in", "org.in", "ac.in",
    "co.nz", "org.nz", "ac.nz",
    "co.zw", "co.bw", "co.ke", "co.tz", "co.mz",
    "co.th", "ac.th", "or.th",
    "com.au", "org.au", "net.au", "edu.au",
    "com.br", "org.br", "net.br",
    "com.mx", "org.mx", "net.mx",
    "com.ar", "org.ar", "net.ar",
    "com.tr", "org.tr", "net.tr", "edu.tr",
    "com.tw", "org.tw", "net.tw", "edu.tw",
    "com.co", "org.co", "net.co", "edu.co",
    "com.pe", "org.pe", "net.pe", "edu.pe",
    "com.pk", "org.pk", "net.pk", "edu.pk",
    "com.my", "org.my", "net.my", "edu.my",
    "com.np", "org.np",
    "com.cn", "org.cn", "net.cn", "edu.cn",
    "com.es", "org.es",
    "com.hk", "org.hk",
    "com.ph", "org.ph", "edu.ph",
    "com.bd", "org.bd",
    "com.ve", "org.ve",
    "com.ec", "org.ec",
    "com.sa", "org.sa",
    "com.bo", "org.bo",
    "com.tn", "org.tn",
    "com.vn",
    "edu.ye",
    "gob.ec", "gob.mx", "gob.pe",
}


def _get_parent_domain(domain):
    """
    Ambil parent domain. Contoh:
      am.em-net.ne.jp  -> em-net.ne.jp
      sub.example.co.uk -> example.co.uk
      sub.example.com  -> example.com
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return None

    for i in range(len(parts) - 2, 0, -1):
        suffix = ".".join(parts[i:])
        if suffix in _CC_TLDS:
            parent = ".".join(parts[i-1:])
            if parent != domain:
                return parent
            return None

    parent = ".".join(parts[-2:])
    if parent != domain:
        return parent
    return None


def lookup_imap_config(domain, extra_configs=None):
    """
    Cari IMAP config untuk domain dengan fallback ke parent domain.
    """
    configs = DEFAULT_IMAP_CONFIG

    cfg = configs.get(domain)
    if cfg:
        return cfg

    if extra_configs:
        cfg = extra_configs.get(domain)
        if cfg:
            return cfg

    parent = _get_parent_domain(domain)
    if parent:
        cfg = configs.get(parent)
        if cfg:
            return cfg
        if extra_configs:
            cfg = extra_configs.get(parent)
            if cfg:
                return cfg

        grandparent = _get_parent_domain(parent)
        if grandparent:
            cfg = configs.get(grandparent)
            if cfg:
                return cfg
            if extra_configs:
                cfg = extra_configs.get(grandparent)
                if cfg:
                    return cfg

    return None


def load_imap_success():
    """Load imap_success.json dari central database."""
    if os.path.exists(IMAP_SUCCESS_PATH):
        try:
            with open(IMAP_SUCCESS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_imap_success(data):
    """Save imap_success.json ke central database."""
    try:
        os.makedirs(os.path.dirname(IMAP_SUCCESS_PATH), exist_ok=True)
        with open(IMAP_SUCCESS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


import socket, struct

def query_mx(domain, dns_server="8.8.8.8", timeout=2.0):
    """Raw stdlib DNS query for MX record."""
    # ponytail: minimal raw DNS MX query via stdlib socket; use dnspython if full DNSSEC/TCP fallback needed
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
        packet = header + qname + struct.pack("!HH", 15, 1)
        s.sendto(packet, (dns_server, 53))
        data, _ = s.recvfrom(1024)
        s.close()

        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None

        idx = 12
        while data[idx] != 0:
            if data[idx] >= 192:
                idx += 2
                break
            idx += data[idx] + 1
        else:
            idx += 1
        idx += 4

        def read_name(offset):
            parts = []
            visited = set()
            while True:
                if offset in visited: break
                visited.add(offset)
                if offset >= len(data): break
                b = data[offset]
                if b == 0:
                    offset += 1
                    break
                elif b >= 192:
                    ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
                    p_name, _ = read_name(ptr)
                    parts.append(p_name)
                    offset += 2
                    break
                else:
                    offset += 1
                    parts.append(data[offset:offset+b].decode('latin1', errors='replace'))
                    offset += b
            return ".".join(parts), offset

        mx_records = []
        for _ in range(ancount):
            if idx >= len(data): break
            _, idx = read_name(idx)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[idx:idx+10])
            idx += 10
            rdata_end = idx + rdlen
            if rtype == 15:
                pref = struct.unpack("!H", data[idx:idx+2])[0]
                name, _ = read_name(idx + 2)
                mx_records.append((pref, name.lower().rstrip(".")))
            idx = rdata_end

        if not mx_records:
            return None
        mx_records.sort(key=lambda x: x[0])
        return mx_records[0][1]
    except Exception:
        return None


DISALLOWED_MX_KEYWORDS = [
    # 1. OAuth / 2FA / Modern Auth required (Basic Auth permanently disabled)
    "google", "gmail", "googlemail", "aspmx",
    "outlook", "office365", "microsoft", "hotmail", "live.com", "msn.com",
    "zoho",
    "icloud", "apple",
    "yahoo", "ymail", "yahoodns",
    "protonmail", "proton.me",
    "tuta", "tutanota",
    "fastmail",

    # 2. Inbound Security / Spam Gateways (relays without IMAP mailboxes)
    "mimecast",
    "spamexperts",
    "barracuda",
    "proofpoint", "pphosted",
    "trendmicro",
    "mailinblack",
    "cloudflare",
    "hornetsecurity",
    "ironport",
    "fireeye",
    "messagelabs",
    "symantec",
    "sophos",
    "cleanmail",
    "antispam",
    "spamfilter",

    # 3. Dead / fake / unresponsive MX relays
    "generic-isp",
    "breakthur",
    "b5z.net",
    "secureserver.net",
]


import ssl

def verify_usable_imap(host, port=993, timeout=1.5):
    """Verify host responds with valid IMAP greeting (* OK) and allows LOGIN."""
    # ponytail: basic SSL banner verification; rejects gateways and non-IMAP servers
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket()
        s.settimeout(timeout)
        ss = ctx.wrap_socket(s)
        ss.connect((host, port))
        banner = ss.recv(512).decode("utf-8", errors="ignore")
        ss.close()
        if not banner.startswith("* OK") or "LOGINDISABLED" in banner:
            return False
        return True
    except Exception:
        return False


def probe_imap_port(host, port=993, timeout=1.5):
    """Backward-compatible alias using verify_usable_imap."""
    return verify_usable_imap(host, port=port, timeout=timeout)


def map_mx_to_imap(mx_host, domain=None):
    """Map known provider MX exchangers to their dedicated IMAP endpoints, strictly filtering useless/OAuth hosts."""
    # ponytail: known multi-tenant provider mappings + strict verification; extend as new providers surface
    if not mx_host:
        return None
    m = mx_host.lower()

    # Reject unsupported / OAuth / Gateway hosts immediately
    if any(k in m for k in DISALLOWED_MX_KEYWORDS):
        return None

    # Verified multi-tenant providers (all accept direct email:pass basic auth)
    if "ovh.net" in m or "ovh.com" in m:
        return {"server": "ssl0.ovh.net", "port": 993}
    if "hostinger" in m:
        return {"server": "imap.hostinger.com", "port": 993}
    if "stackmail.com" in m:
        return {"server": "imap.stackmail.com", "port": 993}
    if "mailhostbox.com" in m:
        return {"server": "imap.mailhostbox.com", "port": 993}
    if "hostedemail.com" in m:
        return {"server": "mail.hostedemail.com", "port": 993}
    if "aliyun.com" in m or "mxhichina.com" in m:
        return {"server": "imap.aliyun.com", "port": 993}
    if "kinghost.net" in m:
        return {"server": "imap.kinghost.net", "port": 993}
    if "simply.com" in m:
        return {"server": "mail.simply.com", "port": 993}
    if "one.com" in m:
        return {"server": "imap.one.com", "port": 993}
    if "mail.ru" in m:
        return {"server": "imap.mail.ru", "port": 993}
    if "yandex" in m:
        return {"server": "imap.yandex.com", "port": 993}
    if "zaq.ad.jp" in m or "zaq.ne.jp" in m:
        return {"server": "imap.jcom.zaq.ne.jp", "port": 993}
    if "mesh.ne.jp" in m or "biglobe.ne.jp" in m:
        return {"server": "mail.biglobe.ne.jp", "port": 993}
    if "nifty.com" in m or "nifty.ne.jp" in m:
        return {"server": "imap.nifty.com", "port": 993}
    if "mose-mail.jp" in m:
        return {"server": "mbox.mose-mail.jp", "port": 993}
    if "enmail.co" in m:
        return {"server": "mail.enmail.co", "port": 993}
    if "gmoserver.jp" in m or "onamae.ne.jp" in m:
        return {"server": "imap.onamae.ne.jp", "port": 993}
    if "muumuu-mail.com" in m:
        return {"server": "imap4.muumuu-mail.com", "port": 993}

    # Custom MX: MUST pass real IMAP banner check (* OK without LOGINDISABLED)
    if verify_usable_imap(mx_host, 993):
        return {"server": mx_host, "port": 993}
    if domain:
        if verify_usable_imap(f"mail.{domain}", 993):
            return {"server": f"mail.{domain}", "port": 993}
        if verify_usable_imap(f"imap.{domain}", 993):
            return {"server": f"imap.{domain}", "port": 993}
    return None


def save_master_imap_configs(new_configs):
    """Atomically append new domain configs to central & local databases."""
    if not new_configs:
        return
    DEFAULT_IMAP_CONFIG.update(new_configs)
    tmp_path = IMAP_CONFIG_PATH + ".tmp"
    try:
        os.makedirs(os.path.dirname(IMAP_CONFIG_PATH), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_IMAP_CONFIG, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, IMAP_CONFIG_PATH)
    except Exception:
        pass
    if _local_cfg_path != IMAP_CONFIG_PATH and os.path.exists(_local_cfg_path):
        try:
            with open(_local_cfg_path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_IMAP_CONFIG, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
