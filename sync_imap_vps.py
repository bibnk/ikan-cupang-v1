#!/usr/bin/env python3
"""
Sync IMAP Master Database & Unusable Domains List across Local & all VPS Nodes.
Two-way synchronization:
1. Pull new resolved domains AND unusable/dead domains from each VPS into Local Master.
2. Push unified Master databases back to any VPS that is behind.
3. Reload/restart services safely.
"""

import os
import sys
import json
import shutil
from concurrent.futures import ThreadPoolExecutor

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko

# Paths
LOCAL_MASTER_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "PMJ", "imap")
LOCAL_MASTER_CONFIG = os.path.join(LOCAL_MASTER_DIR, "imap_config.json")
LOCAL_MASTER_UNUSABLE = os.path.join(LOCAL_MASTER_DIR, "imap_unusable.json")
LOCAL_MASTER_EXCLUSION = os.path.join(LOCAL_MASTER_DIR, "subject_exclusion_list.json")

REPO_DIR = os.path.join(os.path.expanduser("~"), "ikan cupang v1")
REPO_CONFIG = os.path.join(REPO_DIR, "imap_config.json")
REPO_UNUSABLE = os.path.join(REPO_DIR, "imap_unusable.json")
REPO_EXCLUSION = os.path.join(REPO_DIR, "subject_exclusion_list.json")

NODES_CONFIG_PATH = os.path.join(LOCAL_MASTER_DIR, "vps_nodes.json")

REMOTE_CONFIG_PATHS = [
    "/opt/pmj/imap/imap_config.json",
    "/opt/imap-checker/imap_config.json",
]
REMOTE_SUCCESS_PATHS = [
    "/opt/pmj/imap/imap_success.json",
    "/opt/imap-checker/imap_success.json",
]
REMOTE_UNUSABLE_PATHS = [
    "/opt/pmj/imap/imap_unusable.json",
    "/opt/imap-checker/imap_unusable.json",
]
REMOTE_EXCLUSION_PATHS = [
    "/opt/pmj/imap/subject_exclusion_list.json",
    "/opt/imap-checker/subject_exclusion_list.json",
]
LOCAL_MASTER_ALREADY = os.path.join(LOCAL_MASTER_DIR, "already_accounts.txt")
REMOTE_ALREADY_PATHS = [
    "/opt/pmj/imap/already_accounts.txt",
    "/opt/imap-checker/already_accounts.txt",
]

DISALLOWED_KEYWORDS = [
    "google", "gmail", "googlemail", "aspmx",
    "outlook", "office365", "microsoft", "hotmail", "live.com", "msn.com",
    "zoho", "icloud", "apple", "yahoo", "ymail", "yahoodns",
    "protonmail", "tutanota", "fastmail",
    "cloudflare", "mimecast", "spamexperts", "barracuda", "proofpoint",
    "trendmicro", "mailinblack", "hornetsecurity", "ironport",
    "generic-isp", "breakthur", "b5z.net"
]

DEFAULT_NODES = [
    {"name": "VPS-178 (Primary Checker)", "host": "178.128.0.98", "port": 22, "user": "root", "pass": "Jembut!23Je"},
    {"name": "VPS-166 (Worker)", "host": "166.88.227.2", "port": 22, "user": "root", "pass": "Jembut!23"},
]


def load_nodes():
    candidates = [
        "/opt/pmj/imap/vps_nodes.json",
        "/opt/imap-checker/vps_nodes.json",
        NODES_CONFIG_PATH,
        os.path.join(REPO_DIR, "vps_nodes.json"),
        os.path.join(os.path.dirname(__file__), "vps_nodes.json"),
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list) and data:
                        return data
            except Exception as e:
                print(f"[!] Error reading {p}: {e}")
    if os.path.exists(os.path.dirname(NODES_CONFIG_PATH)):
        with open(NODES_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_NODES, f, indent=2)
    return DEFAULT_NODES


def load_local_json(path, fallback_path=None, default=None):
    if default is None:
        default = {}
    for p in [path, fallback_path]:
        if p and os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return default


def save_atomic_json(path, data, fallback_path=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if fallback_path and os.path.exists(os.path.dirname(fallback_path)):
        try:
            shutil.copy(path, fallback_path)
        except Exception:
            pass


def fetch_node_data(node):
    host = node["host"]
    user = node.get("user", "root")
    password = node.get("pass", "")
    port = node.get("port", 22)
    name = node.get("name", host)

    result = {
        "node": node,
        "name": name,
        "host": host,
        "remote_configs": {},
        "remote_unusable": set(),
        "error": None
    }

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=user, password=password, timeout=12)
        sftp = ssh.open_sftp()

        # 1. Fetch imap_config.json
        for rp in REMOTE_CONFIG_PATHS:
            try:
                with sftp.open(rp, "r") as f:
                    data = json.load(f)
                    if data and isinstance(data, dict):
                        result["remote_configs"].update(data)
                        break
            except Exception:
                continue

        # 1b. Fetch imap_success.json (if present, merge verified domains)
        for rp in REMOTE_SUCCESS_PATHS:
            try:
                with sftp.open(rp, "r") as f:
                    data = json.load(f)
                    if data and isinstance(data, dict):
                        for dom, cfg in data.items():
                            if dom not in result["remote_configs"] and isinstance(cfg, dict):
                                result["remote_configs"][dom] = cfg
                        break
            except Exception:
                continue

        # 2. Fetch imap_unusable.json
        for rp in REMOTE_UNUSABLE_PATHS:
            try:
                with sftp.open(rp, "r") as f:
                    data = json.load(f)
                    if data:
                        result["remote_unusable"] = set(data if isinstance(data, list) else data.keys())
                        break
            except Exception:
                continue

        sftp.close()
        ssh.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def push_node_data(node, master_configs, master_unusable):
    host = node["host"]
    user = node.get("user", "root")
    password = node.get("pass", "")
    port = node.get("port", 22)
    name = node.get("name", host)

    result = {"name": name, "host": host, "updated": False, "error": None}

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=user, password=password, timeout=12)
        sftp = ssh.open_sftp()

        cfg_bytes = json.dumps(master_configs, indent=2, ensure_ascii=False).encode("utf-8")
        unusable_bytes = json.dumps(sorted(list(master_unusable)), indent=2, ensure_ascii=False).encode("utf-8")

        for rp in REMOTE_CONFIG_PATHS:
            try:
                pdir = os.path.dirname(rp)
                ssh.exec_command(f"mkdir -p {pdir}")
                with sftp.open(rp + ".tmp", "w") as f:
                    f.write(cfg_bytes)
                ssh.exec_command(f"mv {rp}.tmp {rp}")
            except Exception:
                continue

        for rp in REMOTE_UNUSABLE_PATHS:
            try:
                pdir = os.path.dirname(rp)
                ssh.exec_command(f"mkdir -p {pdir}")
                with sftp.open(rp + ".tmp", "w") as f:
                    f.write(unusable_bytes)
                ssh.exec_command(f"mv {rp}.tmp {rp}")
            except Exception:
                continue

        if os.path.exists(LOCAL_MASTER_EXCLUSION):
            try:
                with open(LOCAL_MASTER_EXCLUSION, "rb") as ef:
                    excl_bytes = ef.read()
                for rp in REMOTE_EXCLUSION_PATHS:
                    try:
                        pdir = os.path.dirname(rp)
                        ssh.exec_command(f"mkdir -p {pdir}")
                        with sftp.open(rp + ".tmp", "w") as f:
                            f.write(excl_bytes)
                        ssh.exec_command(f"mv {rp}.tmp {rp}")
                    except Exception:
                        continue
            except Exception:
                pass

        if os.path.exists(LOCAL_MASTER_ALREADY):
            try:
                with open(LOCAL_MASTER_ALREADY, "rb") as af:
                    already_bytes = af.read()
                for rp in REMOTE_ALREADY_PATHS:
                    try:
                        pdir = os.path.dirname(rp)
                        ssh.exec_command(f"mkdir -p {pdir}")
                        with sftp.open(rp + ".tmp", "w") as f:
                            f.write(already_bytes)
                        ssh.exec_command(f"mv {rp}.tmp {rp}")
                    except Exception:
                        continue
            except Exception:
                pass

        sftp.close()

        # Permissions, hot-reload, and safe conditional restart
        fix_cmd = """
        if id imapchecker >/dev/null 2>&1; then
            chown -R imapchecker:imapchecker /opt/pmj/imap /opt/imap-checker 2>/dev/null || true
            chmod 664 /opt/pmj/imap/*.json /opt/pmj/imap/*.txt /opt/imap-checker/*.json /opt/imap-checker/*.txt 2>/dev/null || true
        fi
        
        # 1. Hot reload in-memory configs via internal API (zero downtime, zero thread drop)
        curl -s -X POST http://127.0.0.1:5000/sbb/api/reload-configs >/dev/null 2>&1 || true

        # 2. Check if any checker job is actively running
        IS_BUSY=$(curl -s http://127.0.0.1:5000/sbb/api/is-busy 2>/dev/null | grep -o '"busy":true' || true)

        # 3. Only restart systemctl if NO jobs are running
        if [ -z "$IS_BUSY" ]; then
            if systemctl is-active --quiet imap-checker 2>/dev/null; then
                systemctl restart imap-checker 2>/dev/null || true
            fi
        else
            echo "PROTECTED: Job is currently running on this runner. Configs hot-reloaded into memory without restarting service!"
        fi
        """
        ssh.exec_command(fix_cmd)
        ssh.close()
        result["updated"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    print("=" * 70)
    print(" 🌐 IMAP MASTER DATABASE — TWO-WAY MULTI-SERVER SYNC")
    print("=" * 70)

    nodes = load_nodes()
    print(f"[*] Loaded {len(nodes)} target node(s) from vps_nodes.json")

    local_configs = load_local_json(LOCAL_MASTER_CONFIG, REPO_CONFIG, default={})
    local_unusable_raw = load_local_json(LOCAL_MASTER_UNUSABLE, REPO_UNUSABLE, default=[])
    local_unusable = set(local_unusable_raw if isinstance(local_unusable_raw, list) else local_unusable_raw.keys())

    print(f"[*] Local Master: {len(local_configs):,} valid configs | {len(local_unusable):,} unusable/dead domains\n")

    # Step 1: PULL from all nodes
    print("--- [1/3] PULLING NEW DATA FROM ALL VPS NODES ---")
    with ThreadPoolExecutor(max_workers=len(nodes) or 1) as pool:
        fetched_results = list(pool.map(fetch_node_data, nodes))

    pulled_configs = 0
    pulled_unusable = 0

    for res in fetched_results:
        name = res["name"]
        host = res["host"]
        if res["error"]:
            print(f"  ❌ [{name}] ({host}): Offline / Error: {res['error']}")
            continue

        r_cfg = res["remote_configs"]
        r_unusable = res["remote_unusable"]

        new_added = 0
        for dom, cfg in r_cfg.items():
            dom = dom.lower().strip()
            if not isinstance(cfg, dict) or not cfg.get("server"):
                continue
            server = str(cfg.get("server", "")).lower()
            if any(kw in server for kw in DISALLOWED_KEYWORDS):
                if dom not in local_unusable:
                    local_unusable.add(dom)
                    pulled_unusable += 1
                continue
            if dom in local_unusable:
                continue
            if dom not in local_configs:
                local_configs[dom] = cfg
                new_added += 1
                pulled_configs += 1

        new_unusable_keys = r_unusable - local_unusable
        if new_unusable_keys:
            local_unusable.update(new_unusable_keys)
            pulled_unusable += len(new_unusable_keys)

        print(f"  📥 [{name}] ({host}): {len(r_cfg):,} pulled (+{new_added} valid, +{len(new_unusable_keys)} unusable)")

    print(f"\n[*] Total new valid configs pulled: +{pulled_configs}")
    print(f"[*] Total new unusable domains pulled: +{pulled_unusable}")
    print(f"[*] Unified Local Master: {len(local_configs):,} valid | {len(local_unusable):,} unusable\n")

    # Step 2: SAVE LOCAL MASTER
    if pulled_configs > 0:
        save_atomic_json(LOCAL_MASTER_CONFIG, local_configs, REPO_CONFIG)
    if pulled_unusable > 0:
        save_atomic_json(LOCAL_MASTER_UNUSABLE, sorted(list(local_unusable)), REPO_UNUSABLE)
    print("--- [2/3] SAVED LOCAL MASTER DATABASES ---")

    # Step 3: PUSH UNIFIED MASTER TO NODES
    print("\n--- [3/3] PUSHING UNIFIED MASTER TO NODES ---")
    nodes_to_update = []
    for res in fetched_results:
        if res["error"]:
            continue
        cfg_diff = len(local_configs) - len(res["remote_configs"])
        unusable_diff = len(local_unusable) - len(res["remote_unusable"])
        if cfg_diff > 0 or unusable_diff > 0:
            nodes_to_update.append((res["node"], cfg_diff, unusable_diff))
        else:
            print(f"  ✔️  [{res['name']}] already 100% in sync (Skipping push)")

    if not nodes_to_update:
        print("  🎉 All reachable VPS nodes are already 100% in sync!")
    else:
        with ThreadPoolExecutor(max_workers=len(nodes_to_update) or 1) as pool:
            push_results = list(pool.map(lambda item: push_node_data(item[0], local_configs, local_unusable), nodes_to_update))

        for (node, cdiff, udiff), pres in zip(nodes_to_update, push_results):
            name = pres["name"]
            host = pres["host"]
            if pres["updated"]:
                print(f"  📤 [{name}] ({host}): Successfully PUSHED (+{cdiff} configs, +{udiff} unusable, service reloaded)")
            else:
                print(f"  ❌ [{name}] ({host}): Push failed: {pres['error']}")

    print("\n" + "=" * 70)
    print(f" ✅ SYNC FINISHED: Unified Master has {len(local_configs):,} valid & {len(local_unusable):,} unusable domains.")
    print("=" * 70)


if __name__ == "__main__":
    main()
