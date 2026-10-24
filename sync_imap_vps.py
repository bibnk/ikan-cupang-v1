#!/usr/bin/env python3
"""
Sync IMAP Master Database across Local & all VPS Nodes.
Two-way synchronization:
1. Pull new resolved domains from each VPS into Local Master.
2. Push unified Master database back to any VPS that is behind.
3. Reload/restart services safely.
"""

import os
import sys
import json
import shutil
import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_MASTER_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "PMJ", "imap", "imap_config.json")
LOCAL_FALLBACK_PATH = os.path.join(os.path.expanduser("~"), "ikan cupang v1", "imap_config.json")
NODES_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "PMJ", "imap", "vps_nodes.json")

REMOTE_PATHS = [
    "/opt/pmj/imap/imap_config.json",
    "/opt/imap-checker/imap_config.json",
]

DEFAULT_NODES = [
    {"name": "VPS-178 (Primary Checker)", "host": "178.128.0.98", "port": 22, "user": "root", "pass": "Jembut!23Je"},
    {"name": "VPS-166 (Worker)", "host": "166.88.227.2", "port": 22, "user": "root", "pass": "Jembut!23"},
]


def load_nodes():
    if os.path.exists(NODES_CONFIG_PATH):
        try:
            with open(NODES_CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error reading {NODES_CONFIG_PATH}: {e}")
    # Write default if not exists
    os.makedirs(os.path.dirname(NODES_CONFIG_PATH), exist_ok=True)
    with open(NODES_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_NODES, f, indent=2)
    return DEFAULT_NODES


def load_local_master():
    if os.path.exists(LOCAL_MASTER_PATH):
        try:
            with open(LOCAL_MASTER_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    if os.path.exists(LOCAL_FALLBACK_PATH):
        try:
            with open(LOCAL_FALLBACK_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_local_master(master_dict):
    os.makedirs(os.path.dirname(LOCAL_MASTER_PATH), exist_ok=True)
    # Write atomic tmp
    tmp = LOCAL_MASTER_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(master_dict, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, LOCAL_MASTER_PATH)

    # Sync to local repo fallback if exists
    if os.path.exists(os.path.dirname(LOCAL_FALLBACK_PATH)):
        try:
            shutil.copy(LOCAL_MASTER_PATH, LOCAL_FALLBACK_PATH)
        except Exception:
            pass


def fetch_node_config(node):
    host = node["host"]
    user = node.get("user", "root")
    password = node.get("pass", "")
    port = node.get("port", 22)
    name = node.get("name", host)

    result = {"node": node, "name": name, "host": host, "remote_data": {}, "error": None}

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=user, password=password, timeout=12)

        sftp = ssh.open_sftp()
        for rp in REMOTE_PATHS:
            try:
                with sftp.open(rp, "r") as f:
                    data = json.load(f)
                    if data:
                        result["remote_data"] = data
                        break
            except Exception:
                continue

        sftp.close()
        ssh.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def push_node_config(node, master_dict):
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
        # Upload via memory buffer
        json_bytes = json.dumps(master_dict, indent=2, ensure_ascii=False).encode("utf-8")

        for rp in REMOTE_PATHS:
            try:
                # Ensure parent dir exists
                pdir = os.path.dirname(rp)
                ssh.exec_command(f"mkdir -p {pdir}")
                with sftp.open(rp + ".tmp", "w") as f:
                    f.write(json_bytes)
                ssh.exec_command(f"mv {rp}.tmp {rp}")
            except Exception:
                continue

        sftp.close()

        # Fix ownership and restart service if present
        fix_cmd = """
        if id imapchecker >/dev/null 2>&1; then
            chown -R imapchecker:imapchecker /opt/pmj/imap /opt/imap-checker 2>/dev/null || true
        fi
        if systemctl is-active --quiet imap-checker 2>/dev/null; then
            systemctl restart imap-checker
        fi
        """
        ssh.exec_command(fix_cmd)
        ssh.close()
        result["updated"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    print("=" * 65)
    print(" 🌐 IMAP MASTER DATABASE — TWO-WAY MULTI-SERVER SYNC")
    print("=" * 65)

    nodes = load_nodes()
    print(f"[*] Loaded {len(nodes)} target node(s) from vps_nodes.json")

    local_master = load_local_master()
    initial_count = len(local_master)
    print(f"[*] Current Local Master entries: {initial_count:,} domains\n")

    # Step 1: PULL from all nodes
    print("--- [1/3] PULLING NEW CONFIGS FROM ALL VPS NODES ---")
    fetched_results = []
    with ThreadPoolExecutor(max_workers=len(nodes) or 1) as pool:
        fetched_results = list(pool.map(fetch_node_config, nodes))

    total_pulled = 0
    for res in fetched_results:
        name = res["name"]
        host = res["host"]
        if res["error"]:
            print(f"  ❌ [{name}] ({host}): Offline / Error: {res['error']}")
            continue

        rdata = res["remote_data"]
        rcount = len(rdata)
        new_keys = set(rdata.keys()) - set(local_master.keys())
        if new_keys:
            for k in new_keys:
                local_master[k] = rdata[k]
            total_pulled += len(new_keys)
            print(f"  📥 [{name}] ({host}): {rcount:,} entries (+{len(new_keys)} NEW domain(s) pulled)")
        else:
            print(f"  ✔️  [{name}] ({host}): {rcount:,} entries (Up-to-date or subset)")

    final_count = len(local_master)
    print(f"\n[*] Total new domain(s) merged into Local Master: +{total_pulled}")
    print(f"[*] Unified Local Master now has: {final_count:,} domains\n")

    # Step 2: SAVE LOCAL MASTER
    if total_pulled > 0:
        save_local_master(local_master)
        print(f"--- [2/3] SAVED LOCAL MASTER ({final_count:,} domains) ---")
    else:
        print("--- [2/3] LOCAL MASTER ALREADY SYNCHRONIZED ---")

    # Step 3: PUSH UNIFIED MASTER TO NODES
    print("\n--- [3/3] PUSHING UNIFIED MASTER TO NODES ---")
    nodes_to_update = []
    for res in fetched_results:
        if res["error"]:
            continue
        rcount = len(res["remote_data"])
        if rcount < final_count:
            nodes_to_update.append((res["node"], final_count - rcount))
        else:
            print(f"  ✔️  [{res['name']}] already has complete {final_count:,} domains (Skipping push)")

    if not nodes_to_update:
        print("  🎉 All reachable VPS nodes are already 100% in sync!")
    else:
        with ThreadPoolExecutor(max_workers=len(nodes_to_update) or 1) as pool:
            push_results = list(pool.map(lambda item: push_node_config(item[0], local_master), nodes_to_update))

        for (node, diff), pres in zip(nodes_to_update, push_results):
            name = pres["name"]
            host = pres["host"]
            if pres["updated"]:
                print(f"  📤 [{name}] ({host}): Successfully PUSHED unified DB (+{diff} domains added, service reloaded)")
            else:
                print(f"  ❌ [{name}] ({host}): Push failed: {pres['error']}")

    print("\n" + "=" * 65)
    print(f" ✅ SYNC FINISHED: Master Database has {final_count:,} active IMAP domains.")
    print("=" * 65)


if __name__ == "__main__":
    main()
