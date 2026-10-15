#!/usr/bin/env python3
"""
Vault draft sidecar — stdio JSON-RPC wrapper for generate_vault_draft.py.
Same protocol as the NVD/MSRC sidecars.

Commands:
  {"cmd": "draft", "case_id": "CVE-XXXX-YYYY"}             → singleton mode
  {"cmd": "draft", "case_id": "CWE-416", "subsystem": "ksmbd"}  → cluster mode
  {"cmd": "draft", "case_id": "X", "mode": "auto|cluster|singleton"}
  {"cmd": "status"}
  {"cmd": "quit"}

Response:
  {"status": "ok", "case_id": "...", "markdown": "..."}
  {"status": "error", "error": "...", "traceback": "..."}

generate_vault_draft calls print() → with the stdout_to_stderr context manager
the JSON-RPC channel stays clean.
"""

import contextlib
import json
import sqlite3
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from prozessfall_config import PROZESSFALL_DB
from generate_vault_draft import generate_vault_draft


@contextlib.contextmanager
def stdout_to_stderr():
    old = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old


# Subsystem keyword extraction — singleton fallback → subsystem hint for cluster.
# The list is summarized from surface_scanner.py, the most common Linux + Windows subsystems.
SUBSYSTEM_KEYWORDS = [
    "ksmbd", "io_uring", "netfilter", "nftables", "bpf", "ebpf",
    "hyper-v", "kvm", "qemu", "virtio",
    "tcp", "udp", "ipv6", "ipv4", "vsock",
    "drm", "i915", "amdgpu",
    "btrfs", "ext4", "xfs", "f2fs", "nfs", "cifs", "vfs",
    "usb", "bluetooth", "wifi", "mac80211",
    "perf", "tracing", "ftrace", "ptrace", "uprobe", "kprobe",
    "namespaces", "cgroup", "seccomp", "apparmor", "selinux",
    "scheduler", "slab", "scsi", "nvme",
    "windows kernel", "ntdll", "win32k", "afd", "tcpip",
    "defender", "exchange", "sharepoint", "office",
    "openssl", "openssh", "samba",
]


def extract_subsystem(desc):
    if not desc:
        return None
    desc_lower = desc.lower()
    for kw in SUBSYSTEM_KEYWORDS:
        if kw in desc_lower:
            return kw
    return None


def cmd_draft(args):
    case_id = args.get("case_id", "")
    subsystem = args.get("subsystem")
    mode = args.get("mode", "auto")

    if not case_id:
        return {"status": "error", "error": "case_id required"}

    conn = sqlite3.connect(PROZESSFALL_DB)
    try:
        with stdout_to_stderr():
            markdown = generate_vault_draft(conn, case_id, subsystem, mode)

        # Fallback: if the CVE singleton is ERROR (not in MSRC), extract the CVE's primary CWE
        # from cve_raw, extract a subsystem keyword from the description, and fall back
        # to cluster mode. This produces a draft for Linux/NVD-only CVEs.
        if (
            case_id.startswith("CVE-")
            and "Discovery Trace — ERROR" in markdown
            and mode == "auto"
        ):
            row = conn.execute(
                "SELECT cwe_ids, description FROM cve_raw WHERE cve_id = ?",
                (case_id,),
            ).fetchone()
            if row and row[0]:
                try:
                    cwes = json.loads(row[0])
                except Exception:
                    cwes = []
                if cwes:
                    primary_cwe = cwes[0]
                    inferred = subsystem or extract_subsystem(row[1] or "")
                    with stdout_to_stderr():
                        cluster_md = generate_vault_draft(
                            conn, primary_cwe, inferred, "cluster"
                        )
                    header = (
                        f"> **Fallback:** {case_id} is not in the MSRC table; "
                        f"primary CWE `{primary_cwe}`"
                        + (f" + subsystem `{inferred}`" if inferred else "")
                        + " — cluster draft generated.\n\n"
                    )
                    markdown = header + cluster_md
                    mode = "cluster_fallback"

        return {
            "status": "ok",
            "case_id": case_id,
            "mode": mode,
            "markdown": markdown,
        }
    except Exception as e:
        return {
            "status": "error",
            "case_id": case_id,
            "error": str(e),
            "traceback": traceback.format_exc(),
        }
    finally:
        conn.close()


def cmd_status(args):
    return {"status": "ok", "sidecar": "vault"}


COMMANDS = {"draft": cmd_draft, "status": cmd_status}


def write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    write({"status": "ready", "sidecar": "vault"})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            write({"status": "error", "error": f"bad json: {e}"})
            continue

        cmd = req.get("cmd")
        if cmd == "quit":
            write({"status": "bye"})
            return

        handler = COMMANDS.get(cmd)
        if not handler:
            write({"status": "error", "error": f"unknown cmd: {cmd}"})
            continue

        try:
            write(handler(req))
        except Exception as e:
            write({
                "status": "error",
                "error": str(e),
                "traceback": traceback.format_exc(),
            })


if __name__ == "__main__":
    main()
