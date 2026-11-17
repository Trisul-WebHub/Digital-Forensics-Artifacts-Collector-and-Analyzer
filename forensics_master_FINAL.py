#!/usr/bin/env python3

# ══════════════════════════════════════════════════════════════════════════════
# PART A — FORENSICS ENGINE  (Unified_Forensics.py — embedded)
# ══════════════════════════════════════════════════════════════════════════════


import os, sys, re, csv, json, glob, shutil, time, subprocess, ipaddress, argparse, threading, platform, hashlib
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: LAUNCHER — menu system, flows, helpers (unprefixed)
# ══════════════════════════════════════════════════════════════════════════════


# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"; CYN="\033[96m"
    BOLD="\033[1m"; RST="\033[0m";  BLU="\033[94m"; MAG="\033[95m"
    DIM="\033[2m";  WHT="\033[97m"

def clear():
    os.system('clear' if os.name != 'nt' else 'cls')

def banner():
    clear()
    print(f"""{C.CYN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║          🛡  FORENSICS MASTER ANALYZER — UNIFIED LAUNCHER               ║
║                                                                          ║
║          Windows  │  Linux (Ubuntu/CentOS)  │  Linux (Kali)             ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{C.RST}""")

# ── Helper: get input ─────────────────────────────────────────────────────────
_ACQ_TL = threading.local()      # set by the web GUI: auto-answers for the acquisition prompts


def ask(prompt, color=C.CYN):
    ans = getattr(_ACQ_TL, "answers", None)
    if ans is not None:             # GUI run: answer from the form instead of waiting on stdin
        pl = prompt.lower()
        if "memory capture" in pl: a = "y" if ans.get("memory") else "n"
        elif "specific process" in pl: a = ans.get("procs", "")
        elif "fuji" in pl: a = "y" if ans.get("fuji") else "n"
        elif "run forensics analysis" in pl: a = "n"
        else: a = "y"
        print(f"  [GUI] {prompt.strip()}  ->  {a or '(skip)'}")
        return a
    return input(f"{color}{prompt}{C.RST}").strip()

def confirm(prompt):
    ans = ask(f"{prompt} [y/n]: ", C.YEL).lower()
    return ans in ('y', 'yes', '')

def print_step(num, total, title):
    print(f"\n{C.BLU}{C.BOLD}[{num}/{total}] {title}{C.RST}")
    print(f"{C.DIM}{'─'*60}{C.RST}")

def print_ok(msg):   print(f"  {C.GRN}✓{C.RST}  {msg}")
def print_warn(msg): print(f"  {C.YEL}⚠{C.RST}  {msg}")
def print_err(msg):  print(f"  {C.RED}✗{C.RST}  {msg}")
def print_info(msg): print(f"  {C.CYN}→{C.RST}  {msg}")

# ── Analysis modules (merged in-process, no external files / subprocess) ───────
SCRIPT_DIR    = Path(__file__).parent

# ══════════════════════════════════════════════════════════════════════════════
# MENU SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

def mode_menu():
    banner()
    print(f"{C.WHT}{C.BOLD}  What do you want to do?{C.RST}\n")
    print(f"  {C.CYN}[1]{C.RST}  🔎  Forensics — analyze evidence already collected")
    print(f"       └─ Point at an evidence folder, run full analysis, get a dashboard")
    print()
    print(f"  {C.CYN}[2]{C.RST}  📥  Acquisition — collect evidence from THIS live machine")
    print(f"       └─ Must be run on the box being investigated (reads its live state)")
    print()
    print(f"  {C.CYN}[3]{C.RST}  ❌  Exit")
    print()
    return ask("  Enter choice [1-3]: ")

def acq_os_menu():
    banner()
    print(f"{C.WHT}{C.BOLD}  Acquisition — Select This Machine's OS:{C.RST}\n")
    print(f"  {C.DIM}Run this on the box being investigated — it collects from THIS{C.RST}")
    print(f"  {C.DIM}machine's live state, not from a remote host.{C.RST}\n")
    print(f"  {C.CYN}[1]{C.RST}  🪟  Windows")
    print(f"  {C.CYN}[2]{C.RST}  🐧  Linux")
    print(f"  {C.CYN}[3]{C.RST}  🍎  macOS")
    print(f"  {C.CYN}[4]{C.RST}  ⬅️   Back")
    print()
    return ask("  Enter choice [1-4]: ")

def acquisition_flow():
    choice = acq_os_menu()
    if choice == "4":
        return
    os_label = {"1":"windows","2":"linux","3":"macos"}.get(choice)
    if not os_label:
        print(f"\n{C.RED}  Invalid choice.{C.RST}")
        ask("\n  Press Enter to continue...")
        return

    banner()
    print(f"{C.BOLD}  📥 {os_label.capitalize()} Acquisition Setup{C.RST}\n")
    default_out = f"./acquisition_{os_label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    out_prompt = ask(f"  Output folder [{C.DIM}Enter for default: {default_out}{C.RST}]: ")
    output = out_prompt.strip() or default_out
    output = os.path.expanduser(output)

    print()
    if not confirm(f"  Collect evidence from THIS machine into {output}?"):
        return

    if os_label == "windows":
        collected = run_windows_acquisition(output)
    elif os_label == "linux":
        collected = run_linux_acquisition(output)
    else:
        collected = run_macos_acquisition(output)

    if confirm("  Run Forensics analysis on this now?"):
        vt_key, abuse_key = get_api_keys()
        analysis_out = str(collected) + "_analysis"
        if os_label == "windows":
            run_windows_analysis(str(collected), analysis_out, vt_key, abuse_key,
                                  skip_memory=False, evtx_only=False, skip_setup=False)
        elif os_label == "linux":
            run_linux_analysis(str(collected), analysis_out, vt_key, abuse_key,
                                skip_memory=False, need_sudo=False, os_type="ubuntu", skip_setup=False)
        else:
            run_macos_analysis(str(collected), analysis_out, vt_key, abuse_key, skip_setup=False)
    else:
        ask("\n  Press Enter to return to menu...")

def main_menu():
    banner()
    print(f"{C.WHT}{C.BOLD}  Select Target OS:{C.RST}\n")
    print(f"  {C.CYN}[1]{C.RST}  🪟  Windows")
    print(f"       └─ EVTX Logs, Memory Dump, Registry, Network, EDR")
    print()
    print(f"  {C.CYN}[2]{C.RST}  🐧  Linux (Ubuntu / CentOS / RHEL)")
    print(f"       └─ Auth/Secure logs, Audit, Crontab, SSH, Process, Memory")
    print()
    print(f"  {C.CYN}[3]{C.RST}  🎯  Linux (Kali / Debian)")
    print(f"       └─ Same as above + Kali-specific paths and tools")
    print()
    print(f"  {C.CYN}[4]{C.RST}  🍎  macOS")
    print(f"       └─ LaunchAgents/Daemons (persistence), Quarantine, Unified Logs, TCC, Kexts")
    print()
    print(f"  {C.CYN}[5]{C.RST}  📋  Show tool status")
    print(f"  {C.CYN}[6]{C.RST}  ❌  Exit")
    print()

    choice = ask("  Enter choice [1-6]: ")
    return choice

def tool_status():
    banner()
    print(f"{C.BOLD}  Tool Status:{C.RST}\n")

    # Analysis modules are merged directly into this file (no external .py needed)
    print_ok("Windows Forensics module (win_main) — built-in")
    print_ok("Linux Forensics module (lin_main) — built-in")
    print_ok("macOS Forensics module (mac_main) — built-in")
    print()

    # Check external tools
    ext_tools = {
        "Hayabusa":    ["tools/hayabusa/hayabusa"],
        "Chainsaw":    ["tools/chainsaw/chainsaw"],
        "Volatility3": ["vol"],
        "7zip":        ["7z", "7za"],
        "unrar":       ["unrar"],
    }
    print(f"  {C.BOLD}External Tools:{C.RST}")
    for name, cmds in ext_tools.items():
        found = any(shutil.which(c) or (SCRIPT_DIR/c).exists() for c in cmds)
        if found:
            print_ok(f"{name}")
        else:
            print_warn(f"{name} — not found (optional)")

    print()

    # Check Python packages
    py_pkgs = ["evtx", "volatility3", "Registry", "requests", "tqdm"]
    print(f"  {C.BOLD}Python Packages:{C.RST}")
    for pkg in py_pkgs:
        try:
            __import__(pkg)
            print_ok(pkg)
        except ImportError:
            print_warn(f"{pkg} — not installed")

    print()
    ask("  Press Enter to continue...", C.DIM)

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION WIZARD
# ══════════════════════════════════════════════════════════════════════════════

def get_evidence_path(os_type):
    """Get and validate evidence folder path"""
    print_step(1, 4, "Evidence Folder")

    examples = {
        "windows": [
            "~/Downloads/SCDC Forensic Logs/VEEAM-MGMT-SRV_20260901_160713",
            "/mnt/evidence/windows_host/",
            "D:/Evidence/Case001/",
        ],
        "linux_ubuntu": [
            "~/Downloads/CentOS_Evidence/",
            "/mnt/evidence/linux_host/",
            "/media/usb/forensics/",
        ],
        "linux_kali": [
            "~/Desktop/kali_evidence/",
            "/mnt/evidence/kali_host/",
        ],
        "macos": [
            "~/Downloads/macOS_Evidence/",
            "/mnt/evidence/mac_host/",
        ],
    }

    key = "windows" if os_type == "windows" else \
          "macos"   if os_type == "macos"   else \
          "linux_kali" if os_type == "kali" else "linux_ubuntu"

    print(f"  Examples:")
    for ex in examples[key]:
        print(f"    {C.DIM}{ex}{C.RST}")
    print()

    while True:
        path_str = ask("  Evidence folder path: ")
        if not path_str:
            print_err("Path cannot be empty")
            continue

        # Expand ~ and env vars
        path = Path(os.path.expandvars(os.path.expanduser(path_str)))

        if not path.exists():
            print_err(f"Path not found: {path}")
            if not confirm("  Try anyway?"):
                continue

        # Show what's inside
        if path.exists():
            items = list(path.iterdir())
            print(f"\n  {C.GRN}Found:{C.RST} {len(items)} items in folder")
            for item in sorted(items)[:10]:
                icon = "📁" if item.is_dir() else "📄"
                print(f"    {icon} {item.name}")
            if len(items) > 10:
                print(f"    ... and {len(items)-10} more")
            print()

            if confirm("  Use this folder?"):
                return str(path)
        else:
            return str(path)

def get_output_path():
    """Get output directory"""
    print_step(2, 4, "Output Directory")
    default = str(Path.home() / "Downloads" / "forensics_output")
    print(f"  Default: {C.DIM}{default}{C.RST}")
    path_str = ask(f"  Output path [Enter for default]: ")
    if not path_str:
        return default
    return str(Path(os.path.expandvars(os.path.expanduser(path_str))))

def get_api_keys():
    """Get optional API keys"""
    print_step(3, 4, "API Keys (Optional)")
    print(f"  {C.DIM}These enable IP/hash reputation checks{C.RST}")
    print(f"  {C.DIM}Get free key: https://www.virustotal.com/gui/sign-in{C.RST}\n")

    vt_key    = ask("  VirusTotal API key [Enter to skip]: ", C.YEL)
    abuse_key = ask("  AbuseIPDB API key  [Enter to skip]: ", C.YEL)

    return vt_key or None, abuse_key or None

def get_windows_options():
    """Windows-specific options"""
    print_step(4, 4, "Windows Options")

    print(f"  {C.BOLD}Analysis modules:{C.RST}")
    print(f"  {C.CYN}[1]{C.RST}  Full analysis (EVTX + Memory + Registry + Network)")
    print(f"  {C.CYN}[2]{C.RST}  Fast mode (skip memory — saves 1-2 hours)")
    print(f"  {C.CYN}[3]{C.RST}  EVTX only (logs only, no memory/registry)")
    print()

    choice = ask("  Select [1-3, default=1]: ") or "1"

    skip_memory = choice in ("2", "3")
    evtx_only   = choice == "3"

    # Setup
    print()
    skip_setup = not confirm("  Download/update tools (Hayabusa, Chainsaw, Sigma)?")

    return skip_memory, evtx_only, skip_setup

def get_linux_options(os_type):
    """Linux-specific options"""
    print_step(4, 4, "Linux Options")

    print(f"  {C.BOLD}Analysis modules:{C.RST}")
    print(f"  {C.CYN}[1]{C.RST}  Full analysis (all logs + memory if available)")
    print(f"  {C.CYN}[2]{C.RST}  Logs only (no memory analysis)")
    print()

    choice = ask("  Select [1-2, default=1]: ") or "1"
    skip_memory = choice == "2"

    # Sudo
    print()
    need_sudo = confirm("  Some files need root/sudo access? (recommended: yes)")

    print()
    skip_setup = not confirm("  Check/install requirements (Volatility3, Python packages, 7z/unrar)?")

    return skip_memory, need_sudo, skip_setup

# ══════════════════════════════════════════════════════════════════════════════
# RUNNERS
# ══════════════════════════════════════════════════════════════════════════════

def run_windows_analysis(evidence, output, vt_key, abuse_key,
                          skip_memory, evtx_only, skip_setup):
    banner()
    print(f"{C.BOLD}{C.GRN}  🪟 Starting Windows Forensics Analysis{C.RST}\n")

    argv = ["--base", evidence, "--output", output]
    if vt_key:    argv += ["--vt-key",    vt_key]
    if abuse_key: argv += ["--abuse-key", abuse_key]
    if skip_memory: argv += ["--skip-memory"]
    if skip_setup:  argv += ["--skip-setup"]

    print(f"  {C.DIM}Running (in-process): win_main({argv}){C.RST}\n")
    print(f"{'─'*60}\n")

    try:
        win_main(argv)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print(f"\n{C.YEL}  Analysis interrupted by user{C.RST}")
    except Exception as e:
        print_err(f"Error running analysis: {e}")

    print(f"\n{'─'*60}")
    print(f"{C.GRN}  Dashboard: {output}/dashboard.html{C.RST}")
    ask("\n  Press Enter to return to menu...")

def run_linux_analysis(evidence, output, vt_key, abuse_key,
                        skip_memory, need_sudo, os_type, skip_setup=False):
    banner()
    label = "🎯 Kali" if os_type == "kali" else "🐧 Linux (Ubuntu/CentOS)"
    print(f"{C.BOLD}{C.GRN}  {label} Forensics Analysis{C.RST}\n")

    argv = ["--base", evidence, "--output", output]
    if vt_key:    argv += ["--vt-key",    vt_key]
    if abuse_key: argv += ["--abuse-key", abuse_key]
    if skip_setup: argv += ["--skip-setup"]

    # Note: this runs in-process (no subprocess), so a separate "sudo" wrapper
    # is not possible anymore. If root access is needed for protected files,
    # re-run this whole launcher itself with sudo.
    if need_sudo and os.name != 'nt' and hasattr(os, "geteuid") and os.geteuid() != 0:
        print_warn("Some files may need root access. Running in-process, so 'sudo' can't")
        print_warn("be applied to just this step — re-run this launcher with sudo if reads fail.")

    print(f"  {C.DIM}Running (in-process): lin_main({argv}){C.RST}\n")
    print(f"{'─'*60}\n")

    try:
        lin_main(argv)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print(f"\n{C.YEL}  Interrupted{C.RST}")
    except Exception as e:
        print_err(f"Error: {e}")

    print(f"\n{'─'*60}")
    print(f"{C.GRN}  Dashboard: {output}/dashboard.html{C.RST}")
    ask("\n  Press Enter to return to menu...")

def run_macos_analysis(evidence, output, vt_key, abuse_key, skip_setup=False):
    banner()
    print(f"{C.BOLD}{C.GRN}  🍎 macOS Forensics Analysis{C.RST}\n")

    argv = ["--base", evidence, "--output", output]
    if vt_key:    argv += ["--vt-key",    vt_key]
    if abuse_key: argv += ["--abuse-key", abuse_key]
    if skip_setup: argv += ["--skip-setup"]

    print(f"  {C.DIM}Running (in-process): mac_main({argv}){C.RST}\n")
    print(f"{'─'*60}\n")

    try:
        mac_main(argv)
    except SystemExit:
        pass
    except KeyboardInterrupt:
        print(f"\n{C.YEL}  Interrupted{C.RST}")
    except Exception as e:
        print_err(f"Error: {e}")

    print(f"\n{'─'*60}")
    print(f"{C.GRN}  Dashboard: {output}/dashboard.html{C.RST}")
    ask("\n  Press Enter to return to menu...")

# ══════════════════════════════════════════════════════════════════════════════
# ACQUISITION — collects live evidence from THIS machine into a folder laid out
# exactly the way the matching Forensics module auto-discovers (file names match
# FILE_SIGNATURES / MAC_FILE_SIGNATURES), so the collected folder can be fed
# straight into Forensics mode afterwards with zero manual reorganizing.
# Must be run on the OS it's acquiring from (a Linux box for Linux acquisition,
# a Windows box for Windows acquisition, etc.) — it reads THIS machine's live
# state, it does not reach out to a remote host.
# ══════════════════════════════════════════════════════════════════════════════

_ACQ_LEDGER = []      # (collected file, source path, original mode, original uid, original gid)


def _acq_copy(src, dst, label, log_lines):
    """Copy one file if it exists/readable; records what happened either way."""
    try:
        src = Path(src)
        if not src.exists():
            log_lines.append(f"  [skip] {label}: not present ({src})")
            return False
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        try:
            st_ = os.stat(src)
            _ACQ_LEDGER.append((str(dst), str(src), oct(st_.st_mode & 0o7777), getattr(st_, "st_uid", ""), getattr(st_, "st_gid", "")))
        except Exception: pass
        log_lines.append(f"  [ok]   {label}: {src} -> {dst.name}")
        return True
    except PermissionError:
        log_lines.append(f"  [perm] {label}: permission denied ({src}) — try running with sudo")
        return False
    except Exception as e:
        log_lines.append(f"  [err]  {label}: {e}")
        return False

def _acq_run(cmd, dst, label, log_lines, timeout=60):
    """Run a shell command and save its stdout to dst; records what happened."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(r.stdout or "", encoding='utf-8')
        if r.stdout.strip():
            log_lines.append(f"  [ok]   {label} -> {dst.name}")
            return True
        else:
            log_lines.append(f"  [empty]{label}: command produced no output "
                              f"({(r.stderr or '').strip()[:120]})")
            return False
    except Exception as e:
        log_lines.append(f"  [err]  {label}: {e}")
        return False

def run_linux_acquisition(output_dir):
    """Collects live evidence from THIS Linux machine into output_dir, laid out
    to match the Linux Forensics module's FILE_SIGNATURES auto-discovery."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    log = []
    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)

    print(f"{C.BOLD}{C.GRN}  🐧 Linux Live Acquisition{C.RST}")
    print(f"  {C.DIM}Target: this machine ({os.uname().nodename}) → {out}{C.RST}")
    if not is_root:
        print(f"  {C.YEL}Not running as root — some files (shadow, audit.log, other users'"
              f" home dirs) will be skipped. Re-run with sudo for a complete collection.{C.RST}")
    print()

    # Auth / system logs — try both Debian (auth.log) and RHEL (secure) names
    _acq_copy("/var/log/auth.log", out/"auth.log", "Auth log (Debian/Ubuntu)", log)
    _acq_copy("/var/log/secure",   out/"secure",   "Auth log (RHEL/CentOS)",  log)
    _acq_copy("/var/log/syslog",   out/"syslog",   "Syslog", log)
    _acq_copy("/var/log/messages", out/"messages", "Syslog (RHEL)", log)
    _acq_copy("/var/log/kern.log", out/"kern.log", "Kernel log", log)
    _acq_copy("/var/log/cron",     out/"cron",     "Cron log", log)
    _acq_copy("/var/log/audit/audit.log", out/"audit.log", "Audit log", log)

    # Identity / privilege files
    _acq_copy("/etc/passwd",  out/"passwd",  "passwd", log)
    _acq_copy("/etc/shadow",  out/"shadow",  "shadow (root only)", log)
    _acq_copy("/etc/group",   out/"group",   "group", log)
    _acq_copy("/etc/sudoers", out/"sudoers", "sudoers", log)
    _acq_copy("/etc/hosts",   out/"hosts",   "hosts", log)

    # SSH
    _acq_copy("/etc/ssh/sshd_config", out/"sshd_config", "sshd_config", log)

    # Per-user home directory artifacts: bash/zsh history, SSH keys, crontab
    home_bases = ["/root"] + [str(p) for p in Path("/home").glob("*") if p.is_dir()]
    for home in home_bases:
        user = Path(home).name
        udir = out / "home_users" / user
        _acq_copy(f"{home}/.bash_history", udir/".bash_history", f"{user} bash_history", log)
        _acq_copy(f"{home}/.zsh_history",  udir/".zsh_history",  f"{user} zsh_history", log)
        _acq_copy(f"{home}/.ssh/authorized_keys", udir/"authorized_keys", f"{user} authorized_keys", log)
        _acq_copy(f"{home}/.ssh/known_hosts",     udir/"known_hosts",     f"{user} known_hosts", log)
        _acq_run(f"crontab -u {user} -l 2>/dev/null", out/"crontabs"/f"crontab.{user}",
                  f"{user} crontab", log)
    _acq_copy("/etc/crontab", out/"crontab", "/etc/crontab", log)

    # Live system state snapshots
    _acq_run("ps auxf",            out/"ps_aux.txt",     "Process list (ps auxf)", log)
    _acq_run("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null",
              out/"netstat.txt",   "Network connections", log)
    _acq_run("ip a 2>/dev/null || ifconfig -a 2>/dev/null",
              out/"ifconfig.txt",  "Interfaces", log)
    _acq_run("lsmod",              out/"lsmod.txt",      "Loaded kernel modules", log)
    _acq_run("last -F -n 200",     out/"lastlog.txt",    "Login history (last)", log)
    _acq_run("hostname",           out/"hostname.txt",   "Hostname", log)
    _acq_run("uname -a",           out/"uname.txt",      "uname -a", log)
    _acq_run("uptime",             out/"uptime.txt",     "Uptime", log)
    _acq_copy("/etc/os-release",   out/"os-release.txt", "OS release info", log)
    _acq_copy("/etc/rc.local",     out/"rc.local",       "rc.local", log)

    full_mem = None
    if confirm("  Attempt FULL memory capture (uses/downloads AVML, needs root)?"):
        full_mem = epr_mem_full_capture(out/"memory", lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"))
    if full_mem:
        log.append(f"  [ok]   Memory (full, AVML) -> {Path(full_mem).name}")
    else:
        if full_mem is None:
            log.append("  [skip] Memory: full capture not attempted/failed — process-level dump is the fallback")
        targets = ask("  Dump memory of specific process(es) instead? PID or name, comma-separated (blank to skip): ")
        for t in [x.strip() for x in targets.split(",") if x.strip()]:
            pids = epr_mem_resolve_pids(t, lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"))
            if not pids:
                log.append(f"  [err]  Process memory: could not resolve '{t}' to a running PID")
                continue
            for pid in pids:
                d = epr_mem_dump_process(pid, out/"memory", lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"), name_hint=t if not t.isdigit() else "")
                log.append(f"  [{'ok' if d else 'err'}] Process memory: {t} (PID {pid}) -> {Path(d).name if d else 'failed'}")

    (out/"forensics_run.log").write_text(
        f"Linux acquisition — {datetime.now().isoformat()}\n"
        f"Host: {os.uname().nodename}\nRoot: {is_root}\n\n" + "\n".join(log),
        encoding='utf-8')

    print(f"\n{C.BOLD}{'─'*60}{C.RST}")
    for line in log:
        color = C.GRN if '[ok]' in line else C.YEL if ('[skip]' in line or '[perm]' in line or '[empty]' in line) else C.RED
        print(f"{color}{line}{C.RST}")
    print(f"{'─'*60}")
    collected = sum(1 for l in log if '[ok]' in l)
    print(f"\n{C.BOLD}{C.GRN}  Acquisition complete — {collected} item(s) collected{C.RST}")
    print(f"  {C.CYN}Evidence folder: {out}{C.RST}\n")
    return out

def run_macos_acquisition(output_dir):
    """Collects live evidence from THIS macOS machine. Must be run with python3
    directly on the Mac being investigated — this launcher must be copied there
    first (it cannot reach out to a remote Mac)."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    log = []
    is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    home = os.path.expanduser("~")

    print(f"{C.BOLD}{C.GRN}  🍎 macOS Live Acquisition{C.RST}")
    print(f"  {C.DIM}Target: this machine → {out}{C.RST}")
    if not is_root:
        print(f"  {C.YEL}Not running as root/sudo — TCC.db and other users' files will be"
              f" skipped. Re-run with sudo for a complete collection.{C.RST}")
    print()

    # Persistence — LaunchAgents/LaunchDaemons
    for src_dir, label in [
        (f"{home}/Library/LaunchAgents", "User LaunchAgents"),
        ("/Library/LaunchAgents",        "System LaunchAgents"),
        ("/Library/LaunchDaemons",       "System LaunchDaemons"),
    ]:
        p = Path(src_dir)
        if p.is_dir():
            for plist in p.glob("*.plist"):
                _acq_copy(plist, out/"LaunchAgents"/plist.name, f"{label}: {plist.name}", log)
        else:
            log.append(f"  [skip] {label}: {src_dir} not accessible")

    # Unified logs (last 24h, exported as text) + legacy system.log
    _acq_run('log show --last 24h --style syslog 2>/dev/null',
              out/"system.log.txt", "Unified log export (last 24h)", log, timeout=120)
    _acq_copy("/var/log/system.log", out/"system.log", "Legacy system.log", log)

    # Quarantine / TCC
    _acq_copy(f"{home}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
               out/"QuarantineEventsV2", "Quarantine DB", log)
    _acq_copy(f"{home}/Library/Application Support/com.apple.TCC/TCC.db",
               out/"TCC.db", "TCC privacy DB", log)

    # Shell history / SSH
    _acq_copy(f"{home}/.bash_history", out/".bash_history", "bash_history", log)
    _acq_copy(f"{home}/.zsh_history",  out/".zsh_history",  "zsh_history", log)
    _acq_copy("/etc/ssh/sshd_config",  out/"sshd_config",   "sshd_config", log)
    _acq_copy(f"{home}/.ssh/authorized_keys", out/"authorized_keys", "authorized_keys", log)
    _acq_copy(f"{home}/.ssh/known_hosts",     out/"known_hosts",     "known_hosts", log)

    # Privilege / identity files
    _acq_copy("/etc/passwd",  out/"passwd",  "passwd", log)
    _acq_copy("/etc/sudoers", out/"sudoers", "sudoers", log)
    _acq_run("crontab -l 2>/dev/null", out/"crontab", "crontab", log)

    # Live system state
    _acq_run("ps aux",              out/"ps.txt",         "Process list", log)
    _acq_run("netstat -an",         out/"netstat.txt",    "Network connections", log)
    _acq_run("lsof -i 2>/dev/null", out/"lsof.txt",        "Open network sockets (lsof)", log)
    _acq_run("kextstat",            out/"kextstat.txt",   "Kernel extensions", log)
    _acq_copy("/Library/Receipts/InstallHistory.plist",
               out/"InstallHistory.plist", "Install history", log)

    if confirm("  Launch Fuji for a Full File System acquisition (disk-side evidence, separate from "
               "memory; recommended, especially on Apple Silicon)?"):
        fuji_ok = epr_fuji_acquire(out/"fuji", lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"))
        log.append(f"  [{'ok' if fuji_ok else 'err'}] Fuji launched for Full File System acquisition "
                   f"(complete the acquisition in its window; the resulting DMG/ZIP is separate evidence)"
                   if fuji_ok else "  [err]  Could not launch Fuji - see log above")
    else:
        log.append("  [skip] Fuji Full File System acquisition not requested")

    full_mem = None
    if confirm("  Attempt FULL memory capture (Intel only; not possible on Apple Silicon)?"):
        full_mem = epr_mem_full_capture(out/"memory", lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"))
    if full_mem:
        log.append(f"  [ok]   Memory (full) -> {Path(full_mem).name}")
    else:
        if full_mem is None:
            log.append("  [skip] Memory: full capture not possible/failed on this Mac — process-level dump is the fallback")
        targets = ask("  Dump memory of specific process(es) instead? PID or name, comma-separated (blank to skip): ")
        for t in [x.strip() for x in targets.split(",") if x.strip()]:
            pids = epr_mem_resolve_pids(t, lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"))
            if not pids:
                log.append(f"  [err]  Process memory: could not resolve '{t}' to a running PID")
                continue
            for pid in pids:
                d = epr_mem_dump_process(pid, out/"memory", lambda l, x: print(f"  {C.CYN}[*]{C.RST} {x}"), name_hint=t if not t.isdigit() else "")
                log.append(f"  [{'ok' if d else 'err'}] Process memory: {t} (PID {pid}) -> {Path(d).name if d else 'failed'}")

    (out/"forensics_run.log").write_text(
        f"macOS acquisition — {datetime.now().isoformat()}\nRoot: {is_root}\n\n" + "\n".join(log),
        encoding='utf-8')

    print(f"\n{C.BOLD}{'─'*60}{C.RST}")
    for line in log:
        color = C.GRN if '[ok]' in line else C.YEL if ('[skip]' in line or '[perm]' in line or '[empty]' in line) else C.RED
        print(f"{color}{line}{C.RST}")
    print(f"{'─'*60}")
    collected = sum(1 for l in log if '[ok]' in l)
    print(f"\n{C.BOLD}{C.GRN}  Acquisition complete — {collected} item(s) collected{C.RST}")
    print(f"  {C.CYN}Evidence folder: {out}{C.RST}\n")
    return out

def run_windows_acquisition(output_dir):
    """Collects live evidence from THIS Windows machine. Must be run with a
    Windows-native Python directly on the Windows box being investigated — this
    launcher must be copied there first (it cannot reach out to a remote host).
    NOTE: written to correct, documented wevtutil/reg.exe syntax but could not
    be executed/verified in this (Linux) environment — test on a real Windows
    box and report back if any command needs adjustment."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    log = []
    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass

    print(f"{C.BOLD}{C.GRN}  🪟 Windows Live Acquisition{C.RST}")
    print(f"  {C.DIM}Target: this machine → {out}{C.RST}")
    if not is_admin:
        print(f"  {C.YEL}Not running as Administrator — EVTX export and registry save will"
              f" likely fail. Re-run this script from an elevated (Run as Administrator)"
              f" terminal for a complete collection.{C.RST}")
    print()

    # EVTX export — the channels Hayabusa/Chainsaw/deep-parse look for
    evtx_dir = out/"winevt"
    evtx_dir.mkdir(exist_ok=True)
    _edr_profiles = epr_detect_edr(win_log)
    channels = epr_build_evtx_channel_list(_edr_profiles, win_log)
    # Detect SIEM/XDR/log-forwarding agents on the live machine so the report can advise
    # the analyst to pull historical data from the detected destinations (Splunk, Elastic, Wazuh etc.)
    _agents = epr_detect_agents(None, win_log)
    for _ag in _agents:
        _dest_txt = ", ".join(_ag.get("destinations", [])) or "config not parsed"
        log.append(f"  [ok]   Telemetry agent: {_ag['name']} ({_ag['type']}) - {_dest_txt}")
    if not _agents:
        log.append("  [info] No additional telemetry agents (SIEM forwarders/XDR/syslog) detected")
    for ch in channels:
        safe_name = ch.replace("/", "_") + ".evtx"
        dst = evtx_dir/safe_name
        try:
            r = subprocess.run(f'wevtutil epl "{ch}" "{dst}"', shell=True,
                                capture_output=True, text=True, timeout=120)
            if dst.exists() and dst.stat().st_size > 0:
                log.append(f"  [ok]   EVTX export: {ch} -> {safe_name}")
            else:
                log.append(f"  [skip] EVTX export: {ch} — {(r.stderr or '').strip()[:120] or 'channel not found/empty'}")
        except subprocess.TimeoutExpired:
            log.append(f"  [err]  EVTX export: {ch} — timed out after 120s (log may be very large); try exporting it manually later")
        except Exception as _ex:
            log.append(f"  [err]  EVTX export: {ch} — {type(_ex).__name__}: {_ex}")

    # Registry hives — reg save produces a binary hive copy python-registry can parse
    reg_dir = out/"registry"
    reg_dir.mkdir(exist_ok=True)
    for hive, dst_name in [
        ("HKLM\\SYSTEM",  "SYSTEM"), ("HKLM\\SOFTWARE", "SOFTWARE"),
        ("HKLM\\SAM",     "SAM"),    ("HKLM\\SECURITY",  "SECURITY"),
    ]:
        dst = reg_dir/dst_name
        try:
            r = subprocess.run(f'reg save "{hive}" "{dst}" /y', shell=True,
                                capture_output=True, text=True, timeout=60)
            if dst.exists():
                log.append(f"  [ok]   Registry hive: {hive} -> {dst_name}")
            else:
                log.append(f"  [perm] Registry hive: {hive} — {(r.stderr or '').strip()[:120]}")
        except subprocess.TimeoutExpired:
            log.append(f"  [err]  Registry hive: {hive} — timed out after 60s")
        except Exception as _ex:
            log.append(f"  [err]  Registry hive: {hive} — {type(_ex).__name__}: {_ex}")

    # Network / process / scheduled tasks
    _acq_run("netstat -ano", out/"network"/"netstat.txt", "Network connections", log)
    _acq_run("tasklist /v",  out/"artifacts"/"tasklist.txt", "Running processes", log)
    _acq_run("schtasks /query /fo LIST /v", out/"artifacts"/"scheduled_tasks.txt",
              "Scheduled tasks", log)
    _acq_run("wmic service get name,displayname,pathname,startmode",
              out/"artifacts"/"services.txt", "Services", log)

    full_mem = None
    if confirm("  Attempt FULL memory capture (downloads/runs WinPmem, needs Administrator)?"):
        full_mem = epr_mem_full_capture(out/"memory", win_log)
    if full_mem:
        log.append(f"  [ok]   Memory (full, WinPmem) -> {Path(full_mem).name}")
    else:
        if full_mem is None:
            log.append("  [skip] Memory: full capture not attempted/failed — process-level dump is the fallback")
        targets = ask("  Dump memory of specific process(es) instead? PID or name, comma-separated (blank to skip): ")
        for t in [x.strip() for x in targets.split(",") if x.strip()]:
            pids = epr_mem_resolve_pids(t, win_log)
            if not pids:
                log.append(f"  [err]  Process memory: could not resolve '{t}' to a running PID")
                continue
            for pid in pids:
                d = epr_mem_dump_process(pid, out/"memory", win_log, name_hint=t if not t.isdigit() else "")
                log.append(f"  [{'ok' if d else 'err'}] Process memory: {t} (PID {pid}) -> {Path(d).name if d else 'failed'}")

    (out/"forensics_run.log").write_text(
        f"Windows acquisition — {datetime.now().isoformat()}\nAdmin: {is_admin}\n\n" + "\n".join(log),
        encoding='utf-8')

    print(f"\n{C.BOLD}{'─'*60}{C.RST}")
    for line in log:
        color = C.GRN if '[ok]' in line else C.YEL if ('[skip]' in line or '[perm]' in line) else C.RED
        print(f"{color}{line}{C.RST}")
    print(f"{'─'*60}")
    collected = sum(1 for l in log if '[ok]' in l)
    print(f"\n{C.BOLD}{C.GRN}  Acquisition complete — {collected} item(s) collected{C.RST}")
    print(f"  {C.CYN}Evidence folder: {out}{C.RST}\n")
    return out


def acq_fix_permissions(out, log=print, write_meta=True):
    """Collected copies are created by the elevated process (root / Administrator). Hand them back to the person who ran the
    tool so the analysis can read them without elevation. Original owner/mode of every source file is recorded first."""
    out = Path(out)
    try:
        if not write_meta: raise StopIteration
        rows = ["collected_file,source_path,original_mode,original_uid,original_gid"] + [",".join(f'"{x}"' for x in r) for r in _ACQ_LEDGER]
        (out / "ORIGINAL_FILE_METADATA.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    except Exception: pass
    if os.name == "posix":
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        n = 0
        for p_ in [out] + list(out.rglob("*")):
            try:
                if uid and hasattr(os, "geteuid") and os.geteuid() == 0:
                    os.chown(p_, int(uid), int(gid or uid), follow_symlinks=False)
                if not p_.is_symlink():
                    os.chmod(p_, (0o750 if p_.is_dir() else 0o640) | (0o100 if (p_.stat().st_mode & 0o100 and p_.is_file()) else 0))
                n += 1
            except Exception: pass
        who = f"uid {uid}" if uid else "the current user"
        log(f"  {C.CYN}[*] Evidence permissions normalised ({n} items): owner = {who}, no world access{C.RST}")
    else:
        user = os.environ.get("USERNAME")
        if user:
            r = subprocess.run(f'icacls "{out}" /grant "{user}:(OI)(CI)F" /T /C /Q', shell=True, capture_output=True, text=True)
            log(f"  {C.CYN}[*] Evidence ACL: full control granted to {user} (rc={r.returncode}){C.RST}")


def _acq_wrap(fn):
    def w(output_dir, *a, **k):
        _ACQ_LEDGER.clear()
        res = fn(output_dir, *a, **k)
        try: acq_fix_permissions(res or output_dir)
        except Exception as e: print(f"  [perm] could not normalise permissions: {e}")
        return res
    w.__name__ = fn.__name__
    return w


run_linux_acquisition = _acq_wrap(run_linux_acquisition)
run_macos_acquisition = _acq_wrap(run_macos_acquisition)
run_windows_acquisition = _acq_wrap(run_windows_acquisition)


# ══════════════════════════════════════════════════════════════════════════════
# FLOWS
# ══════════════════════════════════════════════════════════════════════════════

def windows_flow():
    banner()
    print(f"{C.BOLD}  🪟 Windows Forensics Setup{C.RST}\n")
    print(f"  {C.DIM}Tools: Hayabusa + Chainsaw + Volatility3 + python-evtx + python-registry{C.RST}\n")

    evidence            = get_evidence_path("windows")
    output              = get_output_path()
    vt_key, abuse_key   = get_api_keys()
    skip_mem, evtx_only, skip_setup = get_windows_options()

    # Confirm
    banner()
    print(f"{C.BOLD}  📋 Configuration Summary:{C.RST}\n")
    print(f"  {'Evidence':<15}: {C.GRN}{evidence}{C.RST}")
    print(f"  {'Output':<15}: {C.GRN}{output}{C.RST}")
    print(f"  {'VT Key':<15}: {C.GRN}{'Yes' if vt_key else 'No'}{C.RST}")
    print(f"  {'Skip Memory':<15}: {C.YEL if skip_mem else C.GRN}{skip_mem}{C.RST}")
    print(f"  {'Skip Setup':<15}: {C.YEL if skip_setup else C.GRN}{skip_setup}{C.RST}")
    print()

    if confirm("  Start analysis?"):
        run_windows_analysis(evidence, output, vt_key, abuse_key,
                              skip_mem, evtx_only, skip_setup)

def linux_flow(os_type="ubuntu"):
    banner()
    label = "Kali Linux" if os_type == "kali" else "Linux (Ubuntu / CentOS / RHEL)"
    print(f"{C.BOLD}  🐧 {label} Forensics Setup{C.RST}\n")
    print(f"  {C.DIM}Tools: python-evtx patterns + auditd + SSH + crontab + kernel analysis{C.RST}\n")

    evidence             = get_evidence_path(os_type)
    output               = get_output_path()
    vt_key, abuse_key    = get_api_keys()
    skip_mem, need_sudo, skip_setup = get_linux_options(os_type)

    # Confirm
    banner()
    print(f"{C.BOLD}  📋 Configuration Summary:{C.RST}\n")
    print(f"  {'OS Type':<15}: {C.CYN}{'Kali Linux' if os_type=='kali' else 'Ubuntu/CentOS'}{C.RST}")
    print(f"  {'Evidence':<15}: {C.GRN}{evidence}{C.RST}")
    print(f"  {'Output':<15}: {C.GRN}{output}{C.RST}")
    print(f"  {'VT Key':<15}: {C.GRN}{'Yes' if vt_key else 'No'}{C.RST}")
    print(f"  {'Sudo':<15}: {C.GRN if need_sudo else C.YEL}{need_sudo}{C.RST}")
    print(f"  {'Skip Memory':<15}: {C.YEL if skip_mem else C.GRN}{skip_mem}{C.RST}")
    print(f"  {'Skip Setup':<15}: {C.YEL if skip_setup else C.GRN}{skip_setup}{C.RST}")
    print()

    if confirm("  Start analysis?"):
        run_linux_analysis(evidence, output, vt_key, abuse_key,
                            skip_mem, need_sudo, os_type, skip_setup)

def macos_flow():
    banner()
    print(f"{C.BOLD}  🍎 macOS Forensics Setup{C.RST}\n")
    print(f"  {C.DIM}Modules: LaunchAgents/Daemons (persistence), Quarantine, Unified Logs, TCC, Kexts, SSH, Network{C.RST}\n")

    evidence           = get_evidence_path("macos")
    output             = get_output_path()
    vt_key, abuse_key  = get_api_keys()
    print()
    skip_setup = not confirm("  Check/install requirements (Volatility3, Python packages, 7z/unrar)?")

    banner()
    print(f"{C.BOLD}  📋 Configuration Summary:{C.RST}\n")
    print(f"  {'Evidence':<15}: {C.GRN}{evidence}{C.RST}")
    print(f"  {'Output':<15}: {C.GRN}{output}{C.RST}")
    print(f"  {'VT Key':<15}: {C.GRN}{'Yes' if vt_key else 'No'}{C.RST}")
    print(f"  {'Skip Setup':<15}: {C.YEL if skip_setup else C.GRN}{skip_setup}{C.RST}")
    print()

    if confirm("  Start analysis?"):
        run_macos_analysis(evidence, output, vt_key, abuse_key, skip_setup)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def forensics_menu_loop():
    while True:
        choice = main_menu()

        if choice == "1":
            windows_flow()

        elif choice == "2":
            linux_flow("ubuntu")

        elif choice == "3":
            linux_flow("kali")

        elif choice == "4":
            macos_flow()

        elif choice == "5":
            tool_status()

        elif choice == "6":
            return  # back to mode menu

        else:
            print(f"\n{C.RED}  Invalid choice. Please enter 1-6.{C.RST}")
            import time; time.sleep(1)

def main():
    while True:
        mode = mode_menu()

        if mode == "1":
            forensics_menu_loop()

        elif mode == "2":
            acquisition_flow()

        elif mode == "3":
            clear()
            print(f"\n{C.CYN}  Exiting Forensics Launcher. Stay safe!{C.RST}\n")
            sys.exit(0)

        else:
            print(f"\n{C.RED}  Invalid choice. Please enter 1-3.{C.RST}")
            import time; time.sleep(1)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: WINDOWS FORENSICS MODULE (all top-level names prefixed win_*)
# Tools: Hayabusa + Chainsaw + Volatility3 + python-evtx + Custom Analysis
# ══════════════════════════════════════════════════════════════════════════════


# ── Colors ────────────────────────────────────────────────────────────────────
class win_C:
    RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"; CYN="\033[96m"
    BOLD="\033[1m"; RST="\033[0m";  BLU="\033[94m"; MAG="\033[95m"

def win_log(lvl, msg):
    icons={"INFO":f"{win_C.CYN}[*]","OK":f"{win_C.GRN}[+]","WARN":f"{win_C.YEL}[!]",
           "CRIT":f"{win_C.RED}[!!!]","STEP":f"{win_C.BLU}[→]","HEAD":f"{win_C.MAG}[■]"}
    print(f"{icons.get(lvl,'[?]')} {msg}{win_C.RST}")

def win_banner():
    print(f"""{win_C.CYN}{win_C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║        Windows Forensics Master Analyzer v3.0                        ║
║  Hayabusa │ Chainsaw │ Volatility3 │ EVTX │ Network │ EDR  │ DNS   ║
╚══════════════════════════════════════════════════════════════════════╝
{win_C.RST}""")

# ── Helpers ───────────────────────────────────────────────────────────────────
def win_is_private(ip):
    try:
        o = ipaddress.ip_address(ip.strip())
        return o.is_private or o.is_loopback or o.is_link_local
    except: return True

def win_extract_ips(t):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', t)

def extract_domains(t):
    return re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', t)

def run_cmd(cmd, timeout=900):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", 1
    except Exception as e:
        return "", str(e), 1

def win_new_results():
    return {
        "critical":[], "high":[], "medium":[],
        "external_ips":set(), "suspicious_domains":set(),
        "c2_indicators":[], "threat_intel":[], "dns_hits":[],
        "hayabusa":[], "chainsaw":[], "volatility":[],
        "network_summary":{}, "cisco_hits":[]
    }

def win_add(results, sev, src, desc, data=None, file=""):
    e = {"severity":sev,"source":src,"desc":desc,
         "data":data or {},"file":str(file),
         "timestamp":datetime.now().isoformat()}
    if   sev == "CRITICAL": results["critical"].append(e)
    elif sev == "HIGH":     results["high"].append(e)
    else:                   results["medium"].append(e)

# ── IOC Lists ─────────────────────────────────────────────────────────────────
win_SUSP_PORTS = {
    4444:"Metasploit",1234:"Common RAT",31337:"Back Orifice",
    8888:"C2",9999:"C2",6666:"C2",5555:"RAT/ADB",
    1337:"Hacker port",12345:"NetBus",54321:"Reverse shell",
    65535:"Max port",9001:"Tor",9050:"Tor SOCKS",
}

MALWARE_PATTERNS = [
    (re.compile(r'powershell.*-[Ee][Nn][Cc]',re.I),          "Encoded PowerShell"),
    (re.compile(r'powershell.*(-[Ww]indow\s*[Hh]idden|-[Ww]\s*[Hh]idden)',re.I),"Hidden PS Window"),
    (re.compile(r'downloadstring|downloadfile|webclient',re.I),"PS Download Cradle"),
    (re.compile(r'\bIEX\b|\bInvoke-Expression\b',re.I),       "PowerShell IEX"),
    (re.compile(r'certutil.+(-decode|-urlcache)',re.I),        "Certutil LOLBin"),
    (re.compile(r'\bmshta\b.+http',re.I),                     "MSHTA Remote"),
    (re.compile(r'\bregsvr32\b.+(scrobj|http)',re.I),          "Regsvr32 Squiblydoo"),
    (re.compile(r'vssadmin.+delete.+shadows',re.I),            "VSS Delete (Ransomware)"),
    (re.compile(r'wbadmin.+delete|bcdedit.+no',re.I),          "Backup Destroy"),
    (re.compile(r'mimikatz|sekurlsa|lsadump|kerberos::',re.I), "Mimikatz/Cred Dump"),
    (re.compile(r'net\s+(user|localgroup).+\/add',re.I),       "Account Manipulation"),
    (re.compile(r'psexec|wmiexec|dcomexec|smbexec',re.I),      "Lateral Movement Tool"),
    (re.compile(r'netsh.+portproxy',re.I),                     "Port Proxy Tunnel"),
    (re.compile(r'ssh.+-[RLD]\s+\d+:',re.I),                  "SSH Tunnel"),
    (re.compile(r'schtasks.+\/create',re.I),                   "Schtask Persistence"),
    (re.compile(r'reg\s+(add|export).+(run|startup)',re.I),    "Registry Persistence"),
    (re.compile(r'wscript|cscript',re.I),                      "Script Host"),
    (re.compile(r'bitsadmin.+transfer',re.I),                  "BITSAdmin LOLBin"),
    (re.compile(r'rundll32.+javascript|rundll32.+shell32',re.I),"Rundll32 Abuse"),
]

SUSP_EVTX = {
    4625:("HIGH","Failed Login"),4648:("MEDIUM","Explicit Cred Use"),
    4720:("HIGH","User Created"),4732:("HIGH","Added to Admin Group"),
    4688:("MEDIUM","Process Creation"),4697:("HIGH","Service Installed"),
    7045:("HIGH","New Service"),4103:("HIGH","PS Module Log"),
    4104:("HIGH","PS Script Block"),4698:("HIGH","Schtask Created"),
    4702:("MEDIUM","Schtask Modified"),4657:("MEDIUM","Registry Modified"),
    1102:("CRITICAL","Audit Log Cleared ⚠️"),104:("CRITICAL","System Log Cleared ⚠️"),
    4776:("MEDIUM","NTLM Auth"),5156:("LOW","Firewall Connection"),
    3:("MEDIUM","Sysmon Net Connect"),
}

# EDR-specific Event IDs (Cisco Secure Endpoint / AMP naming kept as example keys)
CISCO_EVTX = {
    # Common EDR event categories (works across vendors via EDR_VENDOR_NAMES match)
    "threat_detected":       ("CRITICAL","EDR: Threat Detected"),
    "malware_detected":      ("CRITICAL","EDR: Malware Detected"),
    "quarantine":            ("HIGH",    "EDR: File Quarantined"),
    "cloud_ioc":             ("CRITICAL","EDR: Cloud IOC Hit"),
    "exploit_prevented":     ("CRITICAL","EDR: Exploit Prevented"),
    "ransomware":            ("CRITICAL","EDR: Ransomware Activity"),
    "policy_violation":      ("HIGH",    "EDR: Policy Violation"),
    "network_flow":          ("HIGH",    "EDR: Suspicious Network Flow"),
    "scan_completed":        ("MEDIUM",  "EDR: Scan Completed"),
    "engine_error":          ("MEDIUM",  "EDR: Engine Error"),
}

WHITELIST_DOMAINS = {
    'microsoft.com','windows.com','windowsupdate.com','msftconnecttest.com',
    'msocsp.com','digicert.com','google.com','googleapis.com',
    'gstatic.com','cloudflare.com','akamai.com','akamaiedge.net',
    'symantec.com','norton.com','cisco.com','amp.cisco.com',
}

SUSP_DOMAIN_RE = [
    re.compile(r'\.onion$',re.I), re.compile(r'\.bit$',re.I),
    re.compile(r'dyndns|no-ip|ddns|ngrok|serveo|pagekite',re.I),
    re.compile(r'[a-z0-9]{20,}\.(com|net|org|info)',re.I),
    re.compile(r'pastebin|paste\.ee|hastebin',re.I),
    re.compile(r'discord(app)?\.com/api/webhooks',re.I),
    re.compile(r'raw\.githubusercontent|gist\.github',re.I),
]

REG_PERSIST_KEYS = [
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'SYSTEM\CurrentControlSet\Services',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    r'SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
]

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: TOOL SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def _host_arch_keywords():
    """Returns (positive_arch_keywords, foreign_arch_keywords_to_exclude) for the
    CPU architecture this script is actually running on — used to pick the right
    release asset instead of relying on filename blacklists, since e.g. 'arm' as
    an exclude keyword does NOT match 'aarch64' as a substring (that bug shipped
    an ARM binary on an x86_64 host and crashed with 'Exec format error')."""
    import platform
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return (["x64", "x86_64", "amd64"], ["aarch64", "arm64", "armv7", "arm"])
    elif m in ("aarch64", "arm64"):
        return (["aarch64", "arm64"], ["x64", "x86_64", "amd64"])
    else:
        # Unknown/other arch — don't filter by arch, just report it
        return ([], [])

def _github_latest_asset_url(repo, include_kw, exclude_kw=()):
    """Resolve the real download URL for the latest GitHub release asset matching
    include_kw (all must appear in the filename, lowercased) and none of exclude_kw.
    This avoids hardcoding a specific filename, since release asset names change
    between versions (e.g. gnu/musl, x64/intel/arm, lin/linux) and a fixed guess
    like '.../latest/download/hayabusa-linux-x64.zip' goes stale and 404s."""
    import urllib.request, json as _json
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(api_url, headers={
            "User-Agent": "forensics-unified-tool",
            "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = _json.loads(resp.read().decode())
        for asset in data.get("assets", []):
            name = asset["name"].lower()
            if all(k in name for k in include_kw) and not any(k in name for k in exclude_kw):
                return asset["browser_download_url"], data.get("tag_name", "")
        return None, data.get("message") or "no matching asset found"
    except Exception as e:
        return None, str(e)

def setup_common_tools(tools_dir):
    """Checks/installs everything shared across Windows/Linux/macOS flows:
    Volatility3, required Python packages, and system archive tools (7z/unrar).
    Returns a dict of what's available so callers can report it."""
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    paths = {}

    win_log("HEAD", "Checking common requirements (Volatility3, Python packages, archive tools)...")

    # ── Volatility3 (memory analysis — used by Windows/Linux/macOS) ────────────
    out, _, rc = run_cmd("vol --help 2>/dev/null", timeout=10)
    if rc == 0:
        win_log("OK", "Volatility3 available")
        paths["volatility"] = "vol"
    else:
        win_log("INFO", "Volatility3 not found — installing (pip3 install volatility3)...")
        run_cmd("pip3 install volatility3 --break-system-packages -q", timeout=180)
        out, _, rc = run_cmd("vol --help 2>/dev/null", timeout=10)
        paths["volatility"] = "vol" if rc == 0 else None
        win_log("OK" if paths["volatility"] else "WARN",
            "Volatility3 installed" if paths["volatility"] else
            "Volatility3 install failed — memory analysis will be skipped")

    # ── Python packages ───────────────────────────────────────────────────────
    py_pkgs = {
        "python-evtx":     "Evtx.Evtx",  # Windows EVTX deep parsing
        "tqdm":            "tqdm",       # progress bars
        "requests":        "requests",   # threat intel (VT/AbuseIPDB)
        "python-registry": "Registry",   # Windows registry hive parsing
    }
    for pip_name, import_name in py_pkgs.items():
        try:
            __import__(import_name)
            win_log("OK", f"{pip_name} available")
        except ImportError:
            win_log("INFO", f"Installing {pip_name}...")
            out, err, rc = run_cmd(f"pip3 install {pip_name} --break-system-packages -q", timeout=90)
            try:
                __import__(import_name)
                win_log("OK", f"{pip_name} installed")
            except ImportError:
                win_log("WARN", f"{pip_name} install failed — related analysis will be limited")

    # ── System archive tools (7z / unrar — password-protected ZIP/7z/RAR) ──────
    import shutil as _shutil
    if _shutil.which("7z") or _shutil.which("7za"):
        win_log("OK", "7z available")
        paths["7z"] = True
    else:
        win_log("INFO", "7z not found — attempting install (apt-get)...")
        _, _, rc = run_cmd(
            "sudo -n apt-get install -y p7zip-full -q 2>/dev/null || "
            "apt-get install -y p7zip-full -q 2>/dev/null", timeout=90)
        paths["7z"] = bool(_shutil.which("7z") or _shutil.which("7za"))
        if paths["7z"]:
            win_log("OK", "7z installed")
        else:
            win_log("WARN", "7z not auto-installed — sudo needs a password, which this "
                             "script can't type for you. Run once manually, then re-run this tool:")
            win_log("WARN", "    sudo apt-get install -y p7zip-full")
            win_log("WARN", ".7z archives in evidence will be skipped until then")

    if _shutil.which("unrar"):
        win_log("OK", "unrar available")
        paths["unrar"] = True
    else:
        win_log("INFO", "unrar not found — attempting non-interactive install (apt-get)...")
        _, _, rc = run_cmd(
            "sudo -n apt-get install -y unrar -q 2>/dev/null || "
            "apt-get install -y unrar -q 2>/dev/null", timeout=90)
        paths["unrar"] = bool(_shutil.which("unrar"))
        if paths["unrar"]:
            win_log("OK", "unrar installed")
        else:
            win_log("WARN", "unrar not auto-installed — sudo needs a password, which this "
                             "script can't type for you. Run once manually, then re-run this tool:")
            win_log("WARN", "    sudo apt-get install -y unrar")
            win_log("WARN", "    (if 'unable to locate package': sudo add-apt-repository multiverse && sudo apt-get update)")
            win_log("WARN", ".rar archives in evidence will be skipped until then")

    return paths

def setup_tools(tools_dir):
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    paths = {}

    win_log("HEAD", "Setting up analysis tools...")

    # ── Hayabusa ──────────────────────────────────────────────────────────────
    import platform as _pf_hb
    _hb_ext = ".exe" if _pf_hb.system() == "Windows" else ""
    hayabusa_bin = tools_dir / "hayabusa" / f"hayabusa{_hb_ext}"
    if hayabusa_bin.exists():
        win_log("OK", f"Hayabusa already installed: {hayabusa_bin}")
        paths["hayabusa"] = str(hayabusa_bin)
    else:
        win_log("INFO", "Looking up latest Hayabusa release (GitHub API)...")
        import urllib.request, zipfile
        arch_kw, foreign_arch_kw = _host_arch_keywords()
        win_log("INFO", f"  Host CPU: {__import__('platform').machine()} "
                         f"— matching assets containing {arch_kw or 'any arch'}")
        # Try to positively match this host's architecture + libc flavour (gnu
        # preferred over musl on a typical Ubuntu/Debian host), excluding any
        # asset built for a different CPU architecture.
        url = info = None
        import platform as _pf
        _is_win = _pf.system() == "Windows"
        if _is_win:
            # Windows: look for win-x64 .exe asset
            url, info = _github_latest_asset_url("Yamato-Security/hayabusa",
                include_kw=["win", "x64"], exclude_kw=["lin", "mac"])
            if not url:
                url, info = _github_latest_asset_url("Yamato-Security/hayabusa",
                    include_kw=[".exe"], exclude_kw=["lin", "mac"])
        else:
            for arch_term in (arch_kw or [""]):
                for libc in ("gnu", ""):
                    kws = ["lin", arch_term] + ([libc] if libc else [])
                    url, info = _github_latest_asset_url("Yamato-Security/hayabusa",
                        include_kw=[k for k in kws if k],
                        exclude_kw=["win", ".exe", "mac"] + foreign_arch_kw)
                    if url: break
                if url: break
            if not url:
                url, info = _github_latest_asset_url("Yamato-Security/hayabusa",
                    include_kw=["lin"], exclude_kw=["win", ".exe", "mac"] + foreign_arch_kw)
        if url:
            win_log("INFO", f"Downloading Hayabusa {info}: {url.rsplit('/',1)[-1]}")
        else:
            win_log("WARN", f"Could not resolve Hayabusa download URL ({info})")
            win_log("WARN", "Manual install: https://github.com/Yamato-Security/hayabusa/releases")
            url = None
        zip_path = tools_dir / "hayabusa.zip"
        try:
            if not url:
                raise RuntimeError("no download URL resolved")
            urllib.request.urlretrieve(url, zip_path)
            haya_dir = tools_dir / "hayabusa"
            haya_dir.mkdir(exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(haya_dir)
            # Find the actual binary — the release zip also ships config assets like
            # config/html_report/hayabusa_report.css that also match "hayabusa*" by
            # name, so filename alone isn't reliable. The compiled binary is always
            # by far the largest "hayabusa*"-named file (10+ MB vs KBs for assets).
            candidates = [b for b in haya_dir.rglob("hayabusa*") if b.is_file()]
            bins = sorted(candidates, key=lambda b: b.stat().st_size, reverse=True)
            if bins and bins[0].stat().st_size > 1_000_000:  # sanity floor: 1MB
                actual_bin = bins[0]
                actual_bin.chmod(0o755)
                # Move/rename to the standard flat path the rest of the tool expects
                target = haya_dir / f"hayabusa{_hb_ext}"
                if actual_bin != target:
                    shutil.move(str(actual_bin), str(target))
                paths["hayabusa"] = str(target)
                win_log("OK", "Hayabusa downloaded")
            else:
                win_log("WARN", "Hayabusa zip extracted but no binary found inside")
            zip_path.unlink(missing_ok=True)
        except Exception as e:
            win_log("WARN", f"Hayabusa download failed: {e}")
            win_log("WARN", "Manual install: https://github.com/Yamato-Security/hayabusa/releases")

    # ── Chainsaw ──────────────────────────────────────────────────────────────
    import platform as _pf_cb
    _cb_ext = ".exe" if _pf_cb.system() == "Windows" else ""
    chainsaw_bin = tools_dir / "chainsaw" / f"chainsaw{_cb_ext}"
    if chainsaw_bin.exists():
        win_log("OK", f"Chainsaw already installed: {chainsaw_bin}")
        paths["chainsaw"] = str(chainsaw_bin)
    else:
        win_log("INFO", "Looking up latest Chainsaw release (GitHub API)...")
        import urllib.request, tarfile
        arch_kw, foreign_arch_kw = _host_arch_keywords()
        win_log("INFO", f"  Host CPU: {__import__('platform').machine()} "
                         f"— matching assets containing {arch_kw or 'any arch'}")
        import platform as _pf_cs2
        url = info = None
        if _pf_cs2.system() == "Windows":
            # Windows: prefer the win-x64 zip
            url, info = _github_latest_asset_url("WithSecureLabs/chainsaw",
                include_kw=["win", "x86_64"], exclude_kw=["lin", "mac"])
            if not url:
                url, info = _github_latest_asset_url("WithSecureLabs/chainsaw",
                    include_kw=[".exe"], exclude_kw=["lin", "mac"])
            if not url:
                url = "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-pc-windows-msvc.zip"
                win_log("WARN", f"GitHub API lookup failed ({info}), trying known Windows filename as fallback")
        else:
            for arch_term in (arch_kw or [""]):
                kws = ["linux", arch_term]
                url, info = _github_latest_asset_url("WithSecureLabs/chainsaw",
                    include_kw=[k for k in kws if k],
                    exclude_kw=["win", ".exe", "mac"] + foreign_arch_kw)
                if url: break
            if not url:
                url, info = _github_latest_asset_url("WithSecureLabs/chainsaw",
                    include_kw=["linux"], exclude_kw=["win", ".exe", "mac"] + foreign_arch_kw)
            if not url:
                if "x86_64" in arch_kw or not arch_kw:
                    url = "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
                    win_log("WARN", f"GitHub API lookup failed ({info}), trying known x86_64 filename as fallback")
                else:
                    win_log("WARN", f"Could not resolve a Chainsaw asset for this CPU architecture ({info})")
                    win_log("WARN", "Manual install: https://github.com/WithSecureLabs/chainsaw/releases")
        if url:
            win_log("INFO", f"Downloading Chainsaw {info or ''}: {url.rsplit('/',1)[-1]}")
        tar_path = tools_dir / "chainsaw.tar.gz"
        try:
            if not url:
                raise RuntimeError("no download URL resolved")
            urllib.request.urlretrieve(url, tar_path)
            with tarfile.open(tar_path, 'r:gz') as t:
                t.extractall(tools_dir)
            # Find the actual binary by size — same reasoning as Hayabusa above:
            # the archive may also contain small "chainsaw*"-named config/mapping
            # files, and the compiled binary is always the largest match by far.
            candidates = [b for b in tools_dir.rglob("chainsaw*") if b.is_file()]
            bins = sorted(candidates, key=lambda b: b.stat().st_size, reverse=True)
            if bins and bins[0].stat().st_size > 1_000_000:  # sanity floor: 1MB
                actual_bin = bins[0]
                actual_bin.chmod(0o755)
                target = tools_dir/"chainsaw"/f"chainsaw{_cb_ext}"
                target.parent.mkdir(exist_ok=True)
                if actual_bin != target:
                    shutil.move(str(actual_bin), str(target))
                paths["chainsaw"] = str(target)
                win_log("OK", "Chainsaw downloaded")
            else:
                win_log("WARN", "Chainsaw archive extracted but no binary found")
            tar_path.unlink(missing_ok=True)
        except Exception as e:
            win_log("WARN", f"Chainsaw download failed: {e}")

    # ── Sigma Rules ───────────────────────────────────────────────────────────
    sigma_dir = tools_dir / "sigma"
    if sigma_dir.exists():
        win_log("OK", "Sigma rules already present")
        paths["sigma"] = str(sigma_dir)
    else:
        win_log("INFO", "Cloning Sigma rules (may take a moment)...")
        out, err, rc = run_cmd(
            f"git clone --depth=1 -q https://github.com/SigmaHQ/sigma.git {sigma_dir}",
            timeout=300)
        if rc == 0:
            win_log("OK", "Sigma rules cloned")
            paths["sigma"] = str(sigma_dir)
        else:
            win_log("WARN", f"Sigma clone failed: {err[:100]}")

    # ── Chainsaw mappings ─────────────────────────────────────────────────────
    mapping_candidates = [
        tools_dir / "chainsaw" / "mappings" / "sigma-event-logs-all.yml",
        tools_dir / "mappings" / "sigma-event-logs-all.yml",
    ]
    for m in mapping_candidates:
        if m.exists():
            paths["chainsaw_mapping"] = str(m)
            break

    # ── Volatility3 + Python packages + archive tools (shared helper) ──────────
    paths.update(setup_common_tools(tools_dir))

    return paths

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: HAYABUSA
# ═══════════════════════════════════════════════════════════════════════════════

def run_hayabusa(evtx_dir, output_dir, hayabusa_bin, results):
    win_log("HEAD", "Running Hayabusa EVTX analysis...")

    if not hayabusa_bin or not Path(hayabusa_bin).exists():
        win_log("WARN", "Hayabusa not found — skipping")
        return

    csv_out = Path(output_dir) / "hayabusa_timeline.csv"
    json_out = Path(output_dir) / "hayabusa_results.jsonl"

    # Hayabusa v4.x merged csv-timeline/json-timeline into one 'dfir-timeline'
    # command with an -t/--output-type flag (csv/json/jsonl). The rules folder
    # also defaults to './rules' relative to the current working directory —
    # NOT relative to the binary — so it must be passed explicitly or Hayabusa
    # silently loads zero rules when run from outside its own tools folder.
    rules_dir = Path(hayabusa_bin).parent / "rules"
    rules_arg = f'-r "{rules_dir}" ' if rules_dir.exists() else ""

    # CSV timeline — skip re-running if a previous run already produced it
    if csv_out.exists() and csv_out.stat().st_size > 100:
        win_log("OK", f"  Hayabusa timeline already exists, reusing: {csv_out}")
        _parse_hayabusa_csv(csv_out, results)
    else:
        cmd = (f'"{hayabusa_bin}" dfir-timeline '
               f'-d "{evtx_dir}" '
               f'-o "{csv_out}" '
               f'-t csv {rules_arg}'
               f'--no-wizard -q')
        win_log("INFO", "  Hayabusa: generating timeline (this may take a few minutes)...")
        out, err, rc = run_cmd(cmd, timeout=1800)

        if csv_out.exists() and csv_out.stat().st_size > 100:
            win_log("OK", f"  Hayabusa timeline: {csv_out}")
            _parse_hayabusa_csv(csv_out, results)
        else:
            win_log("WARN", f"  Hayabusa CSV empty/failed. rc={rc}")
            if err:
                win_log("WARN", f"  stderr: {err[:300]}")
            if out:
                win_log("WARN", f"  stdout: {out[:300]}")

    # JSONL for detailed parsing — skip re-running if already present
    if json_out.exists() and json_out.stat().st_size > 100:
        win_log("OK", f"  Hayabusa JSON already exists, reusing: {json_out}")
        _parse_hayabusa_json(json_out, results)
    else:
        cmd_json = (f'"{hayabusa_bin}" dfir-timeline '
                    f'-d "{evtx_dir}" '
                    f'-o "{json_out}" '
                    f'-t jsonl {rules_arg}'
                    f'--no-wizard -q')
        win_log("INFO", "  Hayabusa: generating JSON (for EDR/detailed events)...")
        out2, err2, rc2 = run_cmd(cmd_json, timeout=1800)

        if not (json_out.exists() and json_out.stat().st_size > 100):
            win_log("WARN", f"  Hayabusa JSON rc={rc2}")
            if err2:
                win_log("WARN", f"  stderr: {err2[:300]}")

        if json_out.exists() and json_out.stat().st_size > 100:
            win_log("OK", f"  Hayabusa JSON: {json_out}")
            _parse_hayabusa_json(json_out, results)
        else:
            win_log("WARN", "  Hayabusa JSON empty/failed")

    # Always parse EDR EVTX files directly — more reliable than JSON parsing
    win_log("INFO", "  Parsing EDR EVTX files directly...")
    _parse_cisco_evtx_direct(evtx_dir, results)
    win_log("OK", f"  Total EDR events: {len(results['cisco_hits'])}")

def _parse_hayabusa_csv(csv_path, results):
    count = 0
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                level = (row.get('Level') or row.get('level') or '').strip().upper()
                title = (row.get('RuleTitle') or row.get('rule_title') or
                         row.get('Title') or row.get('title') or '').strip()
                ts    = (row.get('Timestamp') or row.get('timestamp') or '').strip()
                comp  = (row.get('Computer') or row.get('computer') or '').strip()
                detail= (row.get('Details') or row.get('details') or '').strip()
                rule  = (row.get('RuleFile') or row.get('rule_file') or '').strip()
                eid   = (row.get('EventID') or row.get('event_id') or '').strip()

                if level in ('CRITICAL','HIGH','MEDIUM','LOW') and title:
                    sev = "CRITICAL" if level == "CRITICAL" else \
                          "HIGH"     if level == "HIGH"     else "MEDIUM"

                    entry = {
                        "severity": sev, "tool": "Hayabusa",
                        "title": title, "timestamp": ts,
                        "computer": comp, "detail": detail,
                        "rule": rule, "eid": eid
                    }
                    results["hayabusa"].append(entry)
                    win_add(results, sev, "HAYABUSA", f"[{level}] {title}",
                        {"timestamp": ts, "computer": comp, "detail": detail[:300],
                         "eid": eid, "rule": rule}, csv_path)
                    count += 1

                    # C2 indicators from Hayabusa
                    if any(k in title.lower() for k in
                           ['c2','command and control','beacon','cobalt','empire','metasploit']):
                        results["c2_indicators"].append({
                            "type": "HAYABUSA_C2", "title": title,
                            "detail": detail[:200], "timestamp": ts
                        })

                    # EDR specific
                    if _is_edr_name(title) or _is_edr_name(rule):
                        results["cisco_hits"].append(entry)

        win_log("OK", f"  Hayabusa: {count} findings parsed from CSV")
    except Exception as e:
        win_log("WARN", f"  Hayabusa CSV parse error: {e}")

# EDR / endpoint-security vendor name fragments — used to identify EDR-generated
# EVTX files and channels, whichever vendor's agent is deployed (not Cisco-only).
# Add more fragments here as needed for other EDR products.
EDR_VENDOR_NAMES = [
    "cisco", "ciscosecureendpoint", "cisco secure client", "cisco secure endpoint",
    "cisco amp", "cisco:secure",
    "crowdstrike", "falcon",
    "sentinelone", "sentinel one", "s1agent",
    "defender", "windows defender", "microsoft-windows-windows defender",
    "carbonblack", "carbon black", "cb defense", "cbdefense",
    "symantec", "broadcom", "sep ",
    "sophos",
    "trendmicro", "trend micro",
    "mcafee", "trellix",
    "eset",
    "malwarebytes",
    "cylance", "blackberry protect",
    "fireeye", "mandiant", "trellix endpoint",
    "qualys",
]

# Kept for backward compatibility — same list, old name
CISCO_EVTX_FILES = EDR_VENDOR_NAMES
CISCO_CHANNELS   = EDR_VENDOR_NAMES

def _is_edr_name(text):
    """True if text (filename/channel/rule) matches any known EDR vendor fragment."""
    t = (text or "").lower()
    return any(v in t for v in EDR_VENDOR_NAMES)

def _parse_hayabusa_json(json_path, results):
    cisco_count = 0
    all_count   = 0
    try:
        with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Try multiple field names Hayabusa uses
                    channel = str(obj.get('Channel', obj.get('channel',
                              obj.get('Provider', obj.get('provider', ''))))).lower()
                    rule    = str(obj.get('RuleTitle', obj.get('rule_title',
                              obj.get('Title', obj.get('title', ''))))).lower()
                    level   = str(obj.get('Level', obj.get('level', ''))).upper()
                    details = obj.get('Details', obj.get('details', obj.get('EventData', {})))
                    ts      = obj.get('Timestamp', obj.get('timestamp', ''))
                    computer= obj.get('Computer', obj.get('computer', ''))
                    eid     = str(obj.get('EventID', obj.get('event_id', '')))
                    all_count += 1

                    # Check if this is a Cisco event
                    is_cisco = (
                        any(c in channel for c in CISCO_CHANNELS) or
                        _is_edr_name(rule) or
                        'ciscoSecure' in str(obj.get('Channel','')) or
                        _is_edr_name(str(obj.get('Channel','')))
                    )

                    if is_cisco:
                        desc_str = json.dumps(details) if isinstance(details, dict) else str(details)
                        full_text = (channel + " " + rule + " " + desc_str).lower()

                        # Match against Cisco event keywords
                        matched_sev  = "MEDIUM"
                        matched_desc = f"EDR Event (EID {eid})"
                        for keyword, (sev, desc) in CISCO_EVTX.items():
                            if keyword in full_text:
                                matched_sev  = sev
                                matched_desc = desc
                                break

                        # Always add Cisco events regardless of keyword match
                        hit = {
                            "severity":  matched_sev,
                            "desc":      matched_desc,
                            "timestamp": ts,
                            "channel":   channel,
                            "eid":       eid,
                            "computer":  computer,
                            "details":   desc_str[:500],
                        }
                        results["cisco_hits"].append(hit)
                        win_add(results, matched_sev, "CISCO_EVTX",
                            f"{matched_desc} [EID {eid}]",
                            {"ts": ts, "channel": channel,
                             "details": desc_str[:300], "computer": computer},
                            json_path)
                        cisco_count += 1

                        # Extract IOCs from Cisco events
                        ioc_text = desc_str + " " + rule
                        for ip in win_extract_ips(ioc_text):
                            if not win_is_private(ip) and ip not in WHITELIST_DOMAINS:
                                results["external_ips"].add(ip)
                        for dom in extract_domains(ioc_text):
                            if not _is_whitelisted(dom):
                                for pat in SUSP_DOMAIN_RE:
                                    if pat.search(dom):
                                        results["suspicious_domains"].add(dom)
                                        results["c2_indicators"].append({
                                            "type": "CISCO_DOMAIN", "domain": dom,
                                            "context": rule[:100]
                                        })

                    # Non-Cisco but HIGH/CRITICAL events — extract IOCs too
                    elif level in ("CRITICAL", "HIGH"):
                        details_str = json.dumps(details) if isinstance(details, dict) else str(details)
                        for ip in win_extract_ips(details_str):
                            if not win_is_private(ip):
                                results["external_ips"].add(ip)

                except json.JSONDecodeError:
                    continue
                except Exception:
                    continue

        win_log("OK", f"  Hayabusa JSON: {all_count} total events, {cisco_count} EDR events parsed")
        if cisco_count == 0:
            win_log("WARN", "  EDR: 0 events — will parse EDR EVTX directly with python-evtx")
    except Exception as e:
        win_log("WARN", f"  Hayabusa JSON parse error: {e}")


def _parse_cisco_evtx_direct(evtx_dir, results):
    """Directly parse EDR EVTX files using python-evtx as fallback"""
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        return

    evtx_dir = Path(evtx_dir)
    # Find EDR EVTX files
    cisco_files = []
    for f in evtx_dir.rglob("*.evtx"):
        if any(c in f.name.lower() for c in CISCO_EVTX_FILES):
            cisco_files.append(f)

    if not cisco_files:
        win_log("WARN", "  No EDR EVTX files found")
        return

    win_log("INFO", f"  Direct EDR EVTX parse: {len(cisco_files)} files")
    for cf in cisco_files:
        win_log("INFO", f"    Parsing {cf.name}...")
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        count = 0
        try:
            with Evtx(str(cf)) as log_file:
                for record in log_file.records():
                    try:
                        root = ET.fromstring(record.xml())
                        eid_el = root.find(".//e:EventID", ns)
                        eid    = eid_el.text.strip() if eid_el is not None else ""
                        t_el   = root.find(".//e:TimeCreated", ns)
                        ts     = t_el.get("SystemTime","")[:19] if t_el is not None else ""
                        comp_el= root.find(".//e:Computer", ns)
                        comp   = comp_el.text if comp_el is not None else ""

                        # Collect all event data
                        edata = {}
                        for d in root.findall(".//e:Data", ns):
                            nm = d.get("Name","")
                            if nm: edata[nm] = d.text or ""

                        full_text = " ".join(edata.values()).lower()
                        xml_text  = record.xml()

                        # Determine severity based on content
                        sev  = "MEDIUM"
                        desc = f"EDR Event EID {eid}"
                        for keyword, (s, d) in CISCO_EVTX.items():
                            if keyword in full_text:
                                sev  = s
                                desc = d
                                break

                        # Extract IPs from EDR logs
                        for ip in win_extract_ips(xml_text):
                            if not win_is_private(ip):
                                results["external_ips"].add(ip)

                        hit = {
                            "severity": sev, "desc": desc,
                            "timestamp": ts, "channel": cf.name,
                            "eid": eid, "computer": comp,
                            "details": str(edata)[:500],
                        }
                        results["cisco_hits"].append(hit)
                        win_add(results, sev, f"CISCO_{cf.stem.upper()[:20]}",
                            f"{desc} [EID {eid}] — {cf.name}",
                            {**edata, "computer": comp, "timestamp": ts}, cf)
                        count += 1

                    except ET.ParseError:
                        continue
                    except Exception:
                        continue
        except Exception as e:
            win_log("WARN", f"    Error parsing {cf.name}: {e}")
        win_log("OK", f"    {cf.name}: {count} events")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: CHAINSAW
# ═══════════════════════════════════════════════════════════════════════════════

def run_chainsaw(evtx_dir, output_dir, chainsaw_bin, sigma_dir, mapping, results):
    win_log("HEAD", "Running Chainsaw EVTX hunt...")

    if not chainsaw_bin or not Path(chainsaw_bin).exists():
        win_log("WARN", "Chainsaw not found - skipping")
        return

    chainsaw_out = Path(output_dir) / "chainsaw_output"
    chainsaw_out.mkdir(parents=True, exist_ok=True)
    hunt_log = chainsaw_out / "chainsaw_hunt.log"
    bin_dir = Path(chainsaw_bin).resolve().parent

    # ---- self-check: can Chainsaw see and parse YOUR evtx files?
    ep_ = Path(evtx_dir)
    evs = [ep_] if ep_.is_file() else sorted(q for q in ep_.rglob("*") if q.is_file() and q.suffix.lower() == ".evtx")
    ok_evs = []
    for q in evs:
        try:
            with open(q, "rb") as fh:
                if fh.read(8) == b"ElfFile\x00": ok_evs.append(q)
        except Exception: pass
    mb = sum(q.stat().st_size for q in ok_evs) / 1048576
    win_log("INFO", f"  EVTX input: {len(evs)} .evtx file(s) under {evtx_dir}, {len(ok_evs)} valid ({mb:.0f} MB)")
    if not ok_evs:
        win_log("WARN", "  No valid .evtx files found for Chainsaw - check the evidence path (files must end in .evtx and start with the ElfFile header)")
        return
    vout, verr, vrc = run_cmd(f'"{chainsaw_bin}" --version', timeout=30)
    win_log("INFO", f"  Chainsaw binary: {(vout or verr).strip()[:60] or 'version unknown'} (rc={vrc})")
    probe = max(ok_evs, key=lambda q: q.stat().st_size)
    pout, perr, prc = run_cmd(f'"{chainsaw_bin}" search "{probe}" -e "Provider" --json -q 2>&1 | head -c 600', timeout=300)
    if pout.strip().startswith(("[", "{")):
        win_log("OK", f"  Probe OK: Chainsaw can parse {probe.name}")
    else:
        win_log("WARN", f"  Probe FAILED on {probe.name}: {(pout or perr).strip()[:220] or 'no output'}")

    # reuse only a previous run that really produced data
    prev = [f for f in chainsaw_out.rglob("*.csv") if f.stat().st_size > 150]

    # native chainsaw rules + mapping ship next to the binary
    native_rules = next((d for d in (bin_dir / "rules", bin_dir / "chainsaw" / "rules") if d.exists()), None)
    if not (mapping and Path(mapping).exists()):
        for cand in (bin_dir / "mappings" / "sigma-event-logs-all.yml", bin_dir / "chainsaw" / "mappings" / "sigma-event-logs-all.yml"):
            if cand.exists(): mapping = str(cand); break
    sigma_rules = None
    if sigma_dir:
        for cand in (Path(sigma_dir) / "rules" / "windows", Path(sigma_dir) / "rules"):
            if cand.exists(): sigma_rules = cand; break

    if prev:
        win_log("OK", f"  Chainsaw output already exists in {chainsaw_out} ({len(prev)} CSV), reusing")
    elif mapping and Path(mapping).exists() and (sigma_rules or native_rules):
        cmd = f'"{chainsaw_bin}" hunt "{evtx_dir}" --mapping "{mapping}" --skip-errors'
        if sigma_rules: cmd += f' --sigma "{sigma_rules}"'
        if native_rules: cmd += f' --rule "{native_rules}"'
        cmd += f' --csv --output "{chainsaw_out}" 2> "{hunt_log}"'
        nsig = sum(1 for _ in Path(sigma_rules).rglob("*.yml")) if sigma_rules else 0
        nnat = sum(1 for _ in Path(native_rules).rglob("*.yml")) if native_rules else 0
        win_log("INFO", f"  Chainsaw: hunting with {nsig} Sigma + {nnat} native rule file(s), mapping {Path(mapping).name}...")
        out, err, rc = run_cmd(cmd, timeout=3600)
        try: log_txt = hunt_log.read_text(errors="ignore")
        except Exception: log_txt = ""
        mdet = re.search(r"(\d[\d,]*)\s+Detections?\s+found", log_txt, re.I)
        n_det = int(mdet.group(1).replace(",", "")) if mdet else None
        if rc not in (0, 1):
            tail = " | ".join([l.strip() for l in log_txt.splitlines() if l.strip()][-3:])
            win_log("WARN", f"  Chainsaw hunt failed (rc={rc}): {tail[:300]} (full log: {hunt_log})")
        elif n_det is not None:
            win_log("OK" if n_det else "INFO", f"  Chainsaw hunt finished: {n_det} detection(s) reported (rc={rc})")
        else:
            win_log("INFO", f"  Chainsaw hunt finished (rc={rc}); see {hunt_log}")
        if not any(chainsaw_out.rglob("*.csv")):
            errs = [l.strip() for l in log_txt.splitlines() if re.search(r"error|failed|invalid|no (?:rules|evtx)", l, re.I)][:3]
            if errs: win_log("WARN", "  Chainsaw produced no CSV: " + " | ".join(errs)[:300])
            # second pass: native Chainsaw rules only (isolates a Sigma-rule problem)
            if native_rules and sigma_rules:
                cmd2 = (f'"{chainsaw_bin}" hunt "{evtx_dir}" --mapping "{mapping}" --skip-errors --rule "{native_rules}" '
                        f'--csv --output "{chainsaw_out}" 2> "{chainsaw_out / "chainsaw_hunt_native.log"}"')
                win_log("INFO", "  No CSV from Sigma pass - retrying with native Chainsaw rules only...")
                run_cmd(cmd2, timeout=1800)
            if not any(chainsaw_out.rglob("*.csv")):
                win_log("INFO", "  Chainsaw found no rule matches in these logs (Sigma/native rules both clean) - Hayabusa/python-evtx results still apply")
    else:
        win_log("WARN", "  Chainsaw: rules/mapping not available - only keyword search will run")

    # keyword search (search supports JSON output, not CSV)
    attack_keywords = ["mimikatz", "powershell", "certutil", "mshta", "regsvr32", "wscript", "rundll32", "psexec"]
    for kw in attack_keywords:
        cmd = f'"{chainsaw_bin}" search "{evtx_dir}" -e "{kw}" --json -q 2>/dev/null'
        out, err, rc = run_cmd(cmd, timeout=600)
        if out.strip() and rc == 0:
            _parse_chainsaw_output(out, kw, results)

    for csv_file in chainsaw_out.rglob("*.csv"):
        _parse_chainsaw_csv(csv_file, results)

    win_log("OK", f"  Chainsaw: {len(results['chainsaw'])} findings")


def _parse_chainsaw_output(output, keyword, results):
    """chainsaw search --json -> a list of event documents (also tolerates JSON-lines)."""
    docs = []
    try:
        d = json.loads(output)
        docs = d if isinstance(d, list) else [d]
    except Exception:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try: docs.append(json.loads(line))
                except Exception: pass
    seen, n = set(), 0
    for doc in docs:
        ev = doc.get("Event", doc) if isinstance(doc, dict) else {}
        sysd, data = (ev.get("System") or {}), (ev.get("EventData") or {})
        eid = sysd.get("EventID"); eid = eid.get("#text", eid) if isinstance(eid, dict) else eid
        txt = data.get("CommandLine") or data.get("Image") or data.get("ScriptBlockText") or data.get("TargetFilename") or json.dumps(data)[:200]
        ts = ((sysd.get("TimeCreated") or {}).get("#attributes", {}) or {}).get("SystemTime", "") if isinstance(sysd.get("TimeCreated"), dict) else ""
        key = (str(eid), str(txt)[:120])
        if key in seen: continue
        seen.add(key); n += 1
        if n > 40: break
        win_add(results, "HIGH", "CHAINSAW", f"Chainsaw search [{keyword}] EID {eid}: {str(txt)[:160]}",
                {"keyword": keyword, "eid": str(eid), "timestamp": str(ts)[:19].replace("T", " "), "computer": str(sysd.get("Computer", "")), "line": str(txt)[:300]}, "chainsaw_search")
        results["chainsaw"].append({"keyword": keyword, "eid": str(eid), "line": str(txt)[:200]})


_CS_CRIT = re.compile(r"mimikatz|ransom|lsass|credential|dcsync|shadow ?cop|log (?:clear|delet)|clearing|cobalt|meterpreter|psexec|pass.the|kerberoast|ntds|sam (?:hive|dump)|defender.*(?:disabl|tamper)", re.I)


def _parse_chainsaw_csv(csv_path, results):
    """Chainsaw v2 CSV: timestamp, detections, path, count, Event.* columns (older versions: name/level)."""
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                low = {(k or "").lower(): (v or "") for k, v in row.items()}
                name = (low.get("detections") or low.get("name") or low.get("rule") or low.get("title") or low.get("rule_title") or "").strip()
                if not name: continue
                level = (low.get("level") or low.get("severity") or "").strip().upper()
                ts = (low.get("timestamp") or low.get("system_time") or "").strip()[:19].replace("T", " ")
                bits = []
                for k, v in low.items():
                    if v and any(x in k for x in ("commandline", "image", "targetfilename", "scriptblock", "servicename", "imagepath", "targetobject", "user", "computer", "eventid")):
                        bits.append(f"{k.split('.')[-1]}={v[:110]}")
                detail = " | ".join(bits[:7]) or str(row)[:300]
                if level in ("CRITICAL", "HIGH"): sev = "CRITICAL" if level == "CRITICAL" else "HIGH"
                else: sev = "CRITICAL" if _CS_CRIT.search(name) else "HIGH"
                cnt = low.get("count", "")
                results["chainsaw"].append({"name": name, "level": level, "timestamp": ts, "detail": detail[:300]})
                win_add(results, sev, "CHAINSAW", f"Chainsaw: {name}" + (f" (x{cnt})" if cnt and cnt != "1" else ""),
                        {"level": level, "timestamp": ts, "detail": detail[:300], "evtx": low.get("path", "")[-80:]}, csv_path)
    except Exception as e:
        win_log("WARN", f"  Chainsaw CSV parse error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 4: VOLATILITY3 (Memory)
# ═══════════════════════════════════════════════════════════════════════════════

def run_volatility(memory_dir, output_dir, vol_bin, results):
    win_log("HEAD", "Running Volatility3 memory analysis...")

    if not vol_bin:
        win_log("WARN", "Volatility3 not available — skipping")
        return

    memory_dir = Path(memory_dir)
    # Search recursively for memory dumps
    exts = ["*.dmp","*.raw","*.vmem","*.mem","*.bin","*.lime"]
    dumps = []
    for ext in exts:
        dumps.extend(memory_dir.rglob(ext))
    dumps = [Path(d) for d in dumps if Path(d).stat().st_size > 1024*1024]  # >1MB only

    if not dumps:
        win_log("WARN", f"No memory dumps found in {memory_dir}")
        win_log("WARN", "  Expected: *.raw / *.dmp / *.vmem / *.mem")
        return

    win_log("OK", f"Found {len(dumps)} memory dump(s):")
    for d in dumps:
        win_log("INFO", f"  {d} ({Path(d).stat().st_size//1024//1024} MB)")

    vol_out = Path(output_dir) / "volatility"
    vol_out.mkdir(exist_ok=True)

    for dump in dumps:
        size_mb = dump.stat().st_size // 1024 // 1024
        win_log("STEP", f"  Memory: {dump.name} ({size_mb} MB)")

        plugins = [
            ("windows.info",        _vol_info),
            ("windows.pslist",      win__vol_pslist),
            ("windows.pstree",      win__vol_pstree),
            ("windows.psxview",     _vol_psxview),
            ("windows.cmdline",     _vol_cmdline),
            ("windows.netscan",     _vol_netscan),
            ("windows.malfind",     win__vol_malfind),
            ("windows.dlllist",     _vol_dlllist),
            ("windows.handles",     _vol_handles),
            ("windows.svcscan",     _vol_svcscan),
            ("windows.registry.printkey --key \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"",
             _vol_registry),
            ("windows.registry.printkey --key \"SYSTEM\\CurrentControlSet\\Services\"",
             _vol_registry),
        ]

        for plugin, handler in plugins:
            plugin_name = plugin.split()[0]
            _suffix = ""
            if "--key" in plugin:
                _suffix = "_" + re.split(r"[\\/]", plugin.split("--key", 1)[1].strip().strip('" \\'))[-1]
            out_file = vol_out / f"{dump.stem}_{plugin_name.replace('.','_')}{_suffix}.txt"
            cmd = f'{vol_bin} -f "{dump}" {plugin} 2>/dev/null'
            win_log("INFO", f"    vol {plugin_name}...")
            out, err, rc = run_cmd(cmd, timeout=int(os.environ.get("VOL_TIMEOUT", 0)) or 7200)
            if out.strip():
                out_file.write_text(out)
                handler(out, results, dump)
            else:
                if "malfind" in plugin_name:
                    win_log("INFO", f"    {plugin_name}: no output — this is EXPECTED if:")
                    win_log("INFO",  "      1. Memory was collected long after the attack (attacker processes")
                    win_log("INFO",  "         already exited — they leave no trace in a later RAM dump)")
                    win_log("INFO",  "      2. Malware wiped its MZ header after load (common evasion)")
                    win_log("INFO",  "      3. Process hollowing / shellcode without MZ header was used")
                    win_log("INFO",  "      4. Malware ran as a kernel driver (userland malfind won't see it)")
                    win_log("INFO",  "      → Use pslist/cmdline/netscan output to check current state")
                    win_log("INFO",  "        and correlate with EDR detections for the actual attack timeline")
                else:
                    win_log("WARN", f"    {plugin_name}: no output")

def _vol_info(out, results, dump):
    if "Windows" in out:
        win_log("OK", f"    OS: " + re.search(r'(Windows[^\n]+)', out).group(1)[:60] if re.search(r'(Windows[^\n]+)', out) else "    OS detected")

def win__vol_pslist(out, results, dump):
    bad = ['mimikatz','pwdump','fgdump','gsecdump','procdump',
           'wce.exe','meterpreter','nc.exe','ncat','netcat']
    for line in out.splitlines()[2:]:
        for b in bad:
            if b.lower() in line.lower():
                win_add(results,"CRITICAL","MEMORY_PROC",
                    f"🚨 Suspicious process: {b} — {line.strip()[:100]}",
                    {"line":line.strip()}, dump)
                results["volatility"].append({"type":"susp_proc","line":line.strip(),"dump":str(dump)})

def win__vol_pstree(out, results, dump):
    # Look for suspicious parent-child
    PARENT_CHILD = {
        "winword.exe":  ["cmd.exe","powershell.exe","wscript.exe","mshta.exe"],
        "excel.exe":    ["cmd.exe","powershell.exe","wscript.exe"],
        "outlook.exe":  ["cmd.exe","powershell.exe","wscript.exe"],
        "svchost.exe":  ["cmd.exe","powershell.exe"],
        "lsass.exe":    ["cmd.exe","powershell.exe","net.exe"],
    }
    lines = out.splitlines()
    for i, line in enumerate(lines):
        for parent, bad_children in PARENT_CHILD.items():
            if parent in line.lower():
                for j in range(i+1, min(i+5, len(lines))):
                    child_line = lines[j].lower()
                    for bc in bad_children:
                        if bc in child_line:
                            win_add(results,"HIGH","MEMORY_PSTREE",
                                f"Suspicious parent-child: {parent} → {bc}",
                                {"parent":line.strip(),"child":lines[j].strip()}, dump)

def _vol_psxview(out, results, dump):
    for line in out.splitlines()[2:]:
        if "False" in line:
            win_add(results,"HIGH","MEMORY_HIDDEN",
                f"Hidden process (psxview): {line.strip()[:100]}",
                {"line":line.strip()}, dump)
            results["volatility"].append({"type":"hidden_proc","line":line.strip()})

def _vol_netscan(out, results, dump):
    for line in out.splitlines()[2:]:
        for part in line.split():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', part)
            if m:
                ip, port_str = m.group(1), m.group(2)
                if not win_is_private(ip) and ip not in ('0.0.0.0','*','::'):
                    results["external_ips"].add(ip)
                    try:
                        port = int(port_str)
                        sev  = "CRITICAL" if port in win_SUSP_PORTS else "HIGH"
                        desc = (f"🚨 Memory C2 port {port} ({win_SUSP_PORTS[port]}): {ip}"
                                if port in win_SUSP_PORTS else
                                f"Memory external connection: {ip}:{port}")
                        win_add(results,sev,"MEMORY_NET",desc,
                            {"ip":ip,"port":port,"line":line.strip()[:100]}, dump)
                        if port in win_SUSP_PORTS:
                            results["c2_indicators"].append({
                                "type":"MEMORY_C2_PORT","ip":ip,
                                "port":port,"desc":win_SUSP_PORTS[port]
                            })
                    except: pass

def win__vol_malfind(out, results, dump):
    if any(x in out for x in ['MZ','EXECUTE','PAGE_EXECUTE_READWRITE']):
        win_add(results,"CRITICAL","MEMORY_INJECT",
            "🚨 Code injection / PE in memory (malfind)",
            {"output":out[:2000]}, dump)
        results["c2_indicators"].append({"type":"CODE_INJECTION","dump":str(dump)})
        results["volatility"].append({"type":"malfind","dump":str(dump)})

def _vol_cmdline(out, results, dump):
    for pat, pname in MALWARE_PATTERNS:
        for line in out.splitlines():
            if pat.search(line):
                win_add(results,"CRITICAL","MEMORY_CMDLINE",
                    f"🚨 Malicious cmdline in memory: {pname}",
                    {"line":line.strip()[:200],"pattern":pname}, dump)
                break

def _vol_dlllist(out, results, dump):
    susp_dlls = ['meterpreter','inject','hook','keylog','spy','rat']
    for line in out.splitlines():
        for s in susp_dlls:
            if s in line.lower():
                win_add(results,"HIGH","MEMORY_DLL",
                    f"Suspicious DLL: {line.strip()[:100]}",
                    {"line":line.strip()}, dump)

def _vol_registry(out, results, dump):
    for line in out.splitlines():
        if line.strip() and not line.startswith('Offset') and not line.startswith('Volatility'):
            win_add(results,"HIGH","MEMORY_REG",
                f"Registry persistence in memory: {line.strip()[:150]}",
                {"line":line.strip()}, dump)

def _vol_handles(out, results, dump):
    """Check for suspicious handles — mutexes, files in temp"""
    for line in out.splitlines()[2:]:
        if any(s in line.lower() for s in ['\\temp\\','\\tmp\\','appdata\\local\\temp']):
            win_add(results,"HIGH","MEMORY_HANDLE_TEMP",
                f"Handle to suspicious temp path: {line.strip()[:150]}",
                {"line":line.strip()}, dump)

def _vol_svcscan(out, results, dump):
    """Scan for suspicious services in memory"""
    susp_svc_paths = ['\\temp\\','appdata\\temp','\\tmp\\',
                      'users\\public','programdata\\']
    for line in out.splitlines():
        for sp in susp_svc_paths:
            if sp.lower() in line.lower():
                win_add(results,"CRITICAL","MEMORY_SVC",
                    f"🚨 Service with suspicious path: {line.strip()[:200]}",
                    {"line":line.strip()}, dump)
                break
        # Known malicious service names
        for ms in ['mimikatz','metasploit','meterpreter','cobaltstrike','psexec']:
            if ms.lower() in line.lower():
                win_add(results,"CRITICAL","MEMORY_SVC_MALICIOUS",
                    f"🚨 Malicious service detected: {ms}",
                    {"line":line.strip(),"service":ms}, dump)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 5: EVTX (python-evtx) — Deep parsing + EDR
# ═══════════════════════════════════════════════════════════════════════════════

# Priority EVTX files — parse these first (most important)
PRIORITY_EVTX = [
    "Security.evtx","System.evtx","Application.evtx",
    "Microsoft-Windows-Sysmon_Operational.evtx",
    "Microsoft-Windows-PowerShell_Operational.evtx",
    "Microsoft-Windows-PowerShell_Admin.evtx",
    "Microsoft-Windows-TaskScheduler_Operational.evtx",
    "Microsoft-Windows-WinRM_Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager_Operational.evtx",
    "Microsoft-Windows-Windows Defender_Operational.evtx",
    "Microsoft-Windows-WindowsUpdateClient_Operational.evtx",
]

def _parse_single_evtx(evtx_path, is_cisco=False):
    """Parse a single EVTX file — returns list of findings"""
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET

    ns = {"e":"http://schemas.microsoft.com/win/2004/08/events/event"}
    findings = []

    try:
        with Evtx(str(evtx_path)) as lf:
            for record in lf.records():
                try:
                    root = ET.fromstring(record.xml())
                    eid_el = root.find(".//e:EventID", ns)
                    if eid_el is None: continue
                    eid = int(eid_el.text.strip())
                    t_el = root.find(".//e:TimeCreated", ns)
                    ts   = t_el.get("SystemTime","")[:19] if t_el is not None else ""
                    c_el = root.find(".//e:Computer", ns)
                    comp = c_el.text if c_el is not None else ""
                    edata = {}
                    for d in root.findall(".//e:Data", ns):
                        nm = d.get("Name","")
                        if nm: edata[nm] = d.text or ""
                    full = " ".join(edata.values())

                    # EDR events
                    if is_cisco:
                        matched_sev, matched_desc = "MEDIUM", f"EDR Event EID {eid}"
                        for kw, (sev, desc) in CISCO_EVTX.items():
                            if kw in full.lower():
                                matched_sev, matched_desc = sev, desc
                                break
                        findings.append({
                            "type": "CISCO",
                            "sev": matched_sev, "src": "CISCO_EVTX",
                            "desc": f"{matched_desc} (EID {eid})",
                            "data": {**edata,"computer":comp,"timestamp":ts},
                            "file": str(evtx_path),
                            "eid": eid, "ts": ts,
                        })
                        # Extract IPs
                        for ip in win_extract_ips(full):
                            if not win_is_private(ip):
                                findings.append({"type":"IP","ip":ip})
                        continue

                    # Standard suspicious EIDs
                    if eid in SUSP_EVTX:
                        sev, desc = SUSP_EVTX[eid]
                        if eid == 4688:
                            cmdline = edata.get("CommandLine","")
                            matched = None
                            for pat, pname in MALWARE_PATTERNS:
                                if pat.search(cmdline):
                                    matched = pname
                                    sev = "CRITICAL"
                                    desc = f"Malicious Process: {pname}"
                                    break
                            if sev == "MEDIUM" and not matched:
                                continue
                            edata["_matched"] = matched or ""
                        if eid in (5156,3):
                            dst = edata.get("DestAddress",edata.get("DestinationIp",""))
                            if dst and win_is_private(dst): continue
                            if dst: findings.append({"type":"IP","ip":dst})
                        findings.append({
                            "type": "EVTX",
                            "sev": sev, "src": f"EVTX_EID{eid}",
                            "desc": f"[EID {eid}] {desc}",
                            "data": {**edata,"computer":comp,"timestamp":ts},
                            "file": str(evtx_path),
                            "eid": eid, "ts": ts,
                        })
                    else:
                        for pat, pname in MALWARE_PATTERNS:
                            if pat.search(full):
                                findings.append({
                                    "type": "EVTX",
                                    "sev": "HIGH", "src": "EVTX_PATTERN",
                                    "desc": f"Pattern in EID {eid}: {pname}",
                                    "data": {**edata,"computer":comp},
                                    "file": str(evtx_path),
                                    "eid": eid, "ts": ts,
                                })
                                break
                except ET.ParseError: continue
                except Exception: continue
    except Exception:
        pass
    return findings


def run_evtx_analysis(evtx_dir, results):
    win_log("HEAD", "Running deep EVTX analysis (python-evtx) with parallel processing...")
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        win_log("WARN", "python-evtx not installed — skipping")
        return

    all_files  = list(Path(evtx_dir).rglob("*.evtx"))
    if not all_files:
        win_log("WARN", f"No .evtx files in {evtx_dir}")
        return

    # Sort: priority files first, then EDR, then rest
    priority = [f for f in all_files
                if any(p.lower() in f.name.lower() for p in PRIORITY_EVTX)]
    cisco    = [f for f in all_files if _is_edr_name(f.name)]
    rest     = [f for f in all_files
                if f not in priority and f not in cisco]

    ordered = priority + cisco + rest
    win_log("INFO", f"  {len(all_files)} files | Priority: {len(priority)} | "
                f"EDR: {len(cisco)} | Other: {len(rest)}")

    # Parallel processing with ThreadPoolExecutor
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    lock = threading.Lock()
    processed = [0]

    try:
        from tqdm import tqdm
        pbar = tqdm(total=len(ordered), desc="  EVTX",
                    unit="file", colour="cyan")
    except:
        pbar = None

    def process_file(fpath):
        is_cisco = _is_edr_name(fpath.name)
        return _parse_single_evtx(fpath, is_cisco)

    # Use 4 parallel workers
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(process_file, f): f for f in ordered}
        for future in as_completed(futures):
            findings = future.result()
            with lock:
                for f in findings:
                    if f["type"] == "IP":
                        results["external_ips"].add(f["ip"])
                    elif f["type"] == "CISCO":
                        results["cisco_hits"].append({
                            "eid": f.get("eid",""),
                            "desc": f["desc"],
                            "ts": f.get("ts",""),
                            "data": str(f.get("data",""))[:200],
                        })
                        win_add(results, f["sev"], f["src"], f["desc"],
                            f.get("data",{}), f.get("file",""))
                    else:
                        win_add(results, f["sev"], f["src"], f["desc"],
                            f.get("data",{}), f.get("file",""))
                processed[0] += 1
            if pbar:
                pbar.update(1)

    if pbar:
        pbar.close()
    win_log("OK", f"  EVTX done: {processed[0]} files processed")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 6: NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

def run_network_analysis(network_dir, results):
    win_log("HEAD", "Analyzing network data...")
    nd = Path(network_dir)

    # Outbound / Inbound CSVs
    for fname in ["network_outbound.csv","network_inbound.csv"]:
        fp = nd / fname
        if not fp.exists(): continue
        direction = "OUTBOUND" if "outbound" in fname else "INBOUND"
        win_log("INFO", f"  {fname}...")
        try:
            with open(fp, newline='', encoding='utf-8', errors='ignore') as f:
                for row in csv.DictReader(f):
                    rip  = (row.get('RemoteAddress') or row.get('ForeignAddress') or
                            row.get('DestinationIP') or row.get('remote_ip') or '').split(':')[0].strip()
                    rport= (row.get('RemotePort') or row.get('ForeignPort') or
                            row.get('Port') or '0').strip()
                    proc = (row.get('Process') or row.get('ProcessName') or '').strip()
                    state= (row.get('State') or '').strip()
                    if not rip or win_is_private(rip): continue
                    results["external_ips"].add(rip)
                    try:
                        p = int(rport)
                        if p in win_SUSP_PORTS:
                            win_add(results,"CRITICAL",f"NET_{direction}",
                                f"🚨 Suspicious port {p} ({win_SUSP_PORTS[p]}): {proc} → {rip}",
                                {"ip":rip,"port":p,"process":proc}, fp)
                            results["c2_indicators"].append({
                                "type":f"SUSP_PORT_{direction}","ip":rip,"port":p,"process":proc})
                        elif direction == "OUTBOUND":
                            win_add(results,"HIGH",f"NET_{direction}",
                                f"External {direction}: {proc} → {rip}:{p} ({state})",
                                {"ip":rip,"port":p,"process":proc,"state":state}, fp)
                    except: pass
        except Exception as e:
            win_log("WARN", f"  {fname} error: {e}")

    # Listening ports
    fp = nd / "network_listening.csv"
    if fp.exists():
        try:
            with open(fp, newline='', encoding='utf-8', errors='ignore') as f:
                for row in csv.DictReader(f):
                    port = (row.get('LocalPort') or row.get('Port') or '0').strip()
                    proc = (row.get('Process') or row.get('ProcessName') or '').strip()
                    try:
                        p = int(port)
                        if p in win_SUSP_PORTS:
                            win_add(results,"CRITICAL","NET_LISTEN",
                                f"🚨 Backdoor port {p} ({win_SUSP_PORTS[p]}) listening: {proc}",
                                {"port":p,"process":proc}, fp)
                            results["c2_indicators"].append({
                                "type":"BACKDOOR_PORT","port":p,"process":proc})
                    except: pass
        except Exception as e:
            win_log("WARN", f"  network_listening.csv error: {e}")

    # Netstat
    fp = nd / "netstat.txt"
    if fp.exists():
        content = fp.read_text(errors='ignore')
        for ip in win_extract_ips(content):
            if not win_is_private(ip):
                results["external_ips"].add(ip)
        for pm in re.findall(r':(\d{4,5})\b', content):
            try:
                p = int(pm)
                if p in win_SUSP_PORTS:
                    win_add(results,"CRITICAL","NETSTAT",
                        f"Suspicious port {p} in netstat",
                        {"port":p}, fp)
            except: pass

    # DNS Cache
    fp = nd / "dns_cache.txt"
    if fp.exists():
        win_log("INFO", "  dns_cache.txt...")
        content = fp.read_text(errors='ignore')
        domains = extract_domains(content)
        counts  = Counter(domains)
        for dom, cnt in counts.items():
            if _is_whitelisted(dom): continue
            for pat in SUSP_DOMAIN_RE:
                if pat.search(dom):
                    results["dns_hits"].append({"domain":dom,"count":cnt})
                    results["suspicious_domains"].add(dom)
                    win_add(results,"HIGH","DNS",
                        f"Suspicious domain: {dom} (x{cnt})",
                        {"domain":dom,"count":cnt}, fp)
                    break
        # DGA detection
        long_rand = [d for d in set(domains)
                     if len(d)>30 and re.search(r'[a-z0-9]{12,}',d.split('.')[0])
                     and not _is_whitelisted(d)]
        if len(long_rand) > 10:
            win_add(results,"CRITICAL","DNS_DGA",
                f"Possible DGA: {len(long_rand)} random-looking domains",
                {"sample":long_rand[:10]}, fp)
            results["c2_indicators"].append({
                "type":"DGA","count":len(long_rand),"sample":long_rand[:5]})

    win_log("OK", f"  Network done. IPs: {len(results['external_ips'])}, DNS hits: {len(results['dns_hits'])}")

def _is_whitelisted(domain):
    domain = domain.lower()
    return any(domain == w or domain.endswith('.'+w) for w in WHITELIST_DOMAINS)

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 7: REGISTRY (proper .hiv parsing + text fallback)
# ═══════════════════════════════════════════════════════════════════════════════

# Registry persistence keys to check (key path → severity)
REG_PERSIST_MAP = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run":             "CRITICAL",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce":         "CRITICAL",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx":       "CRITICAL",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon":     "HIGH",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options": "HIGH",
    "SOFTWARE\\Classes\\exefile\\shell\\open\\command":              "CRITICAL",
    "SYSTEM\\CurrentControlSet\\Services":                           "HIGH",
    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute": "CRITICAL",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders": "MEDIUM",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run": "CRITICAL",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows":      "HIGH",
    "SYSTEM\\CurrentControlSet\\Control\\SafeBoot":                  "HIGH",
}

def _check_reg_value(val_name, val_data, key_path, hive_name, results, fpath):
    """Check a single registry value for suspicious content"""
    val_str = str(val_data)
    val_lower = val_str.lower()

    # Check malicious patterns
    for pat, pname in MALWARE_PATTERNS:
        if pat.search(val_str):
            win_add(results, "CRITICAL", "REGISTRY_MALICIOUS",
                f"🚨 Malicious value in registry: {pname}",
                {
                    "hive":     hive_name,
                    "key":      key_path,
                    "value_name": val_name,
                    "value_data": val_str[:400],
                    "pattern":  pname,
                }, fpath)
            results.setdefault("registry_hits", []).append({
                "hive": hive_name, "key": key_path,
                "name": val_name, "data": val_str[:200],
                "pattern": pname, "severity": "CRITICAL"
            })
            return

    # Check for external IPs in registry values
    for ip in win_extract_ips(val_str):
        if not win_is_private(ip):
            results["external_ips"].add(ip)
            win_add(results, "HIGH", "REGISTRY_IP",
                f"External IP in registry: {ip}",
                {
                    "hive": hive_name, "key": key_path,
                    "value_name": val_name, "ip": ip
                }, fpath)

    # Check for URLs
    if re.search(r'https?://', val_str, re.I):
        win_add(results, "HIGH", "REGISTRY_URL",
            f"URL found in registry value",
            {
                "hive": hive_name, "key": key_path,
                "value_name": val_name, "value_data": val_str[:300]
            }, fpath)

def _walk_hive(key, hive_name, results, fpath, depth=0, max_depth=12):
    """Recursively walk registry hive"""
    if depth > max_depth:
        return
    try:
        key_path = key.path()

        # Check if this is a persistence key
        for persist_key, sev in REG_PERSIST_MAP.items():
            if persist_key.lower() in key_path.lower():
                # Read all values under this key
                try:
                    vals = list(key.values())
                    if vals:
                        for val in vals:
                            try:
                                vname = val.name() or "(Default)"
                                vdata = val.value()
                                vtype = val.value_type_str()
                                vdata_str = str(vdata)

                                # Log the persistence entry
                                entry_sev = sev
                                # Escalate if data looks suspicious
                                for pat, pname in MALWARE_PATTERNS:
                                    if pat.search(vdata_str):
                                        entry_sev = "CRITICAL"
                                        break

                                win_add(results, entry_sev, "REGISTRY_PERSIST",
                                    f"Persistence key [{entry_sev}]: {persist_key}",
                                    {
                                        "hive":       hive_name,
                                        "key":        key_path,
                                        "value_name": vname,
                                        "value_data": vdata_str[:400],
                                        "value_type": vtype,
                                    }, fpath)

                                results.setdefault("registry_hits", []).append({
                                    "hive": hive_name,
                                    "key":  key_path,
                                    "name": vname,
                                    "data": vdata_str[:200],
                                    "type": vtype,
                                    "severity": entry_sev
                                })

                                # Also check value data for malware
                                _check_reg_value(vname, vdata_str, key_path,
                                                 hive_name, results, fpath)
                            except Exception:
                                pass
                    else:
                        # Key exists but empty — still noteworthy
                        win_add(results, sev, "REGISTRY_PERSIST",
                            f"Persistence key found (empty): {persist_key}",
                            {"hive": hive_name, "key": key_path}, fpath)
                except Exception:
                    pass
                break  # Don't double-report same key

        # Check ALL values for suspicious content (not just persistence keys)
        else:
            try:
                for val in key.values():
                    try:
                        vname = val.name() or "(Default)"
                        vdata_str = str(val.value())
                        _check_reg_value(vname, vdata_str, key_path,
                                         hive_name, results, fpath)
                    except Exception:
                        pass
            except Exception:
                pass

        # Recurse into subkeys
        try:
            for subkey in key.subkeys():
                _walk_hive(subkey, hive_name, results, fpath, depth+1, max_depth)
        except Exception:
            pass

    except Exception:
        pass

def run_registry_analysis(reg_dir, results):
    win_log("HEAD", "Analyzing registry hives (python-registry)...")
    reg_dir = Path(reg_dir)

    # Install python-registry if needed
    try:
        from Registry.Registry import Registry as WinRegistry
        hiv_available = True
    except ImportError:
        win_log("INFO", "  Installing python-registry...")
        run_cmd("pip3 install python-registry --break-system-packages -q", timeout=60)
        try:
            from Registry.Registry import Registry as WinRegistry
            hiv_available = True
            win_log("OK", "  python-registry installed")
        except ImportError:
            hiv_available = False
            win_log("WARN", "  python-registry not available — using text fallback")

    # Search recursively for .hiv files
    hive_files = (list(reg_dir.rglob("*.hiv")) +
                  list(reg_dir.rglob("*.hive")) +
                  list(reg_dir.rglob("*.HIV")))
    # Also check parent directory
    if not hive_files:
        hive_files = (list(reg_dir.parent.rglob("*.hiv")) +
                      list(reg_dir.parent.rglob("*.hive")))
    win_log("INFO", f"  Searching for hives in: {reg_dir}")
    win_log("INFO", f"  Found hive files: {[f.name for f in hive_files]}")
    text_files  = [f for f in reg_dir.glob("*.txt") if f.is_file()]
    total_hits  = 0

    # ── Parse .hiv files properly ─────────────────────────────────────────────
    if hiv_available and hive_files:
        win_log("INFO", f"  Found {len(hive_files)} hive files: {[f.name for f in hive_files]}")
        for hive_path in hive_files:
            hive_name = hive_path.stem.upper()  # SOFTWARE, SYSTEM, SECURITY, SAM
            size_mb = hive_path.stat().st_size // 1024 // 1024
            win_log("INFO", f"  Parsing {hive_name} ({size_mb} MB)...")
            try:
                reg = WinRegistry(str(hive_path))
                before = len(results["critical"]) + len(results["high"])
                _walk_hive(reg.root(), hive_name, results, hive_path)
                after  = len(results["critical"]) + len(results["high"])
                hits   = after - before
                total_hits += hits
                win_log("OK" if hits == 0 else "CRIT",
                    f"  {hive_name}: {hits} findings")
            except Exception as e:
                win_log("WARN", f"  {hive_name} parse error: {e}")
    elif hive_files:
        win_log("WARN", "  .hiv files found but python-registry unavailable — text fallback")

    # ── Text file fallback (regsave_*.txt) ────────────────────────────────────
    if text_files:
        win_log("INFO", f"  Parsing {len(text_files)} text registry files...")
        for fpath in text_files:
            try:
                content = fpath.read_text(errors='ignore')
            except:
                continue
            for key in REG_PERSIST_MAP:
                if key.lower() in content.lower():
                    idx = content.lower().find(key.lower())
                    snippet = content[max(0,idx-20):idx+300]
                    win_add(results, "HIGH", "REGISTRY_PERSIST",
                        f"Persistence key in text dump: {key}",
                        {"key": key, "file": fpath.name,
                         "snippet": snippet[:300]}, fpath)
                    total_hits += 1
            for pat, pname in MALWARE_PATTERNS:
                if pat.search(content):
                    win_add(results, "CRITICAL", "REGISTRY_MALICIOUS",
                        f"Malicious pattern in {fpath.name}: {pname}",
                        {"pattern": pname, "file": fpath.name}, fpath)
                    total_hits += 1
            for ip in win_extract_ips(content):
                if not win_is_private(ip):
                    results["external_ips"].add(ip)

    win_log("OK", f"Registry analysis done — {total_hits} total findings")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 8: ARTIFACTS
# ═══════════════════════════════════════════════════════════════════════════════

def run_artifacts_analysis(art_dir, results):
    win_log("HEAD", "Analyzing artifacts...")
    for fpath in Path(art_dir).rglob("*"):
        if not fpath.is_file(): continue
        try:
            content = fpath.read_text(errors='ignore')
        except: continue
        for ip in win_extract_ips(content):
            if not win_is_private(ip):
                results["external_ips"].add(ip)
        for pat, pname in MALWARE_PATTERNS:
            if pat.search(content):
                win_add(results,"HIGH","ARTIFACT",
                    f"Malicious pattern in {fpath.name}: {pname}",
                    {"file":fpath.name,"pattern":pname}, fpath)
                break
    win_log("OK", "Artifacts done")

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 9: HASHES + THREAT INTEL
# ═══════════════════════════════════════════════════════════════════════════════

def win_run_threat_intel(results, hashes_csv=None, vt_key=None, abuse_key=None):
    win_log("HEAD", "Running Threat Intelligence checks...")
    try:
        import requests
    except ImportError:
        win_log("WARN", "requests not installed — skipping threat intel")
        return

    # Hash lookup
    if hashes_csv and Path(hashes_csv).exists() and vt_key:
        win_log("INFO", "  Checking file hashes against VirusTotal...")
        try:
            with open(hashes_csv, newline='', encoding='utf-8', errors='ignore') as f:
                rows = list(csv.DictReader(f))
            for row in rows[:40]:
                h = (row.get('SHA256') or row.get('sha256') or
                     row.get('MD5') or row.get('Hash') or '').strip()
                if not h or len(h) < 32: continue
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/files/{h}",
                        headers={"x-apikey":vt_key}, timeout=10)
                    if r.status_code == 200:
                        attrs = r.json().get("data",{}).get("attributes",{})
                        stats = attrs.get("last_analysis_stats",{})
                        mal   = stats.get("malicious",0)
                        if mal > 0:
                            name = attrs.get("meaningful_name", h[:16])
                            win_add(results,"CRITICAL","HASH_VT",
                                f"🚨 Malicious file: {name} ({mal} VT detections)",
                                {"hash":h,"detections":mal,"name":name}, hashes_csv)
                            results["threat_intel"].append({
                                "hash":h,"name":name,"detections":mal,"source":"VirusTotal"})
                    time.sleep(16)  # Free: 4/min
                except: pass
        except Exception as e:
            win_log("WARN", f"  Hash lookup error: {e}")

    # IP reputation
    ips = [ip for ip in results["external_ips"] if not win_is_private(ip)]
    if not ips:
        win_log("WARN", "  No external IPs to check")
        return
    win_log("INFO", f"  Checking {min(len(ips),25)} IPs for reputation...")
    for ip in list(ips)[:25]:
        if vt_key and not UNI_CTX.get("vt_in_report", True):      # IP reputation is done once, with ASN/country, by the report builder
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey":vt_key}, timeout=8)
                if r.status_code == 200:
                    stats = (r.json().get("data",{}).get("attributes",{})
                             .get("last_analysis_stats",{}))
                    mal = stats.get("malicious",0)
                    if mal > 0:
                        win_add(results,"CRITICAL","THREAT_INTEL",
                            f"🚨 Malicious IP (VT {mal} hits): {ip}",
                            {"ip":ip,"detections":mal}, "")
                        results["threat_intel"].append({
                            "ip":ip,"detections":mal,"source":"VirusTotal"})
                time.sleep(16)
            except: pass
        if abuse_key:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key":abuse_key,"Accept":"application/json"},
                    params={"ipAddress":ip,"maxAgeInDays":90}, timeout=8)
                if r.status_code == 200:
                    d = r.json().get("data",{})
                    score = d.get("abuseConfidenceScore",0)
                    if score > 40:
                        win_add(results,"CRITICAL","THREAT_INTEL",
                            f"🚨 Malicious IP (AbuseIPDB {score}%): {ip}",
                            {"ip":ip,"score":score}, "")
                        results["threat_intel"].append({
                            "ip":ip,"score":score,
                            "reports":d.get("totalReports",0),"source":"AbuseIPDB"})
            except: pass

# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 10: HTML DASHBOARD with Timeline + Export
# ═══════════════════════════════════════════════════════════════════════════════

def win_generate_dashboard(results, output_dir):
    win_log("HEAD", "Generating HTML dashboard with Timeline & Export...")

    crit  = len(results["critical"])
    high  = len(results["high"])
    med   = len(results["medium"])
    ips   = len(results["external_ips"])
    c2    = len(results["c2_indicators"])
    dns   = len(results["dns_hits"])
    hay   = len(results["hayabusa"])
    chain = len(results["chainsaw"])
    cisco = len(results["cisco_hits"])
    ti    = len(results["threat_intel"])

    all_findings = results["critical"] + results["high"] + results["medium"][:100]

    # ── Build timeline data (sorted by timestamp) ─────────────────────────────
    timeline_events = []
    for f in all_findings:
        d   = f.get("data", {})
        ts  = (d.get("timestamp") or f.get("timestamp") or
               d.get("Timestamp") or "")
        ts  = str(ts).strip()[:19].replace("T", " ")
        if not ts or ts == "None" or len(ts) < 10:
            continue
        timeline_events.append({
            "ts":   ts,
            "sev":  f.get("severity", ""),
            "src":  f.get("source", ""),
            "desc": f.get("desc", ""),
            "det":  str(d.get("CommandLine") or d.get("line") or
                        d.get("value_data") or d.get("domain") or
                        d.get("detail") or d.get("ip") or "")[:200],
            "comp": str(d.get("computer") or d.get("Computer") or ""),
        })

    # Sort timeline by timestamp
    timeline_events.sort(key=lambda x: x["ts"])

    # Timeline stats
    tl_start = timeline_events[0]["ts"]  if timeline_events else "N/A"
    tl_end   = timeline_events[-1]["ts"] if timeline_events else "N/A"
    tl_total = len(timeline_events)

    # Group timeline by date for chart
    from collections import Counter as _Counter
    date_counts = _Counter(e["ts"][:10] for e in timeline_events)
    dates_sorted = sorted(date_counts.keys())
    chart_labels = str([d for d in dates_sorted]).replace("'", '"')
    chart_crit   = str([sum(1 for e in timeline_events
                            if e["ts"][:10] == d and e["sev"] == "CRITICAL")
                        for d in dates_sorted])
    chart_high   = str([sum(1 for e in timeline_events
                            if e["ts"][:10] == d and e["sev"] == "HIGH")
                        for d in dates_sorted])

    # ── Build findings rows ────────────────────────────────────────────────────
    rows = ""
    for f in all_findings[:600]:
        sev  = f["severity"]
        col  = {"CRITICAL":"#ff4444","HIGH":"#f97316","MEDIUM":"#eab308"}.get(sev,"#64748b")
        src  = f.get("source","")
        desc = f.get("desc","")
        d    = f.get("data",{})
        det  = str(d.get("CommandLine") or d.get("line") or d.get("domain") or
                   d.get("detail") or d.get("ip") or d.get("snippet") or
                   d.get("value_data") or d.get("value_name") or
                   d.get("timestamp") or "")[:180]
        ts   = str(d.get("timestamp",""))[:19].replace("T"," ")
        comp = str(d.get("computer") or d.get("Computer") or "")
        rows += f"""<tr data-sev="{sev}" data-src="{src}" data-ts="{ts}">
          <td><span class="badge" style="background:{col}">{sev}</span></td>
          <td class="src-tag">{src}</td>
          <td>{desc}</td>
          <td class="mono">{det}</td>
          <td class="mono dim">{comp}</td>
          <td class="mono dim">{ts}</td>
        </tr>"""

    # ── Timeline rows ──────────────────────────────────────────────────────────
    tl_rows = ""
    prev_date = ""
    for e in timeline_events[:1000]:
        date = e["ts"][:10]
        time = e["ts"][11:19] if len(e["ts"]) > 10 else ""
        sev  = e["sev"]
        col  = {"CRITICAL":"#ff4444","HIGH":"#f97316","MEDIUM":"#eab308"}.get(sev,"#64748b")
        date_sep = ""
        if date != prev_date:
            date_sep = f'<tr class="date-sep"><td colspan="6"><span class="date-label">📅 {date}</span></td></tr>'
            prev_date = date
        tl_rows += f"""{date_sep}<tr data-sev="{sev}">
          <td class="mono dim" style="white-space:nowrap">{time}</td>
          <td><span class="badge" style="background:{col}">{sev}</span></td>
          <td class="src-tag">{e['src']}</td>
          <td>{e['desc']}</td>
          <td class="mono">{e['det'][:150]}</td>
          <td class="mono dim">{e['comp']}</td>
        </tr>"""

    # ── Other tab rows ─────────────────────────────────────────────────────────
    c2_rows = "".join(f"""<tr>
      <td><span class="badge" style="background:#a855f7">{c.get('type','')}</span></td>
      <td class="mono">{c.get('ip','') or c.get('domain','')}</td>
      <td class="mono">{c.get('port','')}</td>
      <td>{c.get('process','') or c.get('desc','') or c.get('title','')}</td>
    </tr>""" for c in results["c2_indicators"])

    cisco_rows = "".join(f"""<tr>
      <td><span class="badge" style="background:#ff4444">{c.get('severity','')}</span></td>
      <td>{c.get('desc','') or c.get('title','')}</td>
      <td class="mono dim">{str(c.get('timestamp','') or c.get('ts',''))[:19]}</td>
      <td class="mono">{str(c.get('detail','') or c.get('data',''))[:150]}</td>
    </tr>""" for c in results["cisco_hits"][:200])

    hay_rows = "".join(f"""<tr>
      <td><span class="badge" style="background:{'#ff4444' if h['severity']=='CRITICAL' else '#f97316'}">{h['severity']}</span></td>
      <td>{h.get('title','')}</td>
      <td class="mono dim">{str(h.get('timestamp',''))[:19]}</td>
      <td class="mono">{h.get('detail','')[:150]}</td>
    </tr>""" for h in results["hayabusa"][:300])

    dns_rows = "".join(f"""<tr>
      <td class="mono">{d.get('domain','')}</td>
      <td>{d.get('count','')}</td>
    </tr>""" for d in results["dns_hits"][:100])

    ip_tags = "".join(f'<span class="ip-tag">{ip}</span>'
                      for ip in sorted(results["external_ips"])[:200])

    ti_rows = "".join(f"""<tr>
      <td class="mono">{t.get('ip','') or t.get('hash','')}</td>
      <td><span class="badge" style="background:#ff4444">{t.get('detections','') or t.get('score','')}</span></td>
      <td>{t.get('source','')}</td>
      <td>{t.get('name','') or t.get('reports','')}</td>
    </tr>""" for t in results["threat_intel"])

    reg_hits  = results.get("registry_hits", [])
    reg_count = len(reg_hits)
    reg_rows  = "".join(f"""<tr>
      <td><span class="badge" style="background:{'#ff4444' if r.get('severity')=='CRITICAL' else '#f97316'}">{r.get('severity','HIGH')}</span></td>
      <td class="mono" style="color:var(--cyan)">{r.get('hive','')}</td>
      <td class="mono" style="font-size:11px">{r.get('key','')}</td>
      <td class="mono" style="color:var(--yellow)">{r.get('name','')}</td>
      <td class="mono">{str(r.get('data',''))[:200]}</td>
      <td class="mono dim">{r.get('type','')}</td>
    </tr>""" for r in reg_hits[:200])

    alert = (f'<div class="alert-banner">🚨 {crit} CRITICAL findings — Immediate investigation required!</div>'
             if crit > 0 else '')

    # ── JSON data for export ───────────────────────────────────────────────────
    import json as _json
    export_data = _json.dumps({
        "report_title": "Windows Forensics Investigation Report",
        "generated":    datetime.now().isoformat(),
        "host":         "VEEAM-MGMT-SRV",
        "summary": {
            "critical": crit, "high": high, "medium": med,
            "external_ips": ips, "c2_indicators": c2,
            "hayabusa_hits": hay, "cisco_hits": cisco,
            "timeline_start": tl_start, "timeline_end": tl_end,
            "total_events": tl_total,
        },
        "timeline": timeline_events[:1000],
        "critical_findings": [
            {"ts": str(f.get("data",{}).get("timestamp",""))[:19],
             "source": f.get("source",""),
             "desc": f.get("desc",""),
             "detail": str(f.get("data",{}).get("CommandLine") or
                           f.get("data",{}).get("line") or
                           f.get("data",{}).get("value_data") or "")[:300]}
            for f in results["critical"]
        ],
        "external_ips": sorted(list(results["external_ips"])),
        "c2_indicators": results["c2_indicators"],
        "threat_intel": results["threat_intel"],
        "registry_hits": reg_hits,
        "cisco_hits": results["cisco_hits"][:100],
    }, default=str, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensics Report — {datetime.now().strftime('%Y-%m-%d')}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');
:root{{
  --bg:#080d1a;--surf:#0f1629;--surf2:#1a2035;--border:#1e2d45;
  --text:#e2e8f0;--dim:#64748b;
  --red:#ff4444;--orange:#f97316;--yellow:#eab308;
  --green:#22c55e;--blue:#3b82f6;--purple:#a855f7;--cyan:#06b6d4;--pink:#ec4899;
}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;line-height:1.6}}
header{{background:linear-gradient(135deg,#080d1a,#0d1832,#080d1a);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center;gap:16px}}
.logo{{font-size:18px;font-weight:700;color:var(--cyan)}}
.logo-sub{{color:var(--dim);font-size:11px;margin-top:2px}}
.ts{{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim);background:var(--surf2);padding:4px 10px;border-radius:6px;border:1px solid var(--border)}}

/* Export toolbar */
.toolbar{{display:flex;gap:10px;padding:12px 28px;background:var(--surf);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}}
.toolbar-title{{font-weight:600;font-size:13px;color:var(--text);margin-right:8px}}
.export-btn{{display:flex;align-items:center;gap:6px;padding:7px 16px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:none;transition:.15s}}
.export-btn:hover{{filter:brightness(1.15)}}
.btn-pdf{{background:#dc2626;color:#fff}}
.btn-csv{{background:#16a34a;color:#fff}}
.btn-json{{background:#2563eb;color:#fff}}
.btn-html{{background:#7c3aed;color:#fff}}
.btn-print{{background:var(--surf2);color:var(--text);border:1px solid var(--border)}}

.wrap{{max-width:1700px;margin:0 auto;padding:20px 28px}}
.alert-banner{{background:rgba(255,68,68,.1);border:1px solid var(--red);border-radius:8px;padding:12px 18px;margin-bottom:20px;color:var(--red);font-weight:600;font-size:14px}}

/* Timeline summary card */
.tl-summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.tl-card{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}}
.tl-val{{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--cyan)}}
.tl-lbl{{color:var(--dim);font-size:11px;margin-top:3px}}

/* Stats */
.stats{{display:grid;grid-template-columns:repeat(10,1fr);gap:10px;margin-bottom:20px}}
.sc{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:12px 8px;text-align:center;position:relative;overflow:hidden}}
.sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
.sc.r::before{{background:var(--red)}}.sc.o::before{{background:var(--orange)}}
.sc.y::before{{background:var(--yellow)}}.sc.b::before{{background:var(--blue)}}
.sc.p::before{{background:var(--purple)}}.sc.c::before{{background:var(--cyan)}}
.sc.g::before{{background:var(--green)}}.sc.pk::before{{background:var(--pink)}}
.sn{{font-size:24px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.sc.r .sn{{color:var(--red)}}.sc.o .sn{{color:var(--orange)}}.sc.y .sn{{color:var(--yellow)}}
.sc.b .sn{{color:var(--blue)}}.sc.p .sn{{color:var(--purple)}}.sc.c .sn{{color:var(--cyan)}}
.sc.g .sn{{color:var(--green)}}.sc.pk .sn{{color:var(--pink)}}
.sl{{color:var(--dim);font-size:10px;margin-top:3px;text-transform:uppercase;letter-spacing:.3px}}

/* Chart */
.chart-wrap{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:20px}}
.chart-title{{font-size:13px;font-weight:600;margin-bottom:12px;color:var(--text)}}
.chart-container{{position:relative;height:180px}}

/* Tabs */
.tabs{{display:flex;gap:2px;border-bottom:1px solid var(--border);flex-wrap:wrap}}
.tab{{padding:9px 16px;font-size:12px;font-weight:500;cursor:pointer;color:var(--dim);border-radius:6px 6px 0 0;transition:.15s;border:1px solid transparent;border-bottom:none;margin-bottom:-1px}}
.tab:hover{{color:var(--text);background:var(--surf2)}}
.tab.active{{color:var(--cyan);background:var(--surf);border-color:var(--border);border-bottom-color:var(--surf)}}
.tab-panel{{display:none;background:var(--surf);border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;padding:14px}}
.tab-panel.active{{display:block}}

/* Filter bar */
.filter-bar{{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;align-items:center}}
.fb{{background:var(--surf2);border:1px solid var(--border);color:var(--dim);padding:4px 11px;border-radius:16px;font-size:11px;cursor:pointer;transition:.15s}}
.fb:hover,.fb.active{{background:var(--blue);border-color:var(--blue);color:#fff}}
.search-box{{margin-left:auto;background:var(--surf2);border:1px solid var(--border);color:var(--text);padding:5px 12px;border-radius:6px;font-size:12px;width:220px;font-family:'Inter',sans-serif}}
.search-box::placeholder{{color:var(--dim)}}

/* Tables */
.tw{{overflow-x:auto;max-height:520px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--surf2);color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1}}
td{{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:rgba(59,130,246,.04)}}
.badge{{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all}}
.dim{{color:var(--dim)}}
.src-tag{{font-size:11px;color:var(--cyan);font-family:'JetBrains Mono',monospace}}

/* Timeline specific */
.date-sep td{{background:var(--surf2);padding:6px 10px;border-top:2px solid var(--border)}}
.date-label{{font-weight:700;font-size:12px;color:var(--yellow)}}

/* IP tags */
.ip-cloud{{line-height:2.5}}
.ip-tag{{display:inline-block;background:var(--surf2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;margin:2px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim)}}
.empty{{color:var(--dim);font-size:12px;padding:24px;text-align:center}}

/* Tool badges */
.tool-row{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.tool-badge{{background:var(--surf2);border:1px solid var(--border);border-radius:20px;padding:4px 12px;font-size:11px;font-weight:600}}
.tool-badge.ok{{border-color:var(--green);color:var(--green)}}
.tool-badge.warn{{border-color:var(--yellow);color:var(--yellow)}}

/* Print styles */
@media print{{
  .toolbar,.tabs{{display:none}}
  .tab-panel{{display:block!important;border:none;page-break-inside:avoid}}
  body{{background:#fff;color:#000}}
  header{{background:#1e3a5f;color:#fff;-webkit-print-color-adjust:exact}}
  .sc,.tl-card,.chart-wrap{{border:1px solid #ddd}}
}}
footer{{border-top:1px solid var(--border);padding:12px 28px;color:var(--dim);font-size:11px;text-align:center;margin-top:32px}}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">🛡 Forensics Master Analyzer v3.0</div>
    <div class="logo-sub">Hayabusa · Chainsaw · Volatility3 · EVTX · Network · EDR · DNS · Registry</div>
  </div>
  <div class="ts">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</header>

<!-- EXPORT TOOLBAR -->
<div class="toolbar">
  <span class="toolbar-title">📤 Export Report:</span>
  <button class="export-btn btn-pdf" onclick="exportPDF()">📄 PDF Report</button>
  <button class="export-btn btn-csv" onclick="exportCSV()">📊 CSV (All Findings)</button>
  <button class="export-btn btn-csv" onclick="exportTimelineCSV()">⏱ Timeline CSV</button>
  <button class="export-btn btn-json" onclick="exportJSON()">🗂 JSON (Full Data)</button>
  <button class="export-btn btn-html" onclick="exportHTMLReport()">📋 Investigation Report (HTML)</button>
  <button class="export-btn btn-print" onclick="window.print()">🖨 Print</button>
</div>

<div class="wrap">
{alert}

<!-- Timeline summary -->
<div class="tl-summary">
  <div class="tl-card">
    <div class="tl-val">{tl_start}</div>
    <div class="tl-lbl">🕐 Attack Start (First Event)</div>
  </div>
  <div class="tl-card">
    <div class="tl-val">{tl_end}</div>
    <div class="tl-lbl">🕐 Last Event</div>
  </div>
  <div class="tl-card">
    <div class="tl-val" style="color:var(--red)">{tl_total}</div>
    <div class="tl-lbl">📍 Total Timed Events</div>
  </div>
  <div class="tl-card">
    <div class="tl-val" style="color:var(--orange)">{len(dates_sorted)}</div>
    <div class="tl-lbl">📅 Active Days</div>
  </div>
</div>

<!-- Activity Chart -->
<div class="chart-wrap">
  <div class="chart-title">📈 Activity Timeline — Events per Day</div>
  <div class="chart-container">
    <canvas id="activityChart"></canvas>
  </div>
</div>

<!-- Tool status -->
<div class="tool-row">
  <div class="tool-badge {'ok' if hay>0 else 'warn'}">{'✓' if hay>0 else '✗'} Hayabusa ({hay})</div>
  <div class="tool-badge {'ok' if chain>0 else 'warn'}">{'✓' if chain>0 else '✗'} Chainsaw ({chain})</div>
  <div class="tool-badge ok">✓ EVTX Parser</div>
  <div class="tool-badge ok">✓ Network</div>
  <div class="tool-badge {'ok' if cisco>0 else 'warn'}">{'✓' if cisco>0 else '?'} EDR ({cisco})</div>
  <div class="tool-badge {'ok' if reg_count>0 else 'warn'}">{'✓' if reg_count>0 else '?'} Registry ({reg_count})</div>
  <div class="tool-badge {'ok' if ti>0 else 'warn'}">{'✓' if ti>0 else '!'} Threat Intel ({ti})</div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="sc r"><div class="sn">{crit}</div><div class="sl">Critical</div></div>
  <div class="sc o"><div class="sn">{high}</div><div class="sl">High</div></div>
  <div class="sc y"><div class="sn">{med}</div><div class="sl">Medium</div></div>
  <div class="sc b"><div class="sn">{ips}</div><div class="sl">Ext. IPs</div></div>
  <div class="sc p"><div class="sn">{c2}</div><div class="sl">C2 IOCs</div></div>
  <div class="sc c"><div class="sn">{dns}</div><div class="sl">Susp. DNS</div></div>
  <div class="sc pk"><div class="sn">{cisco}</div><div class="sl">EDR</div></div>
  <div class="sc g"><div class="sn">{hay}</div><div class="sl">Hayabusa</div></div>
  <div class="sc g"><div class="sn">{reg_count}</div><div class="sl">Registry</div></div>
  <div class="sc r"><div class="sn">{ti}</div><div class="sl">TI Hits</div></div>
</div>

<!-- TABS -->
<div class="tabs">
  <div class="tab active" onclick="switchTab('timeline',this)">⏱ Timeline ({tl_total})</div>
  <div class="tab" onclick="switchTab('all',this)">All Findings ({len(all_findings)})</div>
  <div class="tab" onclick="switchTab('cisco',this)">🔴 EDR ({cisco})</div>
  <div class="tab" onclick="switchTab('hayabusa',this)">Hayabusa ({hay})</div>
  <div class="tab" onclick="switchTab('c2',this)">C2 ({c2})</div>
  <div class="tab" onclick="switchTab('registry',this)">🔑 Registry ({reg_count})</div>
  <div class="tab" onclick="switchTab('dns',this)">DNS ({dns})</div>
  <div class="tab" onclick="switchTab('ips',this)">IPs ({ips})</div>
  <div class="tab" onclick="switchTab('ti',this)">Threat Intel ({ti})</div>
</div>

<!-- TIMELINE TAB -->
<div id="tab-timeline" class="tab-panel active">
  <div class="filter-bar">
    <button class="fb active" onclick="ftTl('ALL',this)">All</button>
    <button class="fb" onclick="ftTl('CRITICAL',this)">Critical</button>
    <button class="fb" onclick="ftTl('HIGH',this)">High</button>
    <button class="fb" onclick="ftTl('MEDIUM',this)">Medium</button>
    <input class="search-box" id="tl-search" placeholder="🔍 Search timeline..." oninput="searchTimeline(this.value)">
    <button class="export-btn btn-csv" style="padding:5px 12px;font-size:11px" onclick="exportTimelineCSV()">⬇ Export CSV</button>
  </div>
  <div class="tw">
    <table id="tl-table">
      <thead><tr>
        <th>Time</th><th>Severity</th><th>Source</th>
        <th>Description</th><th>Detail</th><th>Computer</th>
      </tr></thead>
      <tbody>{tl_rows if tl_rows else '<tr><td colspan="6" class="empty">No timestamped events found</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- ALL FINDINGS TAB -->
<div id="tab-all" class="tab-panel">
  <div class="filter-bar">
    <button class="fb active" onclick="ft('ALL',this)">All</button>
    <button class="fb" onclick="ft('CRITICAL',this)">Critical ({crit})</button>
    <button class="fb" onclick="ft('HIGH',this)">High ({high})</button>
    <button class="fb" onclick="ft('EVTX',this)">EVTX</button>
    <button class="fb" onclick="ft('NETWORK',this)">Network</button>
    <button class="fb" onclick="ft('HAYABUSA',this)">Hayabusa</button>
    <button class="fb" onclick="ft('CHAINSAW',this)">Chainsaw</button>
    <button class="fb" onclick="ft('MEMORY',this)">Memory</button>
    <button class="fb" onclick="ft('CISCO',this)">EDR</button>
    <button class="fb" onclick="ft('REGISTRY',this)">Registry</button>
    <input class="search-box" id="all-search" placeholder="🔍 Search..." oninput="searchAll(this.value)">
  </div>
  <div class="tw"><table id="findings-table">
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th><th>Computer</th><th>Timestamp</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</div>

<!-- CISCO TAB -->
<div id="tab-cisco" class="tab-panel">
  {'<div class="empty">No EDR events detected.</div>' if not results["cisco_hits"] else
   f'<div class="tw"><table><thead><tr><th>Severity</th><th>Description</th><th>Timestamp</th><th>Detail</th></tr></thead><tbody>{cisco_rows}</tbody></table></div>'}
</div>

<!-- HAYABUSA TAB -->
<div id="tab-hayabusa" class="tab-panel">
  {'<div class="empty">Hayabusa: no hits or not available.</div>' if not results["hayabusa"] else
   f'<div class="tw"><table><thead><tr><th>Severity</th><th>Rule</th><th>Timestamp</th><th>Detail</th></tr></thead><tbody>{hay_rows}</tbody></table></div>'}
</div>

<!-- C2 TAB -->
<div id="tab-c2" class="tab-panel">
  {'<div class="empty">No C2 indicators detected.</div>' if not results["c2_indicators"] else
   f'<div class="tw"><table><thead><tr><th>Type</th><th>IP/Domain</th><th>Port</th><th>Detail</th></tr></thead><tbody>{c2_rows}</tbody></table></div>'}
</div>

<!-- REGISTRY TAB -->
<div id="tab-registry" class="tab-panel">
  {'<div class="empty">No registry persistence entries found.</div>' if not reg_hits else f'''
  <div style="margin-bottom:12px;padding:10px 14px;background:rgba(255,68,68,.08);border:1px solid #ff4444;border-radius:6px;font-size:12px;color:#ff4444">
    ⚠️ These registry entries execute automatically on startup/login. Each entry should be verified as legitimate.
  </div>
  <div class="tw"><table>
    <thead><tr><th>Severity</th><th>Hive</th><th>Registry Key Path</th><th>Value Name</th><th>Value Data</th><th>Type</th></tr></thead>
    <tbody>{reg_rows}</tbody>
  </table></div>'''}
</div>

<!-- DNS TAB -->
<div id="tab-dns" class="tab-panel">
  {'<div class="empty">No suspicious DNS entries.</div>' if not results["dns_hits"] else
   f'<div class="tw"><table><thead><tr><th>Domain</th><th>Query Count</th></tr></thead><tbody>{dns_rows}</tbody></table></div>'}
</div>

<!-- IPs TAB -->
<div id="tab-ips" class="tab-panel">
  <div style="margin-bottom:10px;font-size:12px;color:var(--dim)">{ips} unique external IPs found across all sources</div>
  <div class="ip-cloud">{ip_tags or '<span class="dim">None found</span>'}</div>
</div>

<!-- THREAT INTEL TAB -->
<div id="tab-ti" class="tab-panel">
  {'<div class="empty">No threat intel hits. Add --vt-key / --abuse-key to enable.</div>' if not results["threat_intel"] else
   f'<div class="tw"><table><thead><tr><th>IP / Hash</th><th>Score</th><th>Source</th><th>Detail</th></tr></thead><tbody>{ti_rows}</tbody></table></div>'}
</div>

</div>
<footer>Forensics Master Analyzer v3.0 — For authorized security analysis only — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>

<!-- Embedded data for export -->
<script id="export-data" type="application/json">{export_data}</script>

<script>
// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(id, el) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-' + id).classList.add('active');
}}

// ── Findings filter ───────────────────────────────────────────────────────────
function ft(f, btn) {{
  document.querySelectorAll('.fb').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(r => {{
    const sev = r.dataset.sev || '';
    const src = r.dataset.src || '';
    const search = document.getElementById('all-search')?.value?.toLowerCase() || '';
    const text = r.textContent.toLowerCase();
    const matchFilter = f === 'ALL' || sev === f || src.includes(f);
    const matchSearch = !search || text.includes(search);
    r.style.display = (matchFilter && matchSearch) ? '' : 'none';
  }});
}}

function searchAll(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('#findings-table tbody tr').forEach(r => {{
    if (r.classList.contains('date-sep')) return;
    r.style.display = (!q || r.textContent.toLowerCase().includes(q)) ? '' : 'none';
  }});
}}

// ── Timeline filter ───────────────────────────────────────────────────────────
function ftTl(f, btn) {{
  document.querySelectorAll('#tab-timeline .fb').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const search = document.getElementById('tl-search')?.value?.toLowerCase() || '';
  document.querySelectorAll('#tl-table tbody tr').forEach(r => {{
    if (r.classList.contains('date-sep')) {{ r.style.display = ''; return; }}
    const sev  = r.dataset.sev || '';
    const text = r.textContent.toLowerCase();
    const matchF = f === 'ALL' || sev === f;
    const matchS = !search || text.includes(search);
    r.style.display = (matchF && matchS) ? '' : 'none';
  }});
}}

function searchTimeline(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('#tl-table tbody tr').forEach(r => {{
    if (r.classList.contains('date-sep')) {{ r.style.display = ''; return; }}
    r.style.display = (!q || r.textContent.toLowerCase().includes(q)) ? '' : 'none';
  }});
}}

// ── Activity chart ────────────────────────────────────────────────────────────
const ctx = document.getElementById('activityChart').getContext('2d');
new Chart(ctx, {{
  type: 'bar',
  data: {{
    labels: {chart_labels},
    datasets: [
      {{
        label: 'Critical',
        data: {chart_crit},
        backgroundColor: 'rgba(255,68,68,0.8)',
        borderColor: '#ff4444',
        borderWidth: 1,
      }},
      {{
        label: 'High',
        data: {chart_high},
        backgroundColor: 'rgba(249,115,22,0.7)',
        borderColor: '#f97316',
        borderWidth: 1,
      }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }},
      tooltip: {{ mode: 'index', intersect: false }}
    }},
    scales: {{
      x: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }}, maxRotation: 45 }},
             grid: {{ color: '#1e2d45' }} }},
      y: {{ ticks: {{ color: '#64748b', font: {{ size: 10 }} }},
             grid: {{ color: '#1e2d45' }}, beginAtZero: true }}
    }},
    interaction: {{ mode: 'index', intersect: false }}
  }}
}});

// ── Export functions ──────────────────────────────────────────────────────────
function getExportData() {{
  return JSON.parse(document.getElementById('export-data').textContent);
}}

function downloadFile(content, filename, type) {{
  const blob = new Blob([content], {{ type }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}}

function exportCSV() {{
  const data = getExportData();
  const findings = [...(data.critical_findings || [])];
  let csv = 'Timestamp,Severity,Source,Description,Detail\\n';
  const rows = document.querySelectorAll('#findings-table tbody tr');
  rows.forEach(r => {{
    if (r.style.display === 'none') return;
    const cells = r.querySelectorAll('td');
    if (cells.length < 6) return;
    const row = [
      cells[5].textContent.trim(),
      cells[0].textContent.trim(),
      cells[1].textContent.trim(),
      '"' + cells[2].textContent.trim().replace(/"/g,'""') + '"',
      '"' + cells[3].textContent.trim().replace(/"/g,'""') + '"',
    ].join(',');
    csv += row + '\\n';
  }});
  downloadFile(csv, 'forensics_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv', 'text/csv');
}}

function exportTimelineCSV() {{
  const data = getExportData();
  let csv = 'Timestamp,Severity,Source,Description,Detail,Computer\\n';
  (data.timeline || []).forEach(e => {{
    csv += [
      e.ts, e.sev, e.src,
      '"' + (e.desc||'').replace(/"/g,'""') + '"',
      '"' + (e.det||'').replace(/"/g,'""') + '"',
      '"' + (e.comp||'').replace(/"/g,'""') + '"',
    ].join(',') + '\\n';
  }});
  downloadFile(csv, 'forensics_timeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv', 'text/csv');
}}

function exportJSON() {{
  const data = getExportData();
  downloadFile(JSON.stringify(data, null, 2),
    'forensics_full_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json', 'application/json');
}}

function exportPDF() {{
  window.print();
}}

function exportHTMLReport() {{
  const data = getExportData();
  const s = data.summary;
  const tl = (data.timeline || []);
  const crits = (data.critical_findings || []);

  let tlHTML = '';
  let prevDate = '';
  tl.forEach(e => {{
    const date = e.ts.substring(0,10);
    if (date !== prevDate) {{
      tlHTML += `<tr style="background:#f0f4ff"><td colspan="5" style="font-weight:700;padding:8px 10px;color:#1e3a5f">📅 ${{date}}</td></tr>`;
      prevDate = date;
    }}
    const sevColor = e.sev === 'CRITICAL' ? '#dc2626' : e.sev === 'HIGH' ? '#ea580c' : '#ca8a04';
    tlHTML += `<tr>
      <td style="font-family:monospace;white-space:nowrap">${{e.ts.substring(11,19)}}</td>
      <td><span style="background:${{sevColor}};color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:700">${{e.sev}}</span></td>
      <td style="color:#0369a1;font-family:monospace;font-size:11px">${{e.src}}</td>
      <td>${{e.desc}}</td>
      <td style="font-family:monospace;font-size:11px;color:#64748b">${{(e.det||'').substring(0,120)}}</td>
    </tr>`;
  }});

  let critHTML = crits.slice(0,50).map(f => `
    <tr>
      <td style="font-family:monospace;font-size:11px">${{(f.ts||'').substring(0,19)}}</td>
      <td style="color:#0369a1;font-family:monospace;font-size:11px">${{f.source}}</td>
      <td>${{f.desc}}</td>
      <td style="font-family:monospace;font-size:11px;color:#64748b">${{(f.detail||'').substring(0,150)}}</td>
    </tr>`).join('');

  const regHTML = (data.registry_hits||[]).slice(0,30).map(r => `
    <tr>
      <td style="font-weight:700;color:${{r.severity==='CRITICAL'?'#dc2626':'#ea580c'}}">${{r.severity||'HIGH'}}</td>
      <td style="font-family:monospace;font-size:11px">${{r.hive||''}}</td>
      <td style="font-family:monospace;font-size:11px">${{(r.key||'').substring(0,60)}}</td>
      <td style="font-family:monospace;font-size:11px">${{r.name||''}}</td>
      <td style="font-family:monospace;font-size:11px">${{(r.data||'').substring(0,100)}}</td>
    </tr>`).join('');

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Forensics Investigation Report — ${{data.generated?.substring(0,10)||''}}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#1e293b;margin:0;padding:0}}
  .cover{{background:linear-gradient(135deg,#1e3a5f,#0f2444);color:#fff;padding:60px 50px;min-height:280px}}
  .cover h1{{font-size:28px;margin-bottom:8px}}
  .cover .sub{{color:#94a3b8;font-size:14px;margin-bottom:30px}}
  .cover-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:30px}}
  .cover-stat{{background:rgba(255,255,255,.1);border-radius:8px;padding:14px;text-align:center}}
  .cover-stat .n{{font-size:28px;font-weight:700}}
  .cover-stat .l{{font-size:11px;opacity:.7;margin-top:2px}}
  .cover-stat.red .n{{color:#fca5a5}}
  .cover-stat.orange .n{{color:#fdba74}}
  .cover-stat.blue .n{{color:#93c5fd}}
  section{{padding:30px 40px;border-bottom:1px solid #e2e8f0}}
  h2{{font-size:16px;font-weight:700;color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:8px;margin-bottom:16px}}
  h3{{font-size:13px;font-weight:600;color:#334155;margin:16px 0 8px}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px}}
  th{{background:#1e3a5f;color:#fff;padding:8px 10px;text-align:left;font-size:11px}}
  td{{padding:7px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}}
  tr:nth-child(even) td{{background:#f8fafc}}
  .alert-box{{background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;padding:12px 16px;margin-bottom:16px;color:#dc2626;font-weight:600}}
  .info-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:20px}}
  .info-card{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px}}
  .info-card .label{{font-size:10px;text-transform:uppercase;color:#64748b;letter-spacing:.5px;margin-bottom:4px}}
  .info-card .value{{font-weight:600;color:#1e293b}}
  @media print{{section{{page-break-inside:avoid}}}}
</style>
</head><body>

<div class="cover">
  <h1>🛡 Forensics Investigation Report</h1>
  <div class="sub">Windows Security Analysis — VEEAM-MGMT-SRV — ${{data.generated?.substring(0,10)||''}}</div>
  <div style="background:rgba(220,38,38,.3);border:1px solid #fca5a5;border-radius:6px;padding:10px 16px;margin-top:16px;font-size:13px">
    🚨 ${{s.critical}} CRITICAL findings require immediate investigation
  </div>
  <div class="cover-grid">
    <div class="cover-stat red"><div class="n">${{s.critical}}</div><div class="l">Critical</div></div>
    <div class="cover-stat orange"><div class="n">${{s.high}}</div><div class="l">High</div></div>
    <div class="cover-stat blue"><div class="n">${{s.total_events}}</div><div class="l">Timeline Events</div></div>
    <div class="cover-stat"><div class="n">${{s.external_ips}}</div><div class="l">External IPs</div></div>
    <div class="cover-stat"><div class="n">${{s.cisco_hits}}</div><div class="l">EDR Detections</div></div>
    <div class="cover-stat"><div class="n">${{s.hayabusa_hits}}</div><div class="l">Hayabusa Hits</div></div>
  </div>
</div>

<section>
  <h2>1. Investigation Summary</h2>
  <div class="info-grid">
    <div class="info-card"><div class="label">Attack Start</div><div class="value">${{s.timeline_start}}</div></div>
    <div class="info-card"><div class="label">Last Activity</div><div class="value">${{s.timeline_end}}</div></div>
    <div class="info-card"><div class="label">Active Days</div><div class="value">${{tl.length > 0 ? [...new Set(tl.map(e=>e.ts.substring(0,10)))].length : 0}} days</div></div>
    <div class="info-card"><div class="label">External IPs</div><div class="value">${{s.external_ips}} unique IPs</div></div>
  </div>
  <div class="alert-box">Key Finding: Audit logs were cleared multiple times (EID 1102/104) indicating active attacker presence and evidence tampering.</div>
</section>

<section>
  <h2>2. Critical Findings</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>${{critHTML || '<tr><td colspan="4">No critical findings</td></tr>'}}</tbody>
  </table>
</section>

<section>
  <h2>3. Attack Timeline (Chronological)</h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>${{tlHTML || '<tr><td colspan="5">No timeline data</td></tr>'}}</tbody>
  </table>
</section>

<section>
  <h2>4. Registry Persistence</h2>
  ${{regHTML ? `<table><thead><tr><th>Severity</th><th>Hive</th><th>Key</th><th>Value Name</th><th>Value Data</th></tr></thead><tbody>${{regHTML}}</tbody></table>` : '<p style="color:#64748b">No registry persistence entries found.</p>'}}
</section>

<section>
  <h2>5. External IP Addresses</h2>
  <p style="font-family:monospace;font-size:11px;color:#334155;line-height:2">
    ${{(data.external_ips||[]).join(' &nbsp;|&nbsp; ')}}
  </p>
</section>

<section>
  <h2>6. Threat Intelligence</h2>
  ${{(data.threat_intel||[]).length > 0 ?
    `<table><thead><tr><th>IP/Hash</th><th>Score</th><th>Source</th><th>Detail</th></tr></thead><tbody>` +
    data.threat_intel.map(t=>`<tr><td>${{t.ip||t.hash||''}}</td><td>${{t.detections||t.score||''}}</td><td>${{t.source||''}}</td><td>${{t.name||t.reports||''}}</td></tr>`).join('') +
    `</tbody></table>` :
    '<p style="color:#64748b">No threat intel hits recorded. Configure API keys for enrichment.</p>'
  }}
</section>

<section style="background:#f8fafc;border-bottom:none">
  <h2>7. Report Information</h2>
  <p style="color:#64748b;font-size:12px">
    Generated: ${{data.generated}}<br>
    Tool: Windows Forensics Master Analyzer v3.0<br>
    Modules: Hayabusa · Chainsaw · Volatility3 · python-evtx · Network · DNS · Registry<br>
    <strong>This report is for authorized security analysis only.</strong>
  </p>
</section>

</body></html>`;

  downloadFile(html, 'forensics_investigation_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html', 'text/html');
}}
</script>
</body></html>"""

    html_path = Path(output_dir) / "dashboard.html"
    html_path.write_text(html, encoding='utf-8')
    win_log("OK", f"Dashboard: {html_path}")
    return html_path

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

# ===== EPR_BLOCK_BEGIN =====
from datetime import timedelta, timezone
import os, re, csv, json, sys, ipaddress, subprocess, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter, defaultdict
from xml.sax.saxutils import escape as epr__esc
import xml.etree.ElementTree as epr_ET

epr_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
epr_FMT = "%Y-%m-%d %H:%M:%S"

# --------------------------------------------------------------------------- helpers
def epr_esc(x):
    return epr__esc(str(x if x is not None else ""))


def epr_parse_ts(s):
    """Parse many timestamp styles -> naive UTC datetime (or None)."""
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    s = str(s).strip().replace("T", " ")
    off = None
    m = re.search(r"\s*(Z|[+-]\d\d:?\d\d)$", s)
    if m:
        tz = m.group(1)
        s = s[:m.start()]
        if tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[-2:])
            off = timedelta(hours=hh, minutes=mm) * sign
    s = re.sub(r"\.\d+$", "", s.strip())
    try:
        d = datetime.strptime(s[:19], epr_FMT)
    except ValueError:
        return None
    return d - off if off else d


def epr_fmt(d):
    return d.strftime(epr_FMT) if d else "-"


def epr_is_local_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
        return a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return True  # '-', '', 'LOCAL' etc.


def epr_is_private_ip(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


def epr__g(d, *names, default=""):
    low = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return str(v)
    return default


# --------------------------------------------------------------------------- patterns
epr_MAL_PATTERNS = [
    (re.compile(r"powershell.*-[Ee][Nn][Cc]", re.I), "Encoded PowerShell"),
    (re.compile(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest.*http", re.I), "Download cradle"),
    (re.compile(r"\bIEX\b|\bInvoke-Expression\b", re.I), "PowerShell IEX"),
    (re.compile(r"certutil.+(-decode|-urlcache)", re.I), "Certutil LOLBin"),
    (re.compile(r"\bmshta\b.+http", re.I), "MSHTA remote"),
    (re.compile(r"regsvr32.+(scrobj|http)", re.I), "Regsvr32 squiblydoo"),
    (re.compile(r"vssadmin.+delete.+shadows", re.I), "Shadow copy delete"),
    (re.compile(r"wbadmin.+delete", re.I), "Backup catalog delete"),
    (re.compile(r"mimikatz|sekurlsa|lsadump|procdump.+lsass", re.I), "Credential dumping"),
    (re.compile(r"net\s+(user|localgroup).+/add", re.I), "Account manipulation"),
    (re.compile(r"psexec|wmiexec|smbexec|dcomexec", re.I), "Lateral movement tool"),
    (re.compile(r"netsh.+portproxy", re.I), "Port proxy tunnel"),
    (re.compile(r"bitsadmin.+transfer", re.I), "BITSAdmin transfer"),
    (re.compile(r"nbtscan|advanced_ip_scanner|fscan|masscan", re.I), "Network scanner"),
]
epr_POST_EXPLOIT = re.compile(r"nbtscan|netscan|ipscan|portscan|mimikatz|psexec|procdump|lazagne|rubeus|sharphound|bloodhound|"
                          r"cobalt|beacon|meterpreter|plink|ngrok|chisel|\bfrp|proxy|tunnel|credential|lateral|"
                          r"scanner|discovery", re.I)
epr_SPAWNERS = re.compile(r"(w3wp|httpd|nginx|tomcat|java|sqlservr|veeam[^\\]*|php-cgi|winword|excel|outlook)\.exe$", re.I)
epr_SHELLS = re.compile(r"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$", re.I)
epr_SKIP_USERS = re.compile(r"(\$$|^(SYSTEM|ANONYMOUS LOGON|LOCAL SERVICE|NETWORK SERVICE|-)$|^DWM-|^UMFD-)", re.I)
epr_EDR_NAMES = ["cisco", "ciscosecureendpoint", "crowdstrike", "falcon", "sentinelone", "carbonblack", "carbon black",
             "symantec", "sophos", "trendmicro", "mcafee", "trellix", "eset", "malwarebytes", "cylance", "fireeye"]

epr_KIND_LABEL = {
    "logon_ok": "Successful remote logon", "logon_fail": "Failed logon", "explicit_cred": "Explicit credential use",
    "ntlm": "NTLM authentication", "acct_created": "User account created", "group_add": "Added to privileged group",
    "svc_install": "Service installed", "task_created": "Scheduled task created", "audit_changed": "Audit policy changed",
    "log_cleared": "Event log cleared", "rdp_auth": "RDP authentication", "rdp_session": "RDP session",
    "proc_create": "Process creation", "net_conn": "Outbound connection (Sysmon)", "ps_block": "PowerShell script block",
    "av_detect": "Defender detection", "av_history_deleted": "Defender history deleted", "av_config": "Defender config changed",
    "edr_detect": "EDR detection", "cred_access": "Credential store access", "dll_block": "Unsigned DLL blocked",
    "smb_discovery": "SMB share discovery", "fw_change": "Firewall settings changed", "pwd_reset": "Password reset",
}

# --------------------------------------------------------------------------- EVTX parsing
def epr_parse_event_xml(xml):
    """XML string -> dict(ts, eid, channel, computer, data) ; None if malformed."""
    try:
        root = epr_ET.fromstring(xml)
    except epr_ET.ParseError:
        return None
    s = root.find(epr_NS + "System")
    if s is None:
        return None
    try:
        eid = int((s.find(epr_NS + "EventID").text or "0").strip())
    except Exception:
        return None
    tc = s.find(epr_NS + "TimeCreated")
    ts = epr_parse_ts(tc.get("SystemTime") if tc is not None else "")
    ch = s.find(epr_NS + "Channel")
    comp = s.find(epr_NS + "Computer")
    data = {}
    ed = root.find(epr_NS + "EventData")
    if ed is not None:
        pos = 0
        for d in ed.findall(epr_NS + "Data"):
            nm = d.get("Name")
            if nm:
                data[nm] = d.text or ""
            else:
                data["Data%d" % pos] = d.text or ""
            pos += 1
    ud = root.find(epr_NS + "UserData")
    if ud is not None:
        for el in ud.iter():
            tag = el.tag.split("}")[-1]
            if el.text and el.text.strip() and len(list(el)) == 0:
                data[tag] = el.text.strip()
    return {"ts": ts, "eid": eid, "channel": (ch.text if ch is not None else ""), "computer": (comp.text if comp is not None else ""),
            "data": data}


def epr_file_role(name):
    n = name.lower()
    if "sysmon" in n: return "sysmon"
    if "defender" in n: return "defender"
    if "remoteconnectionmanager" in n or "localsessionmanager" in n or "rdpcorets" in n: return "rdp"
    if "powershell" in n: return "powershell"
    if any(v in n for v in epr_EDR_NAMES): return "edr"
    if n == "security.evtx": return "security"
    if n == "system.evtx": return "system"
    return None


epr_SEC_KEEP = {4624, 4625, 4648, 4720, 4724, 4728, 4732, 4756, 4697, 4698, 4719, 1102, 4778, 4779, 4776, 4688}


def epr_classify(role, ev):
    """Return (kind, label_text, severity) or None for an event of interest."""
    e, d = ev["eid"], ev["data"]
    if role == "security":
        if e == 4624:
            lt = epr__g(d, "LogonType"); user = epr__g(d, "TargetUserName"); ip = epr__g(d, "IpAddress")
            if epr_SKIP_USERS.search(user) or lt not in ("3", "7", "9", "10", "11", "2"):
                return None
            if lt in ("3", "9") and epr_is_local_ip(ip):
                return None
            if lt in ("2", "7", "11") and epr_is_local_ip(ip):
                return None
            return ("logon_ok", f"{epr__g(d,'TargetDomainName')}\\{user} type {lt} from {ip or '-'}", "INFO")
        if e == 4625:
            return ("logon_fail", f"{epr__g(d,'TargetUserName')} type {epr__g(d,'LogonType')} from {epr__g(d,'IpAddress') or '-'}", "INFO")
        if e == 4648:
            return ("explicit_cred", f"{epr__g(d,'SubjectUserName')} -> {epr__g(d,'TargetUserName')} @ {epr__g(d,'TargetServerName')} via {epr__g(d,'ProcessName')}", "MEDIUM")
        if e == 4776:
            return ("ntlm", f"{epr__g(d,'TargetUserName')} from {epr__g(d,'Workstation')}", "INFO")
        if e == 4720:
            return ("acct_created", f"{epr__g(d,'TargetUserName')} created by {epr__g(d,'SubjectUserName')}", "HIGH")
        if e == 4724:
            return ("pwd_reset", f"{epr__g(d,'TargetUserName')} reset by {epr__g(d,'SubjectUserName')}", "MEDIUM")
        if e in (4728, 4732, 4756):
            return ("group_add", f"{epr__g(d,'MemberName','MemberSid')} added to {epr__g(d,'TargetUserName')} by {epr__g(d,'SubjectUserName')}", "HIGH")
        if e == 4697:
            return ("svc_install", f"{epr__g(d,'ServiceName')} -> {epr__g(d,'ServiceFileName')}", "HIGH")
        if e == 4698:
            return ("task_created", f"{epr__g(d,'TaskName')} by {epr__g(d,'SubjectUserName')}", "HIGH")
        if e == 4719:
            return ("audit_changed", f"audit policy changed by {epr__g(d,'SubjectUserName')}", "MEDIUM")
        if e == 1102:
            return ("log_cleared", f"Security log cleared by {epr__g(d,'SubjectUserName')}", "CRITICAL")
        if e in (4778, 4779):
            return ("rdp_session", f"{epr__g(d,'AccountName')} from {epr__g(d,'ClientAddress')} ({'reconnect' if e==4778 else 'disconnect'})", "INFO")
        if e == 4688:
            cmd = epr__g(d, "CommandLine"); img = epr__g(d, "NewProcessName"); par = epr__g(d, "ParentProcessName")
            return epr__proc_event(img, cmd, par, epr__g(d, "SubjectUserName"))
    elif role == "system":
        if e == 7045:
            return ("svc_install", f"{epr__g(d,'ServiceName')} -> {epr__g(d,'ImagePath')}", "HIGH")
        if e == 104:
            return ("log_cleared", "System log cleared", "CRITICAL")
    elif role == "rdp":
        if e == 1149:
            return ("rdp_auth", f"{epr__g(d,'Param2')}\\{epr__g(d,'Param1')} from {epr__g(d,'Param3')}", "INFO")
        if e in (21, 22, 25):
            return ("rdp_session", f"{epr__g(d,'User')} from {epr__g(d,'Address')} (EID {e})", "INFO")
    elif role == "powershell":
        if e == 4104:
            txt = epr__g(d, "ScriptBlockText")
            for pat, nm in epr_MAL_PATTERNS:
                if pat.search(txt):
                    return ("ps_block", f"{nm}: {txt[:120]}", "HIGH")
    elif role == "sysmon":
        if e == 1:
            return epr__proc_event(epr__g(d, "Image"), epr__g(d, "CommandLine"), epr__g(d, "ParentImage"), epr__g(d, "User"))
        if e == 3:
            dst = epr__g(d, "DestinationIp")
            if dst and not epr_is_private_ip(dst):
                return ("net_conn", f"{epr__g(d,'Image')} -> {dst}:{epr__g(d,'DestinationPort')}", "INFO")
    elif role == "defender":
        if e in (1116, 1117):
            return ("av_detect", f"{epr__g(d,'Threat Name')} | {epr__g(d,'Path')} | action {epr__g(d,'Action Name')}", "CRITICAL")
        if e == 1013:
            return ("av_history_deleted", f"history deleted by {epr__g(d,'User')}", "MEDIUM")
        if e in (5001, 5004, 5010, 5012):
            return ("av_config", f"EID {e}", "MEDIUM")
    elif role == "edr":
        det = epr_edr_fields(ev)
        if det:
            return ("edr_detect", f"{det['name']} | {det['path']}", "CRITICAL")
    return None


def epr__proc_event(img, cmd, parent, user):
    full = f"{img} {cmd}"
    for pat, nm in epr_MAL_PATTERNS:
        if pat.search(full):
            return ("proc_create", f"{nm}: {cmd[:140] or img}", "CRITICAL")
    if epr_SPAWNERS.search(parent or "") and epr_SHELLS.search(img or ""):
        return ("proc_create", f"SERVICE-SPAWNED SHELL: {os.path.basename(parent)} -> {os.path.basename(img)} {cmd[:100]}", "HIGH")
    return None


def epr_edr_fields(ev):
    """Heuristic extraction of a detection from a generic EDR event."""
    d = ev["data"]
    keys = " ".join(d.keys()).lower() + " " + " ".join(str(v) for v in d.values()).lower()
    if not re.search(r"threat|detect|malware|quarantin|disposition|ioc|trojan|ransom", keys):
        return None
    def pick(rx):
        for k, v in d.items():
            if re.search(rx, k, re.I) and v:
                return str(v)
        return ""
    name = pick(r"threat.?name|detection.?name|signature|detection|threat|malware") or epr__g(d, "Name")
    if not name:
        return None
    return {"name": name, "path": pick(r"file.?path|path|filename|file|image|target"),
            "process": pick(r"parent|process|app"), "hash": pick(r"sha.?256|sha1|md5|hash"),
            "action": pick(r"action|disposition|result"), "user": pick(r"user|account")}


def epr_collect_events(evtx_dir, log=print):
    """Scan EVTX files. Returns (events, coverage). coverage[file] = first/last/records/role."""
    events, coverage = [], {}
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        log("WARN", "python-evtx missing - EVTX re-scan skipped (pip install python-evtx)")
        return events, coverage
    rx_eid = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
    rx_time = re.compile(r'SystemTime="([^"]+)"')
    for fp in sorted(Path(evtx_dir).rglob("*.evtx")):
        role = epr_file_role(fp.name)
        if not role:
            continue
        first = last = None
        n = 0
        try:
            with Evtx(str(fp)) as lf:
                for rec in lf.records():
                    try:
                        xml = rec.xml()
                    except Exception:
                        continue
                    n += 1
                    mt = rx_time.search(xml)
                    t = epr_parse_ts(mt.group(1)) if mt else None
                    if t:
                        first = t if first is None or t < first else first
                        last = t if last is None or t > last else last
                    me = rx_eid.search(xml)
                    if not me:
                        continue
                    eid = int(me.group(1))
                    if role == "security" and eid not in epr_SEC_KEEP:
                        continue
                    if role == "system" and eid not in (7045, 104):
                        continue
                    if role == "rdp" and eid not in (1149, 21, 22, 25):
                        continue
                    if role == "powershell" and eid != 4104:
                        continue
                    if role == "sysmon" and eid not in (1, 3):
                        continue
                    if role == "defender" and eid not in (1116, 1117, 1013, 5001, 5004, 5010, 5012):
                        continue
                    ev = epr_parse_event_xml(xml)
                    if not ev or not ev["ts"]:
                        continue
                    c = epr_classify(role, ev)
                    if c:
                        events.append({"ts": ev["ts"], "eid": ev["eid"], "kind": c[0], "text": c[1], "sev": c[2],
                                       "log": fp.name, "host": ev["computer"], "data": ev["data"]})
        except Exception as ex:
            log("WARN", f"  {fp.name}: {ex}")
        coverage[fp.name] = {"role": role, "first": first, "last": last, "records": n}
        log("INFO", f"  {fp.name}: {n} records, {epr_fmt(first)} -> {epr_fmt(last)}")
    return events, coverage


# --------------------------------------------------------------------------- other inputs
def epr_load_edr_csv(path):
    dets = []
    if not path or not Path(path).exists():
        return dets
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            dets.append({"kind": r.get("kind", "detection"), "name": r.get("threat_or_event", "").replace("EDR TAMPER: ", "").split(" \u2014 ")[0], "path": r.get("file_path", ""),
                         "process": (r.get("process", "").split(";")[0]).strip(), "hash": r.get("hash", ""),
                         "action": r.get("action", ""), "endpoint": r.get("endpoint", ""), "user": r.get("user", ""),
                         "count": int(r.get("count") or 1), "first": epr_parse_ts(r.get("first_seen")),
                         "last": epr_parse_ts(r.get("last_seen")), "log": r.get("source_log", ""), "sev": r.get("severity", "")})
    return dets


epr_HAY_MAP = [("admin grp", "group_add"), ("account created", "acct_created"), ("suspicious service path", "svc_install"),
           ("event auditing disabled", "audit_changed"), ("credential manager", "cred_access"), ("unsigned dll", "dll_block"),
           ("smb share", "smb_discovery"), ("firewall settings", "fw_change"), ("log cleared", "log_cleared")]


def epr_load_hayabusa(path):
    ev = []
    if not path or not Path(path).exists():
        return ev
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            title = (r.get("RuleTitle") or r.get("Title") or "").strip()
            t = epr_parse_ts(r.get("Timestamp") or "")
            if not title or not t:
                continue
            for key, kind in epr_HAY_MAP:
                if key in title.lower():
                    ev.append({"ts": t, "eid": r.get("EventID", ""), "kind": kind, "text": f"{title} | {(r.get('Details') or '')[:140]}",
                               "sev": (r.get("Level") or "").upper(), "log": "hayabusa", "host": r.get("Computer", ""), "data": {}})
                    break
    return ev


def epr_aggregate_detections(events):
    """Group own EDR/AV detection events into detection records (same shape as edr csv)."""
    g = {}
    for e in events:
        if e["kind"] not in ("edr_detect", "av_detect"):
            continue
        d = e["data"]
        if e["kind"] == "av_detect":
            name, path, proc, act, h = epr__g(d, "Threat Name"), epr__g(d, "Path"), epr__g(d, "Process Name"), epr__g(d, "Action Name"), epr__g(d, "SHA256", "Sha256")
            user = epr__g(d, "Detection User")
        else:
            f = epr_edr_fields({"data": d}) or {}
            name, path, proc, act, h, user = f.get("name", ""), f.get("path", ""), f.get("process", ""), f.get("action", ""), f.get("hash", ""), f.get("user", "")
        k = (name, path)
        r = g.setdefault(k, {"kind": "detection", "name": name, "path": path, "process": proc, "hash": h, "action": act,
                             "endpoint": e["host"], "user": user, "count": 0, "first": e["ts"], "last": e["ts"], "log": e["log"], "sev": "CRITICAL"})
        r["count"] += 1
        r["first"] = min(r["first"], e["ts"]); r["last"] = max(r["last"], e["ts"])
    return list(g.values())


def epr_tamper_from_events(events):
    out = []
    for kind, label in (("av_history_deleted", "Defender: malware-detection history deleted (EID 1013)"),
                        ("av_config", "Defender: real-time protection / config changed")):
        ts = sorted(e["ts"] for e in events if e["kind"] == kind)
        if ts:
            out.append({"kind": "tamper", "name": label, "path": "", "process": "", "hash": "", "action": "", "endpoint": "", "user": "",
                        "count": len(ts), "first": ts[0], "last": ts[-1], "log": "Defender_Operational.evtx", "sev": "MEDIUM"})
    return out


# --------------------------------------------------------------------------- entry point engine
def epr_find_entry_point(events, detections, coverage, ctx, window_h=72):
    res = {"status": "NOT DETERMINED", "confidence": "n/a", "vector": "", "access_event": None, "evidence": [], "reasons": [],
           "candidates": [], "anchor": None, "anchor_class": "", "window_hours": window_h}

    # ---- anchor: earliest confirmed malicious artifact
    cand = []
    for d in detections:
        if d["kind"] == "detection" and d["first"]:
            cand.append((d["first"], "EDR/AV detection", d["name"], d["path"], d["process"], d["user"], d["log"]))
    for e in events:
        if e["kind"] in ("proc_create", "ps_block", "log_cleared"):
            cand.append((e["ts"], epr_KIND_LABEL[e["kind"]], e["text"][:90], "", "", "", e["log"]))
    cand.sort(key=lambda x: x[0])
    anchor = None
    if cand:
        a = cand[0]
        anchor = {"time": a[0], "source": a[1], "name": a[2], "path": a[3], "process": a[4], "user": a[5], "log": a[6]}
        res["anchor"] = anchor
        blob = f"{a[2]} {a[3]}"
        if epr_POST_EXPLOIT.search(blob):
            res["anchor_class"] = "post-exploitation"
        else:
            res["anchor_class"] = "unclassified"
    T = anchor["time"] if anchor else None

    # ---- access evidence before the anchor
    if T:
        win = timedelta(hours=window_h)
        lo = T - win
        ok = [e for e in events if e["kind"] in ("logon_ok", "rdp_auth", "rdp_session") and lo <= e["ts"] <= T + timedelta(minutes=5)]

        def ip_of(e):
            m = re.search(r"from\s+([0-9a-fA-F:.]+)", e["text"])
            return m.group(1) if m else ""
        fails_by_ip = defaultdict(list)
        for e in events:
            if e["kind"] == "logon_fail":
                ip = ip_of(e)
                if ip and not epr_is_local_ip(ip):
                    fails_by_ip[ip].append(e["ts"])
        # (b) brute force then success (any time up to 30 days before anchor)
        bf = None
        for e in sorted([x for x in events if x["kind"] in ("logon_ok", "rdp_auth") and x["ts"] <= T + timedelta(minutes=5)
                         and x["ts"] >= T - timedelta(days=30)], key=lambda x: x["ts"]):
            ip = ip_of(e)
            if not ip or epr_is_local_ip(ip):
                continue
            n = sum(1 for t in fails_by_ip.get(ip, []) if e["ts"] - timedelta(hours=2) <= t <= e["ts"])
            if n >= 10:
                bf = (e, ip, n)
                break
        ext = [e for e in ok if e["kind"] != "rdp_session" and ip_of(e) and not epr_is_private_ip(ip_of(e))]
        internal = [e for e in ok if e["kind"] != "rdp_session" and ip_of(e) and epr_is_private_ip(ip_of(e)) and not epr_is_local_ip(ip_of(e))]
        spawn = [e for e in events if e["kind"] == "proc_create" and e["text"].startswith("SERVICE-SPAWNED")
                 and T - timedelta(hours=24) <= e["ts"] <= T + timedelta(hours=24)]
        if bf:
            e, ip, n = bf
            res.update(status="PROBABLE ENTRY POINT", confidence="Medium-High",
                       vector=f"Credential attack: {n} failed logons from {ip} followed by a successful logon",
                       access_event={"time": e["ts"], "text": e["text"], "log": e["log"]})
            res["evidence"].append((e["ts"], f"{n} failed logons from {ip} in the 2 h before this success: {e['text']}"))
        elif ext:
            e = sorted(ext, key=lambda x: x["ts"])[0]
            res.update(status="PROBABLE ENTRY POINT", confidence="Medium",
                       vector=f"Remote logon from external address {ip_of(e)}",
                       access_event={"time": e["ts"], "text": e["text"], "log": e["log"]})
            res["evidence"].append((e["ts"], f"External remote logon within {window_h} h before first malicious artifact: {e['text']}"))
        elif spawn:
            e = spawn[0]
            res.update(status="PROBABLE ENTRY POINT", confidence="Medium",
                       vector="Exploitation of a service / web application (service spawned a shell)",
                       access_event={"time": e["ts"], "text": e["text"], "log": e["log"]})
            res["evidence"].append((e["ts"], e["text"]))
        elif internal:
            e = sorted(internal, key=lambda x: x["ts"])[0]
            res.update(status="POSSIBLE ENTRY POINT", confidence="Low-Medium",
                       vector=f"Lateral movement from internal host {ip_of(e)}",
                       access_event={"time": e["ts"], "text": e["text"], "log": e["log"]})
            res["evidence"].append((e["ts"], f"Internal remote logon shortly before first malicious artifact: {e['text']}"))

        # candidate table (always built from real counts)
        nf = sum(len(v) for v in fails_by_ip.values()); top = Counter({k: len(v) for k, v in fails_by_ip.items()}).most_common(1)
        allfail = [e for e in events if e["kind"] == "logon_fail"]
        if allfail:
            res["candidates"].append(("Credential attack (RDP/SMB/WinRM)", f"{len(allfail)} failed logons" + (f"; {nf} from external IPs, top {top[0][0]} x{top[0][1]}" if top else ""),
                                      "Strong" if bf else "Weak", "Correlate source IP with later 4624 success; check exposure of RDP/SMB."))
        if any(e["kind"] == "proc_create" and e["text"].startswith("SERVICE-SPAWNED") for e in events):
            res["candidates"].append(("Service / web exploitation", f"{len([e for e in events if e['text'].startswith('SERVICE-SPAWNED')])} service-spawned shell events",
                                      "Moderate" if spawn else "Weak", "Review service/IIS logs and patch level around the first artifact."))
        nl = len([e for e in events if e["kind"] in ("explicit_cred", "ntlm")])
        if nl:
            res["candidates"].append(("Valid accounts / lateral movement", f"{nl} explicit-credential / NTLM events", "Moderate" if internal else "Weak",
                                      "Find the originating host and check it for the same artifacts."))
        if not res["candidates"]:
            res["candidates"].append(("Unknown", "No logon, RDP or service-spawn telemetry available", "None", "Collect the missing sources listed in the reasons."))

    # ---- reasons (always computed; they explain gaps even when a probable vector exists)
    R = res["reasons"]
    if not anchor:
        R.append(("No malicious artifact with a timestamp", "No EDR/Defender detection, malicious process or log-clear event was found, so there is no reference time to search backwards from."))
    else:
        if res["anchor_class"] == "post-exploitation":
            R.append(("Earliest artifact is post-exploitation activity",
                      f"'{anchor['name']}' ({epr_fmt(T)}) is a discovery/lateral-movement style tool, so the attacker was already inside; initial access happened before this time."))
        sec = [c for n, c in coverage.items() if c["role"] == "security"]
        if not ctx.get("evtx_given"):
            R.append(("EVTX folder not analysed in this run", "No EVTX directory was supplied, so no logon or process telemetry could be correlated."))
        elif not sec:
            R.append(("Security.evtx not found", "Without the Security log there is no logon (4624/4625), process-creation (4688) or account-change evidence."))
        else:
            c = sec[0]
            if c["first"] and c["first"] > T - timedelta(hours=window_h):
                R.append(("Security log does not reach back to the first artifact",
                          f"Oldest Security record is {epr_fmt(c['first'])} ({(c['first']-T).days} days AFTER the first malicious artifact at {epr_fmt(T)}). Logon history for the intrusion was overwritten."))
            else:
                R.append(("Security log covers the first artifact but shows no access",
                          f"Security log spans {epr_fmt(c['first'])} to {epr_fmt(c['last'])}; no external/remote successful logon, brute-force success or service-spawned shell was found in the {window_h} h before {epr_fmt(T)}."))
            n4688 = sum(1 for e in events if e["eid"] == 4688)
            n4624 = sum(1 for e in events if e["kind"] == "logon_ok")
            R.append(("Logon / process-creation telemetry",
                      f"{n4624} remote successful logons and {n4688} suspicious process-creation events were recorded across the whole log; "
                      "process-creation (4688) auditing with command line is needed to see how the first payload ran."))
        if ctx.get("evtx_given") and not any(c["role"] == "sysmon" for c in coverage.values()):
            R.append(("No Sysmon log", "No process-tree / network-connect telemetry (Sysmon EID 1/3/11) exists to reconstruct parent-child chains."))
        if ctx.get("evtx_given") and not any(c["role"] == "rdp" for c in coverage.values()):
            R.append(("No RDP operational logs", "TerminalServices RemoteConnectionManager/LocalSessionManager logs were not in the evidence, so RDP source addresses are unknown."))
        na = sum(1 for e in events if e["kind"] == "audit_changed")
        if na:
            R.append(("Audit policy was changed", f"{na} audit-policy changes (EID 4719 / Hayabusa) were recorded; some activity may never have been logged."))
        cl = [e for e in events if e["kind"] == "log_cleared"]
        if cl:
            R.append(("Event logs were cleared", f"{len(cl)} log-clear events; first at {epr_fmt(min(e['ts'] for e in cl))}. Earlier history is destroyed."))
        nohash = sum(1 for d in detections if d["kind"] == "detection" and not d["hash"])
        nodet = sum(1 for d in detections if d["kind"] == "detection")
        if nodet and nohash == nodet:
            R.append(("EDR records carry no file hash or parent chain", f"All {nodet} detection records have an empty hash, so the EDR cloud trajectory (download origin, parent chain) cannot be looked up from this export."))
        dirs = " ".join(ctx.get("evidence_dirs", [])).lower()
        miss = [n for n, k in (("IIS/HTTP logs", ("inetpub", "iis", "httplog")), ("firewall/VPN logs", ("firewall", "vpn", "pfsense", "proxy")),
                               ("application (Veeam/SQL) logs", ("veeam", "sql")), ("file-system execution artifacts (Amcache/ShimCache/Prefetch/MFT)", ("prefetch", "amcache", "mft", "artifacts"))) if not any(x in dirs for x in k)]
        if miss and ctx.get("evidence_dirs"):
            R.append(("Delivery-vector sources not in the evidence", "Not found in the evidence folder: " + ", ".join(miss) + "."))
        col = ctx.get("collection")
        if col and ctx.get("memory_dir"):
            R.append(("Memory image is long after the intrusion", f"Memory was captured {(col - T).days} days after the first artifact ({epr_fmt(T)}); volatile evidence of those processes is gone."))
    return res


# --------------------------------------------------------------------------- findings triage
epr_TRIAGE = {
    "EDR_DETECTION": ("CONFIRMED", "Vendor-confirmed malicious detections."),
    "EDR_TAMPER": ("REVIEW", "Defender EID 1013 can also be written by Defender's own scheduled purge; verify the initiator."),
    "CISCO_EVTX": ("DUPLICATE", "Generic EDR events; EID 1013 rows duplicate EDR_TAMPER."),
    "EDR_ROUTINE": ("NOISE", "Routine EDR/Defender telemetry counts."),
    "EVTX_EID4625": ("REVIEW", "Failed logons; see source-IP analysis in this report."),
    "EVTX_EID4648": ("REVIEW", "Explicit credential use."), "EVTX_EID4776": ("REVIEW", "NTLM authentication."),
    "EVTX_EID4720": ("PIVOT", "Account creation - persistence candidate."), "EVTX_EID4732": ("PIVOT", "Privileged group change."),
    "EVTX_EID7045": ("PIVOT", "New service - persistence candidate."), "EVTX_EID4104": ("REVIEW", "PowerShell script blocks; review content."),
    "EVTX_PATTERN": ("REVIEW", "Loose regex match (e.g. 4907 'Backup Destroy'); likely false positive."),
    "HAYABUSA": ("PIVOT", "HIGH rules are pivots; LOW rules are informational."),
    "REGISTRY_IP": ("NOISE", "Dotted version strings in the registry read as IPs."),
    "THREAT_INTEL": ("NOISE", "Reputation hits on version-like strings."),
    "REGISTRY_URL": ("REVIEW", "URL text not exported."), "REGISTRY_MALICIOUS": ("REVIEW", "Broad regexes (wscript/webclient); value data not exported."),
    "REGISTRY_PERSIST": ("NOISE", "Empty/mis-hive persistence keys."), "MEMORY_SVC": ("NOISE", "Defender platform services under ProgramData."),
    "MEMORY_DLL": ("NOISE", "Vendor .NET assemblies."), "MEMORY_HANDLE_TEMP": ("NOISE", "Normal temp-file handles."),
    "MEMORY_HIDDEN": ("REVIEW", "psxview rows; mostly exited processes - ExitTime not exported."), "MEMORY_REG": ("NOISE", "Run keys with no data."),
    "NET_OUTBOUND": ("NOISE", "Check owner of destination IP; Defender cloud traffic is normal."),
}


def epr_triage_table(results):
    rows = Counter(); sevs = defaultdict(Counter)
    for lst in ("critical", "high", "medium"):
        for it in results.get(lst, []):
            rows[it.get("source", "?")] += 1
            sevs[it.get("source", "?")][it.get("severity", "")] += 1
    out = []
    for s, n in sorted(rows.items(), key=lambda x: -x[1]):
        v, note = epr_TRIAGE.get(s, ("REVIEW", "No automatic triage rule."))
        out.append((s, n, "/".join(f"{k[0]}{c}" for k, c in sevs[s].items()), v, note))
    return out


def epr_event_time_of(item):
    d = item.get("data") or {}
    for k in ("timestamp", "ts", "SystemTime", "TimeCreated", "event_time"):
        t = epr_parse_ts(d.get(k)) if isinstance(d, dict) else None
        if t:
            return t
    return None


def epr_write_detailed_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "source", "desc", "file", "analysis_time", "event_time_utc", "details"])
        for lst in ("critical", "high", "medium"):
            for it in results.get(lst, []):
                et = epr_event_time_of(it)
                det = json.dumps(it.get("data", {}), default=str)[:600]
                w.writerow([it.get("severity", ""), it.get("source", ""), it.get("desc", ""), it.get("file", ""),
                            it.get("timestamp", ""), epr_fmt(et) if et else "", det])



# --------------------------------------------------------------------------- analyst narrative (optional)
# Supports a LOCAL model via Ollama (default, no API key / no internet needed) and, as a fallback,
# the Anthropic API if an ANTHROPIC_API_KEY / --engine-key is supplied. Either one failing never breaks the report.
epr_AI_SYSTEM = ("You are a senior DFIR analyst writing one section of a forensic report. Use ONLY the facts in the JSON the user sends. "
             "Never invent hosts, IPs, files, times or tools. Label each statement FACT (directly in the JSON) or INFERENCE (your reasoning). "
             "If the entry point is not determined, say so and do not guess a vector as fact. Output plain text, no markdown, max 260 words, in this order: "
             "ASSESSMENT (3-4 sentences); ATTACK STORY (only what the data supports); NEXT ACTIONS (5 numbered items, most valuable first).")

epr_OLLAMA_HOST_DEFAULT = "http://127.0.0.1:11434"
epr_OLLAMA_MODEL_DEFAULT = "llama3.1"


def epr__ollama_probe(host, timeout=3):
    import urllib.request
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def epr_ollama_find_host(host, log, timeout=3):
    if epr__ollama_probe(host, timeout):
        return host
    if "localhost" in host:
        alt = host.replace("localhost", "127.0.0.1")
        if epr__ollama_probe(alt, timeout):
            log("INFO", f"'{host}' was not reachable but '{alt}' is (localhost resolved to IPv6 while "
                        f"Ollama listens on IPv4) - using {alt}")
            return alt
    log("INFO", f"Ollama not reachable at {host} - start it with 'ollama serve' and 'ollama pull {epr_OLLAMA_MODEL_DEFAULT}' to enable local analyst review")
    return None


def epr_ollama_available(host, log, timeout=3):
    """True if an Ollama server is reachable at host or its localhost/127.0.0.1 counterpart."""
    return epr_ollama_find_host(host, log, timeout) is not None


epr_OLLAMA_TIMEOUT_DEFAULT = int(os.environ.get("OLLAMA_TIMEOUT", "600"))  # local/CPU inference + first-call
                                                                        # model-load time can both be slow


def epr_ai_summary_ollama(payload, host, model, log, system=None, timeout=None):
    import urllib.request
    try:
        body = json.dumps({"model": model, "stream": False,
                           "messages": [{"role": "system", "content": system or epr_AI_SYSTEM},
                                        {"role": "user", "content": payload if isinstance(payload, str) else json.dumps(payload)[:60000]}]}).encode()
        req = urllib.request.Request(f"{host.rstrip('/')}/api/chat", data=body, method="POST", headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout or epr_OLLAMA_TIMEOUT_DEFAULT) as r:
            data = json.load(r)
        txt = (data.get("message") or {}).get("content", "").strip()
        return txt or None
    except TimeoutError:
        log("WARN", f"Ollama timed out after {timeout or epr_OLLAMA_TIMEOUT_DEFAULT}s on this request (model '{model}' may still be "
                    f"loading, or your CPU/RAM is slow for its size) - set OLLAMA_TIMEOUT to wait longer, or use a smaller model")
        return None
    except Exception as ex:
        log("WARN", f"Ollama generation failed ({type(ex).__name__}: {str(ex)[:120]}) - is the model pulled? 'ollama pull {model}'")
        return None


def epr_build_ai_payload(meta, ep, detections, events, coverage, results):
    ser = lambda o: o.strftime(epr_FMT) if isinstance(o, datetime) else o
    kinds = Counter(e["kind"] for e in events)
    fails = Counter()
    for e in events:
        if e["kind"] == "logon_fail":
            m = re.search(r"from\s+(\S+)", e["text"]); fails[m.group(1) if m else "-"] += 1
    return json.loads(json.dumps({
        "host": meta["host"], "collection_time": meta.get("collection_txt"),
        "entry_point": {"status": ep["status"], "confidence": ep["confidence"], "vector": ep["vector"], "anchor": ep.get("anchor"),
                        "anchor_class": ep.get("anchor_class"), "access_event": ep.get("access_event"),
                        "evidence": [(ser(t), x) for t, x in ep["evidence"]], "reasons": ep["reasons"], "candidates": ep["candidates"]},
        "edr_records": [{k: d[k] for k in ("kind", "name", "path", "process", "hash", "action", "user", "count", "first", "last")} for d in detections][:25],
        "event_counts": dict(kinds), "top_failed_logon_sources": fails.most_common(5),
        "coverage": {n: {"role": c["role"], "oldest": c["first"], "newest": c["last"], "records": c["records"]} for n, c in coverage.items()},
        "tool_findings_by_source": {s: n for s, n, _, _, _ in epr_triage_table(results)},
    }, default=ser))


def epr_ai_summary_anthropic(payload, key, model, log, system=None, max_tokens=1200):
    """Call the Anthropic Messages API (stdlib only). Returns text or None; never raises."""
    import urllib.request
    try:
        body = json.dumps({"model": model, "max_tokens": max_tokens, "system": system or epr_AI_SYSTEM,
                           "messages": [{"role": "user", "content": payload if isinstance(payload, str) else json.dumps(payload)[:60000]}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
                                     headers={"content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.load(r)
        txt = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()
        return txt or None
    except Exception as ex:
        log("WARN", f"Anthropic analyst review failed ({type(ex).__name__}: {str(ex)[:120]})")
        return None


def epr__dig_text(data, min_len=20):
    """Best-effort text extractor for API responses whose exact shape may vary / change over time."""
    best = None
    def walk(x):
        nonlocal best
        if isinstance(x, str):
            if len(x) >= min_len and (best is None or len(x) > len(best)):
                best = x
        elif isinstance(x, dict):
            for k in ("text", "content", "message", "output_text"):
                if k in x:
                    walk(x[k])
            for k, v in x.items():
                if k not in ("text", "content", "message", "output_text"):
                    walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)
    walk(data)
    return best


def epr_ai_summary_gemini(payload, key, model, log, system=None):
    """Call the Google Gemini generateContent API (stdlib only). Returns text or None; never raises."""
    import urllib.request
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        body = json.dumps({"system_instruction": {"parts": [{"text": system or epr_AI_SYSTEM}]},
                           "contents": [{"role": "user", "parts": [{"text": payload if isinstance(payload, str) else json.dumps(payload)[:60000]}]}]}).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.load(r)
        try:
            txt = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError, TypeError):
            txt = epr__dig_text(data)
        return txt or None
    except Exception as ex:
        log("WARN", f"Gemini analyst review failed ({type(ex).__name__}: {str(ex)[:120]})")
        return None


def epr_ai_summary_meta(payload, key, model, log, host="https://api.llama.com", system=None):
    """Call Meta's Llama API (OpenAI-compatible chat completions, stdlib only). Returns text or None; never raises."""
    import urllib.request
    try:
        body = json.dumps({"model": model, "messages": [{"role": "system", "content": system or epr_AI_SYSTEM},
                                                          {"role": "user", "content": payload if isinstance(payload, str) else json.dumps(payload)[:60000]}]}).encode()
        req = urllib.request.Request(f"{host.rstrip('/')}/v1/chat/completions", data=body, method="POST",
                                     headers={"content-type": "application/json", "authorization": f"Bearer {key}"})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.load(r)
        txt = None
        try:
            txt = data["completion_message"]["content"]["text"].strip()  # Meta's native shape
        except (KeyError, TypeError):
            pass
        if not txt:
            try:
                txt = data["choices"][0]["message"]["content"].strip()  # OpenAI-compatible shape
            except (KeyError, IndexError, TypeError):
                pass
        if not txt:
            txt = epr__dig_text(data)
        return txt or None
    except Exception as ex:
        log("WARN", f"Meta/Llama analyst review failed ({type(ex).__name__}: {str(ex)[:120]})")
        return None

epr_AI_DEFAULT_MODELS = {"ollama": epr_OLLAMA_MODEL_DEFAULT, "anthropic": "claude-sonnet-5-5",
                     "gemini": "gemini-2.5-flash", "meta": "Llama-4-Scout-17B-16E-Instruct-FP8"}
epr_AI_LABELS = {"ollama": "local Ollama", "anthropic": "Anthropic Claude", "gemini": "Google Gemini", "meta": "Meta Llama API"}


def epr_resolve_ai_cfg(log, provider="auto", ollama_host=None, ollama_model=None,
                   anthropic_key=None, anthropic_model=None, gemini_key=None, gemini_model=None,
                   meta_key=None, meta_model=None, meta_host=None, probe=True):
    oh, om = ollama_host or epr_OLLAMA_HOST_DEFAULT, ollama_model or epr_OLLAMA_MODEL_DEFAULT
    am = anthropic_model or epr_AI_DEFAULT_MODELS["anthropic"]
    gm = gemini_model or epr_AI_DEFAULT_MODELS["gemini"]
    mm = meta_model or epr_AI_DEFAULT_MODELS["meta"]
    mh = meta_host or "https://api.llama.com"
    resolved = {}  # ollama's actual working host, filled in by its ready-check below

    def ollama_ready():
        h = epr_ollama_find_host(oh, log) if probe else oh
        if h:
            resolved["host"] = h
            return True
        return False

    defs = {
        "ollama": {"ready": ollama_ready, "model": om, "extra": lambda: f"@ {resolved.get('host', oh)}",
                  "cfg": lambda: {"provider": "ollama", "host": resolved.get("host", oh), "model": om}},
        "anthropic": {"ready": lambda: bool(anthropic_key), "model": am, "extra": lambda: "",
                     "cfg": lambda: {"provider": "anthropic", "key": anthropic_key, "model": am}},
        "gemini": {"ready": lambda: bool(gemini_key), "model": gm, "extra": lambda: "",
                  "cfg": lambda: {"provider": "gemini", "key": gemini_key, "model": gm}},
        "meta": {"ready": lambda: bool(meta_key), "model": mm, "extra": lambda: f"@ {mh}",
                "cfg": lambda: {"provider": "meta", "key": meta_key, "model": mm, "host": mh}},
    }
    order = ["ollama", "anthropic", "gemini", "meta"] if provider == "auto" else [provider]
    for prov in order:
        if prov not in defs:
            continue
        d = defs[prov]
        if not d["ready"]():
            if provider != "auto":
                log("INFO", f"{epr_AI_LABELS.get(prov, prov)} not configured/reachable")
            continue
        log("INFO", f"Using {epr_AI_LABELS.get(prov, prov)} ({d['model']} {d['extra']()})".strip())
        return d["cfg"]()
    return None


def epr_ai_call(cfg, system, user_payload, log, max_tokens=None):
    """Make one analyst-engine call using an already-resolved cfg. Returns text or None."""
    if not cfg:
        return None
    p = cfg["provider"]
    if p == "ollama":
        return epr_ai_summary_ollama(user_payload, cfg["host"], cfg["model"], log, system=system)
    if p == "anthropic":
        return epr_ai_summary_anthropic(user_payload, cfg["key"], cfg["model"], log, system=system, max_tokens=max_tokens or 1200)
    if p == "gemini":
        return epr_ai_summary_gemini(user_payload, cfg["key"], cfg["model"], log, system=system)
    if p == "meta":
        return epr_ai_summary_meta(user_payload, cfg["key"], cfg["model"], log, host=cfg.get("host", "https://api.llama.com"), system=system)
    return None


def epr_ai_summary(payload, log, provider="auto", ollama_host=None, ollama_model=None,
               anthropic_key=None, anthropic_model=None, gemini_key=None, gemini_model=None,
               meta_key=None, meta_model=None, meta_host=None):
    """Backward-compatible one-shot helper: resolve a provider and make a single call with AI_SYSTEM."""
    cfg = epr_resolve_ai_cfg(log, provider, ollama_host, ollama_model, anthropic_key, anthropic_model,
                         gemini_key, gemini_model, meta_key, meta_model, meta_host)
    if not cfg:
        return None, None, ""
    txt = epr_ai_call(cfg, epr_AI_SYSTEM, payload, log)
    return (txt, cfg["provider"], cfg["model"]) if txt else (None, None, "")


# --------------------------------------------------------------------------- interactive engine setup
def epr__ollama_binary_present():
    import shutil as _sh
    return _sh.which("ollama") is not None


def epr_ensure_ollama_ready(model, log, auto_yes=False, host=None):
    import subprocess, shutil as _sh
    host = host or epr_OLLAMA_HOST_DEFAULT
    try:
        log("INFO", "Step 1/3 — Checking Ollama binary ...")
        if not epr__ollama_binary_present():
            log("WARN", "Ollama binary not found (checked PATH + common locations)")
            log("INFO", "  Download page: https://ollama.com/download")
            go = auto_yes
            if sys.stdin.isatty() and not auto_yes:
                go = input("  Install Ollama now? (requires internet access) [y/N]: ").strip().lower() == "y"
            if not go:
                log("INFO", "Skipping Ollama install - choose a different provider or install manually: https://ollama.com/download")
                return False
            log("INFO", "Installing Ollama (curl -fsSL https://ollama.com/install.sh | sh) ...")
            try:
                r = subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, timeout=600,
                                   capture_output=True, text=True)
                if r.returncode != 0 or not epr__ollama_binary_present():
                    log("WARN", f"Ollama install did not complete (exit {r.returncode}). {r.stderr[-300:] if r.stderr else ''}")
                    return False
                log("OK", "Ollama installed.")
            except Exception as ex:
                log("WARN", f"Ollama install failed: {ex}")
                return False
        # Step 1 passed
        bin_path = shutil.which("ollama") or "ollama"
        log("OK", f"Step 1/3 — Ollama binary: {bin_path}")

        # Step 2: server reachability
        log("INFO", f"Step 2/3 — Checking Ollama server at {host} ...")
        working_host = epr_ollama_find_host(host, log)
        if not working_host:
            log("INFO", "Server not responding — starting Ollama server (ollama serve) ...")
            try:
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                import time as _t
                for i in range(10):
                    _t.sleep(1)
                    working_host = epr_ollama_find_host(host, log)
                    if working_host:
                        break
                    log("INFO", f"  Waiting for server ... ({i+1}/10)")
            except Exception as ex:
                log("WARN", f"Could not start Ollama server automatically: {ex}. Run 'ollama serve' manually.")
                return False
            if not working_host:
                log("WARN", "Ollama server did not come up after 'ollama serve'. Run it manually and check for errors.")
                return False
        log("OK", f"Ollama server running at {working_host}")

        # Step 3: model availability
        log("INFO", f"Step 3/3 — Checking model '{model}' ...")
        try:
            r = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=30)
            have = model in (r.stdout or "")
            if have:
                # show which models are available for context
                model_lines = [l.split()[0] for l in (r.stdout or "").splitlines() if l and not l.startswith("NAME")]
                log("OK", f"Model '{model}' is available  (all pulled models: {', '.join(model_lines[:6]) or 'none'})")
        except Exception:
            have = False
        if not have:
            log("WARN", f"Model '{model}' is not pulled yet.")
            try:
                r2 = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=30)
                available = [l.split()[0] for l in (r2.stdout or "").splitlines() if l and not l.startswith("NAME")]
                if available:
                    log("INFO", f"  Models you already have: {', '.join(available)}")
                    log("INFO", f"  Tip: use --ollama-model {available[0]} to use an existing model instead of pulling '{model}'")
            except Exception:
                pass
            go = auto_yes
            if sys.stdin.isatty() and not auto_yes:
                go = input(f"  Run 'ollama pull {model}' now? (several GB download) [y/N]: ").strip().lower() == "y"
            if not go:
                log("INFO", f"Skipping pull — run 'ollama pull {model}' manually, or pick a smaller model with --ollama-model")
                return False
            log("INFO", f"Pulling {model} (this can take a while — model size is typically 4-8 GB) ...")
            try:
                r = subprocess.run(["ollama", "pull", model], timeout=3600)
                if r.returncode != 0:
                    log("WARN", f"'ollama pull {model}' failed (exit {r.returncode}).")
                    return False
                log("OK", f"Model '{model}' pulled and ready.")
            except Exception as ex:
                log("WARN", f"'ollama pull {model}' failed: {ex}")
                return False
        return working_host
    except Exception as ex:
        log("WARN", f"Ollama setup check failed: {ex}")
        return False


def epr_ensure_api_key(label, env_names, log):
    """Checks env vars for an API key; if missing and interactive, prompts for one (session-only, not saved to disk)."""
    for n in env_names:
        if os.environ.get(n):
            return os.environ[n]
    if sys.stdin.isatty():
        try:
            import getpass
            key = getpass.getpass(f"  Enter {label} API key (input hidden, not saved to disk, blank to skip): ").strip()
        except Exception:
            key = input(f"  Enter {label} API key (blank to skip): ").strip()
        if key:
            os.environ[env_names[0]] = key
            return key
    else:
        log("INFO", f"{label} API key not set (env {'/'.join(env_names)}) and not running interactively - skipping")
    return None


epr_AI_MENU = [("1", "ollama", "Ollama - local model, free, private, needs install (~4-8 GB)"),
           ("2", "anthropic", "Claude (Anthropic API) - needs ANTHROPIC_API_KEY"),
           ("3", "gemini", "Gemini (Google API) - needs GEMINI_API_KEY"),
           ("4", "meta", "Meta Llama API - needs META_API_KEY"),
           ("5", "skip", "None - rule-based report only")]


def epr_interactive_ai_setup(log, ollama_model=None, anthropic_model=None, gemini_model=None, meta_model=None,
                         ollama_host=None, meta_host=None):
    if not sys.stdin.isatty():
        return None
    print("\n  Choose an analyst engine for the full artifact analysis:")
    for num, _, desc in epr_AI_MENU:
        print(f"    [{num}] {desc}")
    choice = input("  Choice [1-5, Enter = auto-detect]: ").strip()
    prov = next((p for n, p, _ in epr_AI_MENU if n == choice), None)
    if choice == "" or prov is None:
        return None  # caller falls back to auto-detect over flags/env
    if prov == "skip":
        return "skip"
    om = ollama_model or epr_OLLAMA_MODEL_DEFAULT
    if prov == "ollama":
        working_host = epr_ensure_ollama_ready(om, log, host=ollama_host)
        if not working_host:
            print("  Ollama is not ready - pick another option.")
            return epr_interactive_ai_setup(log, ollama_model, anthropic_model, gemini_model, meta_model, ollama_host, meta_host)
        return {"provider": "ollama", "host": working_host, "model": om}
    if prov == "anthropic":
        key = epr_ensure_api_key("Claude", ["ANTHROPIC_API_KEY"], log)
        if not key:
            print("  No key given - pick another option.")
            return epr_interactive_ai_setup(log, ollama_model, anthropic_model, gemini_model, meta_model, ollama_host, meta_host)
        return {"provider": "anthropic", "key": key, "model": anthropic_model or epr_AI_DEFAULT_MODELS["anthropic"]}
    if prov == "gemini":
        key = epr_ensure_api_key("Gemini", ["GEMINI_API_KEY", "GOOGLE_API_KEY"], log)
        if not key:
            print("  No key given - pick another option.")
            return epr_interactive_ai_setup(log, ollama_model, anthropic_model, gemini_model, meta_model, ollama_host, meta_host)
        return {"provider": "gemini", "key": key, "model": gemini_model or epr_AI_DEFAULT_MODELS["gemini"]}
    if prov == "meta":
        key = epr_ensure_api_key("Meta Llama API", ["META_API_KEY", "LLAMA_API_KEY"], log)
        if not key:
            print("  No key given - pick another option.")
            return epr_interactive_ai_setup(log, ollama_model, anthropic_model, gemini_model, meta_model, ollama_host, meta_host)
        return {"provider": "meta", "key": key, "model": meta_model or epr_AI_DEFAULT_MODELS["meta"], "host": meta_host or "https://api.llama.com"}
    return None


# --------------------------------------------------------------------------- full-artifact analyst review (map-reduce)
epr_CHUNK_SYSTEM = ("You are a DFIR analyst reviewing a batch of raw tool findings from one host (a JSON list; fields: "
                "severity, source, desc, file). Identify anything that indicates compromise, persistence, credential "
                "access, lateral movement or defence evasion. Ignore routine/benign entries. Reply with PLAIN bullet "
                "lines only, each starting with '- ', max 8 bullets, each under 25 words, citing the source and a "
                "concrete detail (file/desc). If nothing of interest is in this batch, reply with exactly: - nothing notable")

epr_SYNTH_SYSTEM = ("You are a senior DFIR analyst writing the main narrative of a forensic report. You already reviewed "
                "ALL the findings collected by the tool in batches; the bullet points from every batch are given to "
                "you, together with a rule-based entry-point determination and telemetry coverage. Use ONLY these "
                "facts - never invent hosts, IPs, files or times. Label inferences as INFERENCE. Output plain text, "
                "no markdown, about 400-500 words, in this order: ENTRY POINT CONCLUSION (agree or disagree with the "
                "rule-based verdict, and why); ATTACK NARRATIVE (what happened, in time order, across everything "
                "reviewed); FINDINGS REVIEW (what mattered vs what was noise, with rough counts); NEXT ACTIONS "
                "(6 numbered items, most valuable first).")


def epr_chunk_all_findings(results, chunk_size=60, max_items=4000):
    """Flatten + prioritise (CRITICAL>HIGH>MEDIUM) all findings, cap at max_items, chunk for map-reduce."""
    items = []
    for sev in ("critical", "high", "medium"):
        for it in results.get(sev, []):
            items.append({"severity": it.get("severity", sev.upper()), "source": it.get("source", ""),
                          "desc": (it.get("desc", "") or "")[:220], "file": (it.get("file", "") or "").split("/")[-1]})
    total = len(items)
    reviewed = items[:max_items]
    overflow = Counter(it["source"] for it in items[max_items:])
    chunks = [reviewed[i:i + chunk_size] for i in range(0, len(reviewed), chunk_size)]
    return chunks, total, len(reviewed), overflow


def epr_full_artifact_ai_analysis(cfg, meta, ep, detections, events, coverage, results, log, max_chunks=25):
    if not cfg:
        return None, {}
    chunk_size = 30 if cfg.get("provider") == "ollama" else 60  # smaller batches = faster local CPU inference
    chunks, total, reviewed_n, overflow = epr_chunk_all_findings(results, chunk_size=chunk_size)
    cap = max_chunks * chunk_size
    if len(chunks) > max_chunks:
        log("INFO", f"{total:,} findings to review - capping batch review at {cap:,} "
                    f"({max_chunks} batches) for time; the rest are covered by source/count in Section 6")
        chunks = chunks[:max_chunks]
    log("INFO", f"Analyst reviewing {min(reviewed_n, cap):,} of {total:,} findings in {len(chunks)} batches of {chunk_size} ...")
    notes = []
    for i, ch in enumerate(chunks, 1):
        txt = epr_ai_call(cfg, epr_CHUNK_SYSTEM, json.dumps(ch), log)
        if txt and "nothing notable" not in txt.lower():
            notes.append(f"[batch {i}/{len(chunks)}]\n{txt.strip()}")
        if i % 10 == 0 or i == len(chunks):
            log("INFO", f"  ... {i}/{len(chunks)} batches reviewed")
    ser = lambda o: o.strftime(epr_FMT) if isinstance(o, datetime) else o
    synth_payload = {
        "host": meta["host"],
        "entry_point": json.loads(json.dumps({"status": ep["status"], "confidence": ep["confidence"], "vector": ep["vector"],
                                              "anchor": ep.get("anchor"), "access_event": ep.get("access_event"),
                                              "reasons": ep["reasons"]}, default=ser)),
        "edr_detections": [{k: d[k] for k in ("name", "path", "process", "count", "first", "last")} for d in detections][:30],
        "coverage": {n: {"role": c["role"], "oldest": c["first"], "newest": c["last"]} for n, c in coverage.items()},
        "findings_total": total, "findings_ai_reviewed": min(reviewed_n, cap),
        "findings_overflow_by_source": dict(overflow.most_common(10)),
        "ai_batch_notes": notes if notes else ["No notable items surfaced in any reviewed batch."],
    }
    log("INFO", "Synthesising final analyst narrative from all batch notes ...")
    final = epr_ai_call(cfg, epr_SYNTH_SYSTEM, json.dumps(json.loads(json.dumps(synth_payload, default=ser)))[:90000], log)
    stats = {"total": total, "reviewed": min(reviewed_n, cap), "batches": len(chunks), "notable_batches": len(notes)}
    return final, stats

# --------------------------------------------------------------------------- PDF
def epr_make_chart(events, detections, ep, coverage, collection, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
    except ImportError:
        return None
    pts = [e["ts"] for e in events] + [d["first"] for d in detections if d["first"]] + [d["last"] for d in detections if d["last"]]
    if not pts:
        return None
    lo, hi = min(pts) - timedelta(days=7), max(pts + ([collection] if collection else [])) + timedelta(days=7)
    lanes = [("EDR / AV detections", "edr"), ("Remote logons (OK)", "ok"), ("Failed logons", "fail"),
             ("Account / group / service / task", "chg"), ("Defender tamper / audit / log clear", "tamper")]
    y = {k: len(lanes) - i for i, (_, k) in enumerate(lanes)}
    fig, ax = plt.subplots(figsize=(7.4, 3.4), dpi=200)
    lane_of = lambda e: ("ok" if e["kind"] in ("logon_ok", "rdp_auth") else "fail" if e["kind"] == "logon_fail" else
                         "chg" if e["kind"] in ("acct_created", "group_add", "svc_install", "task_created", "pwd_reset") else
                         "tamper" if e["kind"] in ("av_history_deleted", "av_config", "audit_changed", "log_cleared") else
                         "edr" if e["kind"] in ("av_detect", "edr_detect") else None)
    cols = {"edr": "#c0392b", "ok": "#1e8449", "fail": "#7f8c8d", "chg": "#8e44ad", "tamper": "#e67e22"}
    for k in cols:
        xs = [e["ts"] for e in events if lane_of(e) == k]
        if k == "edr":
            xs += [d["first"] for d in detections if d["kind"] == "detection" and d["first"]]
        if xs:
            ax.scatter(xs[:4000], [y[k]] * len(xs[:4000]), s=14 if k != "edr" else 40, color=cols[k], alpha=.7 if k == "fail" else .95, zorder=3)
    for d in detections:
        if d["kind"] == "tamper" and d["first"]:
            ax.plot([d["first"], d["last"]], [y["tamper"]] * 2, color=cols["tamper"], lw=5, alpha=.6, solid_capstyle="butt")
    sec = [c for c in coverage.values() if c["role"] == "security" and c["first"]]
    if sec and sec[0]["first"] > lo:
        ax.axvspan(lo, sec[0]["first"], color="#fdecea", zorder=0)
        ax.text(lo + (sec[0]["first"] - lo) / 2, 0.45, "no Security log\ncoverage", fontsize=5.5, color="#c0392b", ha="center")
    if ep.get("anchor"):
        a = ep["anchor"]["time"]
        ax.axvline(a, color="#c0392b", ls="--", lw=1)
        ax.text(a, len(lanes) + 0.55, " first malicious artifact\n " + epr_fmt(a), fontsize=5.8, color="#c0392b", va="top")
    if collection:
        ax.axvline(collection, color="#16213e", ls=":", lw=1)
        ax.text(collection, 0.45, "evidence collected ", fontsize=5.5, color="#16213e", ha="right")
    ax.set_yticks([y[k] for _, k in lanes]); ax.set_yticklabels([n for n, _ in lanes], fontsize=6)
    ax.set_ylim(0.2, len(lanes) + 0.7); ax.set_xlim(lo, hi)
    span = (hi - lo).days
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, span // 8)) if span < 60 else mdates.MonthLocator(interval=max(1, span // 300 + 1)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d" if span < 60 else "%b %y"))
    plt.setp(ax.get_xticklabels(), fontsize=6); ax.grid(axis="x", alpha=.25)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    plt.tight_layout(); plt.savefig(path); plt.close()
    return path


def epr_build_pdf(path, meta, ep, detections, events, coverage, results, chart, ai_text=None, ai_label="", ai_stats=None, agents=None, telemetry_gaps=None, cor=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
                                    CondPageBreak, Image, Preformatted)

    NAVY = colors.HexColor("#16213e"); RED = colors.HexColor("#c0392b"); MID = colors.HexColor("#d5d9e0"); LG = colors.HexColor("#f2f4f7")
    base = ParagraphStyle("b", fontName="Helvetica", fontSize=9, leading=12.6, textColor=colors.HexColor("#222"))
    sm = ParagraphStyle("sm", parent=base, fontSize=7.8, leading=10.2)
    cw = ParagraphStyle("cw", parent=sm, textColor=colors.white, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=NAVY, spaceBefore=10, spaceAfter=5)
    h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=NAVY, spaceBefore=8, spaceAfter=3)
    ttl = ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=colors.white)
    sub = ParagraphStyle("s", parent=base, fontSize=10, leading=14, textColor=colors.HexColor("#cfd6e4"))
    code = ParagraphStyle("c", fontName="Courier", fontSize=7.2, leading=9.2)
    bl = ParagraphStyle("bl", parent=base, leftIndent=10, firstLineIndent=-8, spaceAfter=2.5)
    P = lambda t, s=base: Paragraph(t, s)
    W = A4[0] - 30 * mm

    def tbl(data, widths, fs=sm):
        rows = [[Paragraph(c, cw if i == 0 else fs) if isinstance(c, str) else c for c in r] for i, r in enumerate(data)]
        t = Table(rows, colWidths=widths, repeatRows=1)
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), .4, MID), ("BACKGROUND", (0, 0), (-1, 0), NAVY),
              ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        st += [("BACKGROUND", (0, i), (-1, i), LG) for i in range(2, len(rows), 2)]
        t.setStyle(TableStyle(st)); return t

    def box(flow, bg, border):
        t = Table([[flow]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("BOX", (0, 0), (-1, -1), 1, border), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        return t

    tag = lambda t, c: f'<font color="{c}"><b>{t}</b></font>'
    VC = {"CONFIRMED": "#c0392b", "PIVOT": "#1a5276", "REVIEW": "#d35400", "NOISE": "#566573", "DUPLICATE": "#566573"}

    def page(c, doc):
        c.saveState(); c.setFillColor(NAVY); c.rect(0, A4[1] - 9 * mm, A4[0], 9 * mm, stroke=0, fill=1)
        c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 7.5)
        c.drawString(15 * mm, A4[1] - 6 * mm, f"FORENSIC ANALYSIS REPORT  |  {meta['host']}"); c.drawRightString(A4[0] - 15 * mm, A4[1] - 6 * mm, "CONFIDENTIAL")
        c.setFillColor(colors.HexColor("#666")); c.setFont("Helvetica", 7.5)
        c.drawString(15 * mm, 8 * mm, f"Auto-generated by Unified_Forensics.py on {meta['generated']}  |  all times UTC unless stated")
        c.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}"); c.restoreState()

    doc = BaseDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=17 * mm, bottomMargin=15 * mm,
                          title=f"Forensic Analysis Report - {meta['host']}")
    doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(doc.leftMargin, doc.bottomMargin, W, A4[1] - 32 * mm, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=page)])
    S = []
    cov = Table([[P("Forensic Analysis Report", ttl)], [P(f"Host: {epr_esc(meta['host'])}<br/>Compromise assessment, entry-point determination and telemetry review", sub)]], colWidths=[W])
    cov.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (0, 0), 14), ("BOTTOMPADDING", (0, -1), (-1, -1), 14)]))
    S += [cov, Spacer(1, 8)]
    S.append(tbl([["Item", "Detail"], ["Report generated", epr_esc(meta["generated"])], ["Evidence", epr_esc(meta["evidence"])],
                  ["Evidence collection time", epr_esc(meta["collection_txt"])], ["Inputs", epr_esc(meta["inputs"])]], [38 * mm, W - 38 * mm]))

    # 1 executive summary
    A = ep.get("anchor"); det_ok = [d for d in detections if d["kind"] == "detection"]
    S.append(P("1. Executive Summary", h1))
    status = ep["status"]
    colr = "#c0392b" if status == "NOT DETERMINED" else "#d35400"
    lines = [P(tag(f"ENTRY POINT: {epr_esc(status)}", colr), ParagraphStyle("x", parent=base, fontSize=10.5, leading=14)), Spacer(1, 3)]
    if A:
        lines.append(P(f"<b>Earliest malicious artifact:</b> <b>{epr_fmt(A['time'])}</b> - {epr_esc(A['source'])}: <b>{epr_esc(A['name'])}</b>"
                       + (f" on <b>{epr_esc(A['path'])}</b>" if A["path"] else "") + (f", process <b>{epr_esc(A['process'])}</b>" if A["process"] else "")
                       + (f", user {epr_esc(A['user'])}" if A["user"] else "") + f". Source: {epr_esc(A['log'])}."))
    else:
        lines.append(P("No malicious artifact with a timestamp was found; there is no reference point for an entry-point search."))
    lines.append(Spacer(1, 3))
    if ep["access_event"]:
        ae = ep["access_event"]
        lines.append(P(f"<b>Probable access event:</b> {epr_fmt(ae['time'])} - {epr_esc(ae['text'])} (log: {epr_esc(ae['log'])}). <b>Vector:</b> {epr_esc(ep['vector'])}. "
                       f"<b>Confidence:</b> {epr_esc(ep['confidence'])} (correlation-based, not proof)."))
    else:
        lines.append(P("<b>Initial access vector could not be determined from the supplied telemetry.</b> "
                       + ("The first artifact is " + ep["anchor_class"] + " activity, so the intrusion predates it. " if ep.get("anchor_class") == "post-exploitation" else "")
                       + "The reasons are listed in Section 2.2."))
    S.append(box(lines, colors.HexColor("#fdf2f0"), RED)); S.append(Spacer(1, 6))
    S.append(P("Key facts", h2))
    facts = [f"{len(det_ok)} distinct EDR/AV detection record(s), {sum(d['count'] for d in det_ok)} event(s)."]
    if A and meta.get("collection"):
        facts.append(f"First malicious artifact to evidence collection: {(meta['collection'] - A['time']).days} days.")
    tam = [d for d in detections if d["kind"] == "tamper"]
    for d in tam:
        facts.append(f"{epr_esc(d['name'])}: {d['count']} event(s), {epr_fmt(d['first'])} to {epr_fmt(d['last'])}.")
    nf = sum(1 for e in events if e["kind"] == "logon_fail")
    if nf: facts.append(f"{nf} failed logons re-extracted with real times and source IPs (Section 4.3).")
    nfind = sum(len(results.get(k, [])) for k in ("critical", "high", "medium"))
    facts.append(f"{nfind:,} tool findings triaged in Section 6; only EDR detections are vendor-confirmed.")
    for t in facts: S.append(P("&bull; " + t, bl))

    if ai_text:
        S.append(Spacer(1, 4))
        cov_txt = ""
        if ai_stats and ai_stats.get("total"):
            cov_txt = f" Review covered {ai_stats['reviewed']:,} of {ai_stats['total']:,} findings across {ai_stats['batches']} batches ({ai_stats['notable_batches']} flagged something)."
        paras = [P(tag("ANALYST REVIEW - CORRELATION & COMPLETENESS CHECK", "#1a5276") + f" <font size=7 color='#666666'>(cross-check of the data in this report; the rule-based entry-point verdict is shown above - verify before acting.{epr_esc(cov_txt)})</font>", sm), Spacer(1, 3)]
        for ln in [x for x in ai_text.splitlines() if x.strip()]:
            paras.append(P(epr_esc(ln.strip()), sm))
        S.append(box(paras, colors.HexColor("#eef4fb"), colors.HexColor("#1a5276")))
    # 2 entry point
    S.append(CondPageBreak(90 * mm)); S.append(P("2. Entry Point Assessment", h1)); S.append(P("2.1 Result", h2))
    rows = [["Field", "Value"], ["Status", tag(epr_esc(status), colr)], ["Date / time of earliest artifact", epr_fmt(A["time"]) if A else "-"],
            ["Entry artifact", epr_esc((A or {}).get("path") or (A or {}).get("name") or "-")], ["Associated process", epr_esc((A or {}).get("process") or "-")],
            ["Account", epr_esc((A or {}).get("user") or "-")], ["Source log", epr_esc((A or {}).get("log") or "-")]]
    if ep["access_event"]:
        rows += [["Probable access time", epr_fmt(ep["access_event"]["time"])], ["Probable vector", epr_esc(ep["vector"])], ["Confidence", epr_esc(ep["confidence"])]]
    else:
        rows += [["Probable access time / vector", "Not determined"]]
    S.append(tbl(rows, [48 * mm, W - 48 * mm]))
    if ep["evidence"]:
        S.append(P("Supporting evidence", h2))
        for t, x in ep["evidence"]: S.append(P(f"&bull; {epr_fmt(t)} - {epr_esc(x)}", bl))
    S.append(P("2.2 Why the entry point could not be proven" if not ep["access_event"] else "2.2 Limitations and coverage gaps", h2))
    for i, (h, d) in enumerate(ep["reasons"], 1):
        S.append(P(f"<b>{i}. {epr_esc(h)}.</b> {epr_esc(d)}", ParagraphStyle("r", parent=base, leftIndent=12, firstLineIndent=-12, spaceAfter=3.5)))
    S.append(CondPageBreak(60 * mm)); S.append(P("2.3 Candidate vectors (from real telemetry)", h2))
    S.append(tbl([["Vector", "Indicator", "Strength", "How to confirm"]] + [[epr_esc(a), epr_esc(b), epr_esc(c), epr_esc(d)] for a, b, c, d in ep["candidates"]] if ep["candidates"] else [["Vector", "Indicator", "Strength", "How to confirm"], ["-", "-", "-", "-"]],
                 [38 * mm, 55 * mm, 22 * mm, W - 115 * mm]))

    if cor:
        S.append(CondPageBreak(60 * mm)); S.append(P("2.4 Cross-Source Correlation (memory / registry hives / hive logs / event logs)", h2))
        for _t, _hd, _rw in cor_sections(cor):
            S.append(P(epr_esc(_t), h2))
            _n = max(1, len(_hd)); _wd = [(W) / _n] * _n
            S.append(tbl([[epr_esc(x) for x in _hd]] + [[epr_esc(str(c))[:260] for c in r] for r in _rw[:80]], _wd))
            S.append(Spacer(1, 4))

    # 3 timeline
    S.append(CondPageBreak(150 * mm)); S.append(P("3. Attack Timeline (real event times)", h1))
    if chart: S.append(Image(chart, width=W, height=W * 3.4 / 7.4))
    S.append(Spacer(1, 4))
    tl = []
    for d in detections:
        tl.append((d["first"], d["last"], d["name"], d["path"], d["process"], d["count"], "TAMPER?" if d["kind"] == "tamper" else "DETECTION"))
    for e in events:
        if e["kind"] in ("acct_created", "group_add", "svc_install", "task_created", "log_cleared", "audit_changed", "logon_ok", "rdp_auth", "proc_create", "ps_block", "pwd_reset", "dll_block", "cred_access", "smb_discovery", "fw_change"):
            tl.append((e["ts"], e["ts"], epr_KIND_LABEL.get(e["kind"], e["kind"]), e["text"], e["log"], 1, e["kind"].upper()))
    tl = sorted([t for t in tl if t[0]], key=lambda x: x[0])
    if len(tl) > 70:
        tl = tl[:35] + tl[-35:]
    rows = [["First seen", "Last seen", "Event", "Detail", "Cnt", "Type"]]
    for a, b, n, dt_, extra, c, k in tl:
        rows.append([epr_fmt(a), epr_fmt(b) if b != a else "-", epr_esc(n)[:70], epr_esc(f"{dt_} {extra}".strip())[:110], str(c), k])
    S.append(tbl(rows, [29 * mm, 29 * mm, 36 * mm, W - 134 * mm, 9 * mm, 31 * mm], fs=ParagraphStyle("tf", parent=sm, fontSize=6.8, leading=8.6)))

    # 4 telemetry
    S.append(CondPageBreak(80 * mm)); S.append(P("4. Telemetry Detail", h1)); S.append(P("4.1 EDR / AV detection telemetry", h2))
    rows = [["Threat / event", "File path", "Process", "Endpoint / user", "Cnt", "First seen", "Last seen", "Hash", "Action"]]
    for d in detections:
        rows.append([epr_esc(d["name"]), epr_esc(d["path"] or "-"), epr_esc(d["process"] or "-"), epr_esc((d["endpoint"] or "").split(".")[0] + " / " + (d["user"] or "-")),
                     str(d["count"]), epr_fmt(d["first"]).replace(" ", "<br/>"), epr_fmt(d["last"]).replace(" ", "<br/>"), epr_esc(d["hash"][:12] or "none"), epr_esc(d["action"] or "blank")])
    if len(rows) == 1: rows.append(["-"] * 9)
    S.append(tbl(rows, [29 * mm, 31 * mm, 20 * mm, 22 * mm, 8 * mm, 17 * mm, 17 * mm, 10 * mm, W - 154 * mm], fs=ParagraphStyle("t", parent=sm, fontSize=6.6, leading=8.3)))
    S.append(P("4.2 Pivot events (persistence / privilege / defence evasion) with real times", h2))
    piv = sorted([e for e in events if e["kind"] in ("acct_created", "group_add", "svc_install", "task_created", "audit_changed", "log_cleared", "pwd_reset", "dll_block", "fw_change")], key=lambda x: x["ts"])
    rows = [["Time (UTC)", "Event", "Detail", "Log"]] + [[epr_fmt(e["ts"]), epr_KIND_LABEL[e["kind"]], epr_esc(e["text"])[:150], epr_esc(e["log"])] for e in piv[:60]]
    if len(rows) == 1: rows.append(["-", "No pivot events recovered (EVTX not re-scanned or none present)", "-", "-"])
    S.append(tbl(rows, [29 * mm, 36 * mm, W - 98 * mm, 33 * mm]))
    S.append(P("4.3 Failed-logon analysis (EID 4625)", h2))
    fl = [e for e in events if e["kind"] == "logon_fail"]
    if fl:
        byip = defaultdict(list); users = Counter()
        for e in fl:
            m = re.search(r"from\s+(\S+)", e["text"]); ip = m.group(1) if m else "-"
            byip[ip].append(e["ts"]); users[e["text"].split(" type")[0]] += 1
        rows = [["Source IP", "Scope", "Failures", "First", "Last"]]
        for ip, ts in sorted(byip.items(), key=lambda x: -len(x[1]))[:10]:
            rows.append([epr_esc(ip), "local/unknown" if epr_is_local_ip(ip) else ("internal" if epr_is_private_ip(ip) else "EXTERNAL"), str(len(ts)), epr_fmt(min(ts)), epr_fmt(max(ts))])
        S.append(tbl(rows, [45 * mm, 30 * mm, 22 * mm, 40 * mm, W - 137 * mm]))
        S.append(P("Most targeted accounts: " + epr_esc(", ".join(f"{u} ({c})" for u, c in users.most_common(8))), sm))
    else:
        S.append(P("No EID 4625 events were re-extracted (EVTX not scanned, Security log absent, or none present).", sm))

    # 4b telemetry stack
    agents = agents or []; telemetry_gaps = telemetry_gaps or []
    S.append(CondPageBreak(70 * mm)); S.append(P("4b. Telemetry Stack Inventory", h1))
    S.append(P("Agents detected on the host that produce or forward telemetry beyond what is in this evidence folder. "
               "Each one potentially holds additional historical data at its destination.", sm))
    S.append(Spacer(1, 4))
    if agents:
        TYPE_COL = {epr_AT_SIEM: "#1a5276", epr_AT_XDR: "#6c3483", epr_AT_SYSLOG: "#1e8449",
                    epr_AT_WAZUH: "#784212", epr_AT_CLOUD: "#0e6655"}
        rows = [["Agent", "Type", "Status", "Forwarding destination", "Advisory"]]
        for a in agents:
            status = ("Running" if a.get("running") is True
                      else "Stopped" if a.get("running") is False
                      else "Installed")
            status_col = "#1e8449" if a.get("running") is True else "#c0392b" if a.get("running") is False else "#d35400"
            dests = "\n".join(a.get("destinations", [])) or "not extracted (check config manually)"
            rows.append([
                epr_esc(a["name"]),
                tag(epr_esc(a["type"]), TYPE_COL.get(a["type"], "#555")),
                tag(status, status_col),
                epr_esc(dests),
                epr_esc(a.get("note", "")[:180]),
            ])
        S.append(tbl(rows, [40*mm, 28*mm, 18*mm, 45*mm, W-131*mm]))
    else:
        S.append(P("No SIEM forwarders, XDR agents, syslog daemons or cloud security agents were detected "
                   "in the collected artifacts or on the live system. The evidence folder contains all "
                   "available telemetry for this host.", sm))
    if telemetry_gaps:
        S.append(Spacer(1, 4))
        S.append(P("Telemetry gaps detected", ParagraphStyle("gh", parent=h2, textColor=colors.HexColor("#c0392b"))))
        S.append(P("The following agents are installed but their EVTX channels had no events in the collected "
                   "evidence. Possible causes: channel disabled, log tampered/cleared, agent stopped "
                   "before collection, or channel name changed in a newer version.", sm))
        gap_rows = [["Agent", "Missing channel(s)", "Possible cause / action"]]
        for g in telemetry_gaps:
            gap_rows.append([
                epr_esc(g["agent"]),
                epr_esc(", ".join(g["missing_channels"])),
                epr_esc(g["message"][:200]),
            ])
        S.append(tbl(gap_rows, [42*mm, 48*mm, W-90*mm]))
    # 5 coverage
    S.append(CondPageBreak(70 * mm)); S.append(P("5. Telemetry Coverage", h1))
    rows = [["Log", "Role", "Records", "Oldest (UTC)", "Newest (UTC)"]] + [[epr_esc(n), c["role"], f"{c['records']:,}", epr_fmt(c["first"]), epr_fmt(c["last"])] for n, c in coverage.items()]
    if len(rows) == 1: rows.append(["(EVTX not re-scanned in this run)", "-", "-", "-", "-"])
    S.append(tbl(rows, [62 * mm, 22 * mm, 22 * mm, 35 * mm, W - 141 * mm]))
    S.append(P("Missing roles that limit entry-point analysis: " + (epr_esc(", ".join(r for r in ("security", "sysmon", "rdp", "powershell", "defender") if not any(c["role"] == r for c in coverage.values()))) or "none"), sm))

    # 6 triage
    S.append(CondPageBreak(110 * mm)); S.append(P("6. Triage of Tool Findings", h1))
    rows = [["Source", "Count", "Severity", "Verdict", "Assessment"]]
    for s, n, sv, v, note in epr_triage_table(results):
        rows.append([epr_esc(s), f"{n:,}", sv, tag(v, VC.get(v, "#d35400")), epr_esc(note)])
    S.append(tbl(rows, [38 * mm, 15 * mm, 25 * mm, 24 * mm, W - 102 * mm]))

    # 7 recommendations
    S.append(CondPageBreak(60 * mm)); S.append(P("7. Recommended Actions", h1))
    recs = ["Pull the EDR cloud data (device trajectory and file trajectory) for every detected file; it holds parent chain, download origin and hashes.",
            "Recover execution evidence: Amcache, ShimCache, Prefetch, $MFT and $UsnJrnl for the detected binaries and their parent process.",
            "Collect IIS/web, application (Veeam/SQL), firewall/VPN and proxy logs covering the days before the first artifact.",
            "Enable 4688 with command line, 4624/4625 auditing, Sysmon and forward logs to a SIEM with enough retention.",
            "Treat the host as compromised: isolate, rotate credentials stored on or used by it, review persistence (accounts, groups, services, tasks) listed in Section 4.2.",
            "Hunt other hosts for the same file names, paths and detections."]
    for t in recs: S.append(P("&bull; " + t, bl))
    S.append(P("Appendix. Time handling", h1))
    S.append(P("EVTX SystemTime and Hayabusa timestamps are converted to UTC. EDR export times (edr_detections.csv) are assumed UTC. "
               "The folder-name collection time is local time of the collector. The 'timestamp' column of findings.csv is the analysis time and is not used; "
               "event times are in findings_detailed.csv. Verdicts in Section 6 are rule-based and should be confirmed by an analyst.", base))
    doc.build(S)
    return str(path)


# --------------------------------------------------------------------------- memory acquisition (cross-platform)
# Full physical-RAM capture fundamentally needs a kernel-level driver on every OS (Windows blocks
# \\.\PhysicalMemory from user mode since Vista SP1; macOS blocks /dev/mem under SIP; modern Linux
# kernels default to CONFIG_STRICT_DEVMEM). There is no way to do this from a plain user-mode script
# without shipping/loading a signed driver - so this module does two honest things instead of
# pretending otherwise: (1) a targeted PROCESS memory dump, which needs no driver and works on every
# OS today, and (2) a best-effort FULL-RAM capture using existing trusted open-source tools
# (WinPmem/AVML), downloaded on demand, with Apple Silicon macOS explicitly called out as not
# possible (its security architecture has no public third-party path to raw physical memory).

def epr_mem_detect_platform():
    import platform as _pf
    system = _pf.system()  # 'Windows' | 'Linux' | 'Darwin'
    machine = (_pf.machine() or "").lower()
    is_arm = machine in ("arm64", "aarch64")
    return {"system": system, "arch": machine, "is_apple_silicon": system == "Darwin" and is_arm}


def epr_mem_download_file(url, dest, log, timeout=600):
    if os.environ.get("FM_OFFLINE"):
        log("WARN", "Offline kit mode: not downloading (tool must already be inside the kit's tools/ folder)"); return False
    """Streamed download with no non-stdlib dependency. Returns True/False, never raises."""
    import urllib.request
    try:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "forensics-tool"})
        with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        return dest.exists() and dest.stat().st_size > 0
    except Exception as ex:
        log("WARN", f"Download failed ({url}): {type(ex).__name__}: {ex}")
        return False


def epr_mem_github_latest_asset(repo, name_contains, log):
    if os.environ.get("FM_OFFLINE"): return None
    """Looks up the latest GitHub release of `repo` and returns the download URL of the first asset
    whose name contains every string in name_contains (case-insensitive list), or None."""
    import urllib.request
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                     headers={"User-Agent": "forensics-tool", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            rel = json.load(r)
        for a in rel.get("assets", []):
            n = a.get("name", "").lower()
            if all(s.lower() in n for s in name_contains):
                return a.get("browser_download_url")
    except Exception as ex:
        log("WARN", f"Could not look up latest release of {repo}: {type(ex).__name__}: {ex}")
    return None


# -------- targeted process dump: no driver, no download, works today on every OS --------
def epr_mem_dump_process(pid, out_dir, log, name_hint=""):
    """Dumps ONE process's memory (not the whole machine) - the highest-value, always-available
    alternative to a full RAM image: credentials in lsass, injected code, decrypted strings, etc.
    Returns the output path or None."""
    plat = epr_mem_detect_platform()
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    label = f"PID {pid}" + (f" ({name_hint})" if name_hint else "")
    try:
        if plat["system"] == "Windows":
            dest = out / f"proc_{pid}{('_'+name_hint) if name_hint else ''}.dmp"
            r = subprocess.run(f'rundll32.exe comsvcs.dll, MiniDump {pid} "{dest}" full',
                               shell=True, capture_output=True, text=True, timeout=180)
            if dest.exists() and dest.stat().st_size > 0:
                log("OK", f"Process memory dumped: {label} -> {dest.name} ({dest.stat().st_size:,} bytes)")
                return str(dest)
            log("WARN", f"Process dump failed for {label}: {(r.stderr or '').strip()[:200] or 'no output produced (needs Administrator, and the PID must exist)'}")
            return None

        if plat["system"] == "Linux":
            maps_f, mem_f = Path(f"/proc/{pid}/maps"), Path(f"/proc/{pid}/mem")
            if not maps_f.exists():
                log("WARN", f"Process dump failed for {label}: /proc/{pid} not found (wrong PID, or process exited)")
                return None
            dest = out / f"proc_{pid}{('_'+name_hint) if name_hint else ''}.raw"
            regions, total = [], 0
            try:
                with open(maps_f) as f:
                    for line in f:
                        bounds = line.split()[0]
                        lo_s, hi_s = bounds.split("-")
                        regions.append((int(lo_s, 16), int(hi_s, 16)))
            except Exception as ex:
                log("WARN", f"Could not read {maps_f}: {ex}")
                return None
            try:
                with open(mem_f, "rb") as mf, open(dest, "wb") as out_f:
                    for lo, hi in regions:
                        try:
                            mf.seek(lo)
                            data = mf.read(hi - lo)
                            out_f.write(data)
                            total += len(data)
                        except (OSError, ValueError):
                            continue  # unreadable region (guard page, device mapping, etc.) - skip it
            except PermissionError:
                log("WARN", f"Process dump failed for {label}: permission denied reading /proc/{pid}/mem "
                            f"(needs root, or must be run as the same user that owns the process)")
                return None
            if total > 0:
                log("OK", f"Process memory dumped: {label} -> {dest.name} ({total:,} bytes across {len(regions)} region(s))")
                return str(dest)
            log("WARN", f"Process dump produced no data for {label} (all regions unreadable)")
            return None

        if plat["system"] == "Darwin":
            if not shutil.which("lldb"):
                log("WARN", f"Process dump failed for {label}: lldb not found - install Xcode Command Line "
                            f"Tools first ('xcode-select --install')")
                return None
            dest = out / f"proc_{pid}{('_'+name_hint) if name_hint else ''}.core"
            r = subprocess.run(["lldb", "-p", str(pid), "--batch",
                               "-o", f"process save-core {dest}", "-o", "process detach", "-o", "quit"],
                               capture_output=True, text=True, timeout=300)
            if dest.exists() and dest.stat().st_size > 0:
                log("OK", f"Process memory dumped: {label} -> {dest.name} ({dest.stat().st_size:,} bytes)")
                return str(dest)
            log("WARN", f"Process dump failed for {label}: {(r.stderr or r.stdout or '').strip()[:200] or 'lldb could not attach (needs sudo, or System Integrity Protection is blocking debugging of this process)'}")
            return None
    except subprocess.TimeoutExpired:
        log("WARN", f"Process dump timed out for {label}")
    except Exception as ex:
        log("WARN", f"Process dump failed for {label}: {type(ex).__name__}: {ex}")
    return None


# -------- best-effort FULL physical memory capture via existing open-source tools --------
def epr_mem_full_capture(out_dir, log, auto_yes=False):
    plat = epr_mem_detect_platform()
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)

    if plat["system"] == "Windows":
        dest = out / "memory.raw"
        exe = shutil.which("winpmem") or shutil.which("winpmem_mini_x64_rc2.exe")
        if not exe:
            log("INFO", "WinPmem not found - looking up the latest release (Velocidex/WinPmem) ...")
            url = epr_mem_github_latest_asset("Velocidex/WinPmem", [".exe"], log) or \
                  epr_mem_github_latest_asset("Velocidex/c-aff4", ["winpmem", ".exe"], log)
            if not url:
                log("WARN", "Could not find a WinPmem download - get it manually from "
                            "https://github.com/Velocidex/WinPmem/releases and re-run with it on PATH")
                return None
            local_exe = out / "winpmem.exe"
            if not epr_mem_download_file(url, local_exe, log):
                return None
            exe = str(local_exe)
        log("INFO", "Running WinPmem (needs Administrator; this can take several minutes) ...")
        try:
            r = subprocess.run([exe, str(dest)], capture_output=True, text=True, timeout=1800)
            if dest.exists() and dest.stat().st_size > 0:
                log("OK", f"Full memory captured -> {dest.name} ({dest.stat().st_size:,} bytes)")
                return str(dest)
            log("WARN", "WinPmem did not produce an image. Common cause: its driver isn't allowed to load on "
                        "this Windows version (driver-signature enforcement). Options: run as Administrator, "
                        "or temporarily allow test-signed drivers ('bcdedit /set testsigning on', reboot), or "
                        "use a GUI tool such as Magnet RAM Capture instead. Falling back to process-level dumps.")
            if r.stderr:
                log("WARN", f"WinPmem output: {r.stderr.strip()[:300]}")
        except subprocess.TimeoutExpired:
            log("WARN", "WinPmem timed out after 30 minutes")
        except Exception as ex:
            log("WARN", f"WinPmem failed: {type(ex).__name__}: {ex}")
        return None

    if plat["system"] == "Linux":
        dest = out / "memory.lime"
        exe = shutil.which("avml")
        if not exe:
            log("INFO", "AVML not found - downloading the static binary (microsoft/avml) ...")
            url = epr_mem_github_latest_asset("microsoft/avml", ["avml"], log) or \
                  "https://github.com/microsoft/avml/releases/latest/download/avml"
            local_bin = out / "avml"
            if not epr_mem_download_file(url, local_bin, log):
                log("WARN", "Could not get AVML - full memory capture skipped, falling back to process-level dumps")
                return None
            try:
                local_bin.chmod(0o755)
            except Exception:
                pass
            exe = str(local_bin)
        log("INFO", "Running AVML (tries /proc/kcore, /dev/crash, /dev/mem in turn; this can take a while) ...")
        try:
            r = subprocess.run([exe, "acquire", str(dest)], capture_output=True, text=True, timeout=1800)
            if dest.exists() and dest.stat().st_size > 0:
                log("OK", f"Full memory captured -> {dest.name} ({dest.stat().st_size:,} bytes)")
                return str(dest)
            log("WARN", "AVML did not produce an image (needs root, and CONFIG_STRICT_DEVMEM or a hardened "
                        "kernel may block every backend it tries). Falling back to process-level dumps.")
            if r.stderr:
                log("WARN", f"AVML output: {r.stderr.strip()[:300]}")
        except subprocess.TimeoutExpired:
            log("WARN", "AVML timed out after 30 minutes")
        except Exception as ex:
            log("WARN", f"AVML failed: {type(ex).__name__}: {ex}")
        return None

    if plat["system"] == "Darwin":
        if plat["is_apple_silicon"]:
            log("WARN", "Full RAM capture is not possible on Apple Silicon Macs: there is no public "
                        "third-party driver path to physical memory on this architecture (System "
                        "Integrity Protection plus Apple's kernel-extension signing requirements block it, "
                        "and no maintained open-source tool supports it). Falling back to process-level "
                        "dumps, which work the same as on Intel.")
            return None
        exe = shutil.which("osxpmem")
        if not exe:
            log("WARN", "Full RAM capture on Intel Mac needs 'osxpmem', which is unmaintained and almost "
                        "certainly will not load on a modern, SIP-enabled macOS (its kernel extension predates "
                        "current signing requirements) - not downloading it automatically. If you have a working "
                        "copy, put it on PATH and re-run; otherwise use process-level dumps or a commercial "
                        "imaging tool with physical access.")
            return None
        dest = out / "memory.aff4"
        log("INFO", "Running osxpmem (best-effort; needs SIP partially disabled and root) ...")
        try:
            r = subprocess.run([exe, "-o", str(dest)], capture_output=True, text=True, timeout=1800)
            if dest.exists() and dest.stat().st_size > 0:
                log("OK", f"Full memory captured -> {dest.name} ({dest.stat().st_size:,} bytes)")
                return str(dest)
            log("WARN", "osxpmem did not produce an image. Falling back to process-level dumps.")
        except subprocess.TimeoutExpired:
            log("WARN", "osxpmem timed out after 30 minutes")
        except Exception as ex:
            log("WARN", f"osxpmem failed: {type(ex).__name__}: {ex}")
        return None

    log("WARN", f"Unrecognised platform '{plat['system']}' - memory capture skipped")
    return None


# --------------------------------------------------------------------------- Fuji (macOS Full File System acquisition)
# Fuji (https://github.com/Lazza/Fuji) is NOT a memory tool - it is a logical Full File System (FFS)
# disk acquisition tool for Mac computers, built specifically to work around the fact that Apple
# Silicon's hardware-level encryption makes a raw disk image (dd/Disk Utility) impossible. It wraps
# the standard macOS utilities asr/rsync/sysdiagnose/hdiutil/diskutil behind a GUI. It has no
# documented CLI/headless mode, and critically it needs Full Disk Access granted to it via System
# Settings - a one-time step that, by macOS design, cannot be scripted or bypassed (it requires a
# human clicking a toggle in a protected Privacy & Security pane, enforced at the TCC database level
# even for root). So this integration does everything that CAN be automated - detecting/installing
# Fuji and launching it - and then hands off to the examiner for that one manual permission step and
# the acquisition itself, which is how Fuji is designed to be used in practice.
epr_FUJI_APP_PATHS = ["/Applications/Fuji.app", str(Path.home() / "Applications/Fuji.app")]


def epr_fuji_find_app():
    for p in epr_FUJI_APP_PATHS:
        if Path(p).exists():
            return p
    return None


def epr_fuji_install(out_dir, log):
    """Downloads the latest Fuji release DMG and installs Fuji.app to /Applications. Returns the
    installed app path, or None on failure. Never raises."""
    import urllib.request
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    url = epr_mem_github_latest_asset("Lazza/Fuji", [".dmg"], log)
    if not url:
        # GitHub API is rate-limited fairly aggressively for unauthenticated requests; fall back to
        # resolving the latest release tag via the redirect on /releases/latest and guessing the
        # asset name from Fuji's actual release naming convention (FujiApp-<version>.dmg).
        try:
            req = urllib.request.Request("https://github.com/Lazza/Fuji/releases/latest", method="HEAD")
            with urllib.request.urlopen(req, timeout=20) as r:
                final_url = r.geturl()
            tag = final_url.rstrip("/").rsplit("/", 1)[-1]
            candidate = f"https://github.com/Lazza/Fuji/releases/download/{tag}/FujiApp-{tag}.dmg"
            req2 = urllib.request.Request(candidate, method="HEAD")
            with urllib.request.urlopen(req2, timeout=20) as r2:
                if r2.status == 200:
                    url = candidate
        except Exception as ex:
            log("WARN", f"Fallback release lookup also failed: {type(ex).__name__}: {ex}")
    if not url:
        log("WARN", "Could not find a Fuji .dmg in the latest release - get it manually from "
                    "https://github.com/Lazza/Fuji/releases")
        return None
    dmg = out / "Fuji.dmg"
    log("INFO", f"Downloading Fuji ({url.rsplit('/', 1)[-1]}) ...")
    if not epr_mem_download_file(url, dmg, log):
        return None
    mount_point = out / "Fuji_mount"
    try:
        r = subprocess.run(["hdiutil", "attach", str(dmg), "-mountpoint", str(mount_point), "-nobrowse", "-quiet"],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            log("WARN", f"Could not mount Fuji.dmg: {(r.stderr or '').strip()[:200]}")
            return None
        app_src = mount_point / "Fuji.app"
        if not app_src.exists():
            found = list(mount_point.glob("*.app"))
            app_src = found[0] if found else None
        if not app_src:
            log("WARN", "Fuji.dmg mounted but no .app bundle was found inside it")
            return None
        dest = Path("/Applications/Fuji.app")
        try:
            r2 = subprocess.run(["cp", "-R", str(app_src), str(dest)], capture_output=True, text=True, timeout=120)
            installed = dest if dest.exists() else None
        except Exception as ex:
            log("WARN", f"Could not copy Fuji.app to /Applications (try with sudo?): {ex}")
            installed = None
        return str(installed) if installed else None
    except Exception as ex:
        log("WARN", f"Fuji install failed: {type(ex).__name__}: {ex}")
        return None
    finally:
        try:
            subprocess.run(["hdiutil", "detach", str(mount_point), "-quiet"], capture_output=True, timeout=30)
        except Exception:
            pass


def epr_fuji_launch(app_path, log):
    """Opens Fuji.app for the examiner to run the acquisition (GUI, by design - see module docstring
    above). Returns True if it was launched, False otherwise. Never raises."""
    try:
        r = subprocess.run(["open", "-a", app_path], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            log("OK", "Fuji launched.")
            return True
        log("WARN", f"Could not launch Fuji: {(r.stderr or '').strip()[:200]}")
        return False
    except Exception as ex:
        log("WARN", f"Could not launch Fuji: {type(ex).__name__}: {ex}")
        return False


def epr_fuji_acquire(out_dir, log):
    import platform as _pf
    if _pf.system() != "Darwin":
        log("WARN", "Fuji only runs on macOS - skipped")
        return False
    app = epr_fuji_find_app()
    if not app:
        log("INFO", "Fuji not found - downloading and installing it ...")
        app = epr_fuji_install(out_dir, log)
    if not app:
        log("WARN", "Fuji could not be installed automatically. Download it yourself from "
                    "https://github.com/Lazza/Fuji/releases and open the DMG.")
        return False
    epr__fuji_notice()
    return epr_fuji_launch(app, log)


def epr__fuji_notice():
    """Print a hard-to-miss terminal notice explaining the one-time manual FDA step and why it is
    needed, right before Fuji opens - so the examiner is not caught off-guard by Fuji's own prompt."""
    W = 72
    sep  = "═" * W
    sep2 = "─" * W
    def row(txt="", col="\033[0m"):
        lines = []
        words = txt.split(); cur = ""
        for w in words:
            if len(cur) + len(w) + 1 > W - 4:
                lines.append(cur)
                cur = w
            else:
                cur = (cur + " " + w).strip()
        if cur: lines.append(cur)
        if not lines: lines = [""]
        for l in lines:
            print(f"\033[93m║\033[0m {col}{l:<{W-3}}\033[0m\033[93m║\033[0m")
    print(f"\n\033[93m╔{sep}╗\033[0m")
    row()
    row("⚠  NOTICE — ONE MANUAL STEP REQUIRED BEFORE FUJI CAN RUN", "\033[1m\033[97m")
    row()
    print(f"\033[93m║{sep2:^{W}}║\033[0m")
    row()
    row("WHAT TO DO (takes about 30 seconds):", "\033[96m\033[1m")
    row()
    row("  1.  Fuji will open now on your screen.", "\033[97m")
    row("  2.  Inside Fuji, click the button:  'Full Disk Access Settings'", "\033[97m")
    row("  3.  macOS will open  System Settings → Privacy & Security →", "\033[97m")
    row("      Full Disk Access.", "\033[97m")
    row("  4.  Click the  '+'  button and select Fuji.app  —  OR  —  drag", "\033[97m")
    row("      Fuji.app from /Applications into the list.", "\033[97m")
    row("  5.  Make sure the toggle next to Fuji is  ENABLED  (green).", "\033[97m")
    row("  6.  Return to the Fuji window and start the acquisition.", "\033[97m")
    row()
    print(f"\033[93m║{sep2:^{W}}║\033[0m")
    row()
    row("WHY THIS STEP CANNOT BE SKIPPED OR SCRIPTED:", "\033[96m\033[1m")
    row()
    row("macOS stores Full Disk Access grants in a protected database called"
        " TCC (Transparency, Consent and Control). Even running as root,"
        " no script or tool — including this one — can write to TCC without"
        " triggering a security violation. Apple enforces this at the kernel"
        " level precisely to prevent malware from silently granting itself"
        " disk access. The toggle must be set by a human in the GUI.", "\033[37m")
    row()
    row("WHY FUJI NEEDS FULL DISK ACCESS:", "\033[96m\033[1m")
    row()
    row("On Apple Silicon Macs the disk is encrypted with keys that live in"
        " the Secure Enclave. A raw 'dd' image would be unreadable. Fuji"
        " uses Apple's own  asr / rsync / sysdiagnose  utilities to copy"
        " files while the system is live and the keys are in use — this is"
        " called a Full File System (FFS) acquisition and it is the same"
        " approach used for modern smartphones. Without Full Disk Access,"
        " those utilities are silently denied access to protected folders"
        " (Mail, Messages, Health, Safari history, etc.).", "\033[37m")
    row()
    row("RECOMMENDED ACQUISITION MODE INSIDE FUJI:", "\033[96m\033[1m")
    row()
    row("  → Rsync   (safest, works on any macOS, continues if a file fails)", "\033[97m")
    row("  → ASR     (faster, but has known errors on some recent macOS versions)", "\033[97m")
    row("  → Sysdiagnose  (system logs + Unified Logs ZIP — good for malware cases)", "\033[97m")
    row()
    row("Output: a  .dmg  or  .zip  file. Copy it next to this tool's other"
        " output when done. It is independent, standalone forensic evidence.", "\033[37m")
    row()
    print(f"\033[93m╚{sep}╝\033[0m\n")


def epr_mem_resolve_pids(name_or_pid, log):
    """Accepts a PID or a process name and returns a list of matching PIDs (strings)."""
    name_or_pid = name_or_pid.strip()
    if name_or_pid.isdigit():
        return [name_or_pid]
    plat = epr_mem_detect_platform()
    try:
        if plat["system"] == "Windows":
            r = subprocess.run(f'tasklist /fi "imagename eq {name_or_pid}" /fo csv /nh',
                               shell=True, capture_output=True, text=True, timeout=30)
            pids = []
            for line in (r.stdout or "").strip().splitlines():
                cols = [c.strip('"') for c in line.split('","')]
                if len(cols) > 1 and cols[1].isdigit():
                    pids.append(cols[1])
            return pids
        else:
            r = subprocess.run(["pgrep", "-f", name_or_pid], capture_output=True, text=True, timeout=30)
            return [p for p in (r.stdout or "").split() if p.isdigit()]
    except Exception as ex:
        log("WARN", f"Could not resolve '{name_or_pid}' to a PID: {ex}")
        return []


# --------------------------------------------------------------------------- Windows EDR auto-detect + channel map
# Each entry: (display_name, detection_keys, evtx_channels, reg_keys, process_names)
#   detection_keys  — strings that may appear in: installed-software names, running process names,
#                     service display names, or EVTX channel names (case-insensitive OR match)
#   evtx_channels   — wevtutil channel names to export when this EDR is found
#   reg_keys        — HKLM software keys that confirm installation (checked with 'reg query')
#   process_names   — exe names whose presence in 'tasklist' confirms the agent is running

epr_EDR_PROFILES = [
    {
        "id": "cisco_secure_endpoint",
        "name": "Cisco Secure Endpoint (AMP)",
        "detection_keys": ["cisco secure endpoint", "cisco amp", "amp for endpoints",
                           "csc_ui", "cscsvc", "ciscosecureclient", "cisco secure client"],
        "evtx_channels": [
            "Cisco Secure Endpoint",
            "Cisco Secure Endpoint Cloud",
            "Cisco Secure Endpoint Events",
            "Cisco Secure Endpoint WMI",
            "Cisco Secure Client",
        ],
        "reg_keys": [
            r"HKLM\SOFTWARE\Cisco\Cisco Secure Endpoint",
            r"HKLM\SOFTWARE\Cisco AMP for Endpoints Connector",
        ],
        "process_names": ["csc_ui.exe", "cscsvc.exe", "ampdaemon.exe", "iptray.exe"],
    },
    {
        "id": "crowdstrike_falcon",
        "name": "CrowdStrike Falcon",
        "detection_keys": ["crowdstrike", "falcon sensor", "falcond", "csfalconservice",
                           "csagent", "crowdstrike falcon"],
        "evtx_channels": [
            "CrowdStrike-Falcon Sensor",
            "CrowdStrike-Falcon-Sensor/Operational",
        ],
        "reg_keys": [
            r"HKLM\SYSTEM\CurrentControlSet\Services\CSAgent",
            r"HKLM\SOFTWARE\CrowdStrike",
        ],
        "process_names": ["csfalconservice.exe", "csagent.exe", "falcond.exe"],
    },
    {
        "id": "sentinelone",
        "name": "SentinelOne",
        "detection_keys": ["sentinelone", "sentinel agent", "s1agent", "sentinelagent",
                           "sentinelone platform"],
        "evtx_channels": [
            "SentinelOne",
            "SentinelOne Deep Visibility",
        ],
        "reg_keys": [
            r"HKLM\SOFTWARE\SentinelOne",
            r"HKLM\SYSTEM\CurrentControlSet\Services\SentinelAgent",
        ],
        "process_names": ["sentinelone.exe", "s1agent.exe", "sentinelagent.exe",
                          "sentinelhelper.exe"],
    },
    {
        "id": "crowdstrike_falcon_sensor",
        "name": "CrowdStrike Falcon Sensor (legacy service name)",
        "detection_keys": ["csfalconservice"],
        "evtx_channels": ["CrowdStrike-Falcon Sensor"],
        "reg_keys": [r"HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService"],
        "process_names": ["csfalconservice.exe"],
    },
    {
        "id": "microsoft_defender_edr",
        "name": "Microsoft Defender for Endpoint (MDE)",
        "detection_keys": ["microsoft defender for endpoint", "mssense", "sense",
                           "windows defender advanced threat", "wdatp"],
        "evtx_channels": [
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Windows Defender/WHC",
            "Microsoft-Windows-SENSE/Operational",
        ],
        "reg_keys": [
            r"HKLM\SOFTWARE\Microsoft\Windows Defender Advanced Threat Protection",
        ],
        "process_names": ["mssense.exe", "sensecncproxy.exe", "mpcmdrun.exe"],
    },
    {
        "id": "carbon_black",
        "name": "VMware Carbon Black",
        "detection_keys": ["carbon black", "cbdefense", "cb defense", "carbonblack",
                           "vmware carbon black", "cbsensor"],
        "evtx_channels": [
            "CarbonBlack",
            "Carbon Black",
        ],
        "reg_keys": [
            r"HKLM\SOFTWARE\CarbonBlack",
            r"HKLM\SOFTWARE\VMware, Inc.\VMware Carbon Black",
        ],
        "process_names": ["cbsensor.exe", "cbdefense.exe", "repux.exe", "repmgr.exe"],
    },
    {
        "id": "sophos",
        "name": "Sophos Endpoint",
        "detection_keys": ["sophos", "sophosav", "sophos endpoint", "sav service"],
        "evtx_channels": ["Sophos Endpoint"],
        "reg_keys": [r"HKLM\SOFTWARE\Sophos"],
        "process_names": ["sophosav.exe", "sophossps.exe", "savservice.exe", "hmpalert.exe"],
    },
    {
        "id": "trellix_edr",
        "name": "Trellix / McAfee Endpoint Security",
        "detection_keys": ["trellix", "mcafee", "fireeye endpoint", "hx agent",
                           "endpoint security for windows", "mfeetp", "mfetp"],
        "evtx_channels": ["Trellix Endpoint Security", "McAfee Endpoint Security"],
        "reg_keys": [
            r"HKLM\SOFTWARE\McAfee",
            r"HKLM\SOFTWARE\Trellix",
            r"HKLM\SOFTWARE\FireEye",
        ],
        "process_names": ["mfeetp.exe", "mfetp.exe", "hxtray.exe", "xagt.exe"],
    },
    {
        "id": "symantec_sep",
        "name": "Symantec / Broadcom Endpoint Security",
        "detection_keys": ["symantec", "sep ", "broadcom endpoint", "norton security",
                           "ccsvchst"],
        "evtx_channels": ["Symantec Endpoint Protection"],
        "reg_keys": [r"HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection"],
        "process_names": ["ccsvchst.exe", "smc.exe", "sepagent.exe", "smcgui.exe"],
    },
    {
        "id": "trend_micro",
        "name": "Trend Micro Apex One / Worry-Free",
        "detection_keys": ["trend micro", "trendmicro", "apex one", "worry-free",
                           "ntrtscan", "pccntmon"],
        "evtx_channels": ["Trend Micro Deep Security"],
        "reg_keys": [
            r"HKLM\SOFTWARE\TrendMicro",
            r"HKLM\SOFTWARE\Trend Micro",
        ],
        "process_names": ["ntrtscan.exe", "pccntmon.exe", "tmlisten.exe", "tmbmsrv.exe"],
    },
    {
        "id": "eset",
        "name": "ESET Endpoint Security",
        "detection_keys": ["eset", "eset endpoint", "eset security", "ekrn"],
        "evtx_channels": ["ESET Security"],
        "reg_keys": [r"HKLM\SOFTWARE\ESET"],
        "process_names": ["ekrn.exe", "egui.exe", "esets_daemon.exe"],
    },
    {
        "id": "elastic_defend",
        "name": "Elastic Defend / Endpoint Security",
        "detection_keys": ["elastic defend", "elastic endpoint", "elastic security",
                           "elasticendpoint"],
        "evtx_channels": ["Elastic-Endpoint"],
        "reg_keys": [r"HKLM\SOFTWARE\Elastic"],
        "process_names": ["elastic-endpoint.exe", "elastic-agent.exe"],
    },
    {
        "id": "palo_alto_cortex",
        "name": "Palo Alto Cortex XDR",
        "detection_keys": ["cortex xdr", "palo alto", "cyvera", "traps", "cytool"],
        "evtx_channels": ["Cortex XDR"],
        "reg_keys": [
            r"HKLM\SOFTWARE\Palo Alto Networks",
            r"HKLM\SOFTWARE\Cyvera",
        ],
        "process_names": ["cytool.exe", "cyvera.exe", "xdr.exe"],
    },
    {
        "id": "bitdefender",
        "name": "Bitdefender GravityZone",
        "detection_keys": ["bitdefender", "gravityzone", "bdagent", "bdservicehost"],
        "evtx_channels": ["Bitdefender Endpoint Security Tools"],
        "reg_keys": [r"HKLM\SOFTWARE\Bitdefender"],
        "process_names": ["bdagent.exe", "bdservicehost.exe", "bdredline.exe"],
    },
    {
        "id": "qualys_edr",
        "name": "Qualys EDR",
        "detection_keys": ["qualys", "qualys edr", "qualys cloud agent"],
        "evtx_channels": ["Qualys"],
        "reg_keys": [r"HKLM\SOFTWARE\Qualys"],
        "process_names": ["qualysagent.exe", "qagent.exe"],
    },
    {
        "id": "cylance",
        "name": "Cylance / BlackBerry Protect",
        "detection_keys": ["cylance", "blackberry protect", "cylinderui", "cylancesvc"],
        "evtx_channels": ["Cylance"],
        "reg_keys": [r"HKLM\SOFTWARE\Cylance"],
        "process_names": ["cylancesvc.exe", "cylinderui.exe"],
    },
    {
        "id": "harfanglab",
        "name": "HarfangLab EDR",
        "detection_keys": ["harfanglab", "hurukai"],
        "evtx_channels": ["HarfangLab"],
        "reg_keys": [r"HKLM\SOFTWARE\HarfangLab"],
        "process_names": ["hurukai.exe", "harfanglab.exe"],
    },
]

# Channels that are ALWAYS collected regardless of which EDR is found
epr_EVTX_ALWAYS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-PowerShell/Analytic",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TaskScheduler/Maintenance",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-CodeIntegrity/Operational",
]

# Microsoft Defender (built-in antivirus, NOT MDE) — always collected since it's on every Windows
epr_EVTX_DEFENDER_BUILTIN = [
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Windows Defender/WHC",
]


def epr_detect_edr(log):
    import platform as _pf
    if _pf.system() != "Windows":
        # On non-Windows (analysis/test run) return empty — caller handles this gracefully
        return []

    def run_cmd(cmd, timeout=30):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (r.stdout or "").lower()
        except Exception:
            return ""

    log("INFO", "Detecting installed EDR agent ...")

    # Gather all evidence into one big lowercase string for cheap substring search
    uninstall_key = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall"
    installed = run_cmd(
        f'wmic product get name,vendor 2>nul || '
        f'reg query "{uninstall_key}" /s /v DisplayName 2>nul',
        timeout=60
    )
    services  = run_cmd("sc query type= all state= all", timeout=30)
    processes = run_cmd("tasklist /fo csv /nh", timeout=15)
    reg_sw    = run_cmd('reg query "HKLM\\\\SOFTWARE" /f "" /k 2>nul', timeout=20)

    haystack  = " ".join([installed, services, processes, reg_sw])

    found = []
    for p in epr_EDR_PROFILES:
        # Check detection_keys against combined haystack
        if any(k.lower() in haystack for k in p["detection_keys"]):
            found.append(p)
            continue
        # Check process names explicitly
        if any(proc.lower() in processes for proc in p["process_names"]):
            found.append(p)
            continue
        # Reg-key check: require actual registry content in output (REG_SZ/DWORD/etc or a sub-key line)
        # to avoid false positives when the mock or real command returns non-registry text.
        for rk in p.get("reg_keys", []):
            out = run_cmd(f'reg query "{rk}" 2>nul', timeout=10)
            is_real_reg = out and ("reg_sz" in out or "reg_dword" in out or "reg_binary" in out
                                   or "reg_multi_sz" in out or "hklm\\" in out or "hkcu\\" in out)
            if is_real_reg:
                found.append(p)
                break

    # Deduplicate (same id may have matched multiple times)
    seen, unique = set(), []
    for p in found:
        if p["id"] not in seen:
            seen.add(p["id"])
            unique.append(p)

    if unique:
        names = ", ".join(p["name"] for p in unique)
        log("OK", f"Detected EDR: {names}")
    else:
        log("INFO", "No known EDR agent detected — collecting only base Windows + Defender logs")

    return unique


def epr_build_evtx_channel_list(edr_profiles, log):
    channels = list(epr_EVTX_ALWAYS) + list(epr_EVTX_DEFENDER_BUILTIN)
    for p in edr_profiles:
        for ch in p["evtx_channels"]:
            if ch not in channels:
                channels.append(ch)
                log("INFO", f"  + EDR channel: {ch}  ({p['name']})")
    return channels


# --------------------------------------------------------------------------- Telemetry Stack Inventory
# Beyond EDR, an endpoint may run SIEM forwarders, XDR agents, cloud security agents, and native
# log-forwarding daemons. Knowing what is present has two critical DFIR consequences:
#   1. Historical logs are probably available at the forwarder's destination SIEM/SOAR - pull them.
#   2. If an agent is installed but its EVTX channel has no events, that is a gap or tamper signal.

# Agent-type labels
epr_AT_SIEM  = "SIEM / log forwarder"
epr_AT_XDR   = "XDR / cloud security"
epr_AT_SYSLOG = "Syslog daemon"
epr_AT_WAZUH = "Wazuh / OSSEC (open-source SIEM+EDR)"
epr_AT_CLOUD = "Cloud monitoring agent"

epr_AGENT_PROFILES = [
    # ---- SIEM / log forwarding agents ----
    {
        "id": "splunk_uf", "name": "Splunk Universal Forwarder", "type": epr_AT_SIEM,
        "detection_keys": ["splunkforwarder", "splunk forwarder", "splunkuniversalforwarder"],
        "process_names": ["splunkd.exe", "splunkd"],
        "service_names": ["SplunkForwarder", "splunkd"],
        "reg_keys": [r"HKLM\SOFTWARE\SplunkUniversalForwarder"],
        "win_config_paths": [
            r"C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf",
            r"C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf",
        ],
        "lin_config_paths": [
            "/opt/splunkforwarder/etc/system/local/outputs.conf",
            "/opt/splunkforwarder/etc/system/local/inputs.conf",
        ],
        "dest_patterns": [
            (r"server\s*=\s*([^\s,\n]+:[0-9]+)", "TCP forwarding to"),
        ],
        "evtx_channels": [],
        "note": "Pull historical logs from the Splunk indexer at the detected destination.",
    },
    {
        "id": "elastic_agent", "name": "Elastic Agent / Beats", "type": epr_AT_SIEM,
        "detection_keys": ["elastic agent", "elastic-agent", "filebeat", "winlogbeat",
                           "metricbeat", "auditbeat"],
        "process_names": ["elastic-agent.exe", "filebeat.exe", "winlogbeat.exe",
                          "elastic-agent", "filebeat", "winlogbeat"],
        "service_names": ["Elastic Agent", "filebeat", "winlogbeat"],
        "reg_keys": [],
        "win_config_paths": [
            r"C:\Program Files\Elastic\Agent\data\elastic-agent.yml",
            r"C:\Program Files\Filebeat\filebeat.yml",
            r"C:\Program Files\Winlogbeat\winlogbeat.yml",
        ],
        "lin_config_paths": [
            "/etc/elastic-agent/elastic-agent.yml",
            "/etc/filebeat/filebeat.yml",
            "/etc/winlogbeat/winlogbeat.yml",
        ],
        "dest_patterns": [
            (r"hosts:\s*\[?['\"]([^'\"\]]+)['\"]", "Elasticsearch/Logstash host"),
            (r"output\.elasticsearch.*?hosts.*?['\"]([^'\"]+)['\"]", "Elasticsearch"),
            (r"output\.logstash.*?hosts.*?['\"]([^'\"]+)['\"]", "Logstash"),
        ],
        "evtx_channels": [],
        "note": "Pull logs from the Elastic/Logstash destination. Check Kibana for this host's timeline.",
    },
    {
        "id": "nxlog", "name": "NXLog", "type": epr_AT_SIEM,
        "detection_keys": ["nxlog"],
        "process_names": ["nxlog.exe", "nxlog"],
        "service_names": ["nxlog"],
        "reg_keys": [],
        "win_config_paths": [
            r"C:\Program Files\nxlog\conf\nxlog.conf",
            r"C:\Program Files (x86)\nxlog\conf\nxlog.conf",
        ],
        "lin_config_paths": ["/etc/nxlog/nxlog.conf"],
        "dest_patterns": [
            (r"(?:Host|Server)\s+([^\s]+)\s+(?:Port\s+)?([0-9]+)", "forwarding to"),
        ],
        "evtx_channels": [],
        "note": "NXLog is forwarding logs - check its destination for historical data.",
    },
    {
        "id": "wef", "name": "Windows Event Forwarding (WEF/WEC)", "type": epr_AT_SIEM,
        "detection_keys": ["wecsvc", "windows event collector", "wecutil"],
        "process_names": ["wecutil.exe"],
        "service_names": ["Wecsvc"],
        "reg_keys": [r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding"],
        "win_config_paths": [],
        "lin_config_paths": [],
        "dest_patterns": [
            (r"<SubscriptionManager>([^<]+)</SubscriptionManager>", "WEC server"),
        ],
        "evtx_channels": ["ForwardedEvents"],
        "note": "Windows Event Forwarding is configured - a Windows Event Collector (WEC) server "
                "is receiving events. Pull logs from that WEC server for the full history.",
    },
    {
        "id": "fluentd", "name": "Fluentd / td-agent", "type": epr_AT_SIEM,
        "detection_keys": ["fluentd", "td-agent", "td_agent"],
        "process_names": ["fluentd", "td-agent", "ruby"],
        "service_names": ["td-agent", "fluentd"],
        "reg_keys": [],
        "win_config_paths": [r"C:\opt\td-agent\etc\td-agent\td-agent.conf"],
        "lin_config_paths": ["/etc/fluent/fluent.conf", "/etc/td-agent/td-agent.conf"],
        "dest_patterns": [
            (r"<server>\s*host\s+([^\s]+)\s*port\s+([0-9]+)", "forwarding to"),
            (r"host\s+([^\s]+)\s*\n\s*port\s+([0-9]+)", "forwarding to"),
        ],
        "evtx_channels": [],
        "note": "Fluentd is shipping logs - check its downstream destination.",
    },
    {
        "id": "fluent_bit", "name": "Fluent Bit", "type": epr_AT_SIEM,
        "detection_keys": ["fluent-bit", "fluentbit"],
        "process_names": ["fluent-bit"],
        "service_names": ["fluent-bit"],
        "reg_keys": [],
        "win_config_paths": [],
        "lin_config_paths": ["/etc/fluent-bit/fluent-bit.conf", "/etc/fluent-bit/outputs.conf"],
        "dest_patterns": [
            (r"Host\s+([^\s]+)[\s\S]{1,40}Port\s+([0-9]+)", "forwarding to"),
        ],
        "evtx_channels": [],
        "note": "Fluent Bit is shipping logs - check its downstream destination.",
    },
    {
        "id": "cribl_edge", "name": "Cribl Edge", "type": epr_AT_SIEM,
        "detection_keys": ["cribl", "cribl edge", "cribl stream"],
        "process_names": ["cribl"],
        "service_names": ["cribl"],
        "reg_keys": [],
        "win_config_paths": [r"C:\Program Files\Cribl\cribl\local\cribl\outputs.yml"],
        "lin_config_paths": ["/opt/cribl/local/cribl/outputs.yml"],
        "dest_patterns": [
            (r"host:\s*['\"]?([^'\"\s]+)['\"]?[\s\S]{1,60}port:\s*([0-9]+)", "forwarding to"),
        ],
        "evtx_channels": [],
        "note": "Cribl Edge is routing logs - check the Cribl leader and downstream destinations.",
    },
    # ---- XDR / cloud security agents ----
    {
        "id": "ms_sentinel_ama", "name": "Microsoft Sentinel / Azure Monitor Agent (AMA)", "type": epr_AT_XDR,
        "detection_keys": ["azure monitor agent", "azuremonitoragent", "ama",
                           "microsoft monitoring agent", "mma", "oms agent", "healthservice"],
        "process_names": ["MonAgentLauncher.exe", "MonAgentHost.exe", "HealthService.exe",
                          "MsSenseS.exe"],
        "service_names": ["AzureMonitorAgent", "HealthService", "MsSense"],
        "reg_keys": [
            r"HKLM\SOFTWARE\Microsoft\Azure Monitor Agent",
            r"HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager",
        ],
        "win_config_paths": [],
        "lin_config_paths": ["/var/opt/microsoft/azuremonitoragent/config/"],
        "dest_patterns": [],
        "evtx_channels": ["Microsoft-Windows-SENSE/Operational"],
        "note": "Azure Monitor/Sentinel agent is present - pull this host's events from Microsoft Sentinel "
                "or the Log Analytics workspace for full historical coverage.",
    },
    {
        "id": "ms_defender_cloud", "name": "Microsoft Defender for Cloud (MMA/AMA)", "type": epr_AT_XDR,
        "detection_keys": ["microsoft defender for cloud", "mma", "oms"],
        "process_names": ["HealthService.exe"],
        "service_names": ["HealthService"],
        "reg_keys": [r"HKLM\SOFTWARE\Microsoft\Microsoft Operations Manager"],
        "win_config_paths": [],
        "lin_config_paths": [],
        "dest_patterns": [],
        "evtx_channels": [],
        "note": "Microsoft Defender for Cloud agent - check Azure Security Center for alerts on this host.",
    },
    {
        "id": "wazuh_agent", "name": "Wazuh Agent", "type": epr_AT_WAZUH,
        "detection_keys": ["wazuh", "ossec", "wazuh agent"],
        "process_names": ["wazuh-agent.exe", "ossec-agent.exe", "wazuh-agent", "ossec-agentd"],
        "service_names": ["WazuhSvc", "OssecSvc"],
        "reg_keys": [r"HKLM\SOFTWARE\Wazuh"],
        "win_config_paths": [r"C:\Program Files (x86)\ossec-agent\ossec.conf"],
        "lin_config_paths": ["/var/ossec/etc/ossec.conf"],
        "dest_patterns": [
            (r"<address>([^<]+)</address>", "Wazuh manager at"),
            (r"<port>([0-9]+)</port>", "port"),
        ],
        "evtx_channels": [],
        "note": "Wazuh agent is present - check the Wazuh manager at the detected address for "
                "alerts and decoded events for this host.",
    },
    {
        "id": "qualys_cloud_agent", "name": "Qualys Cloud Agent", "type": epr_AT_CLOUD,
        "detection_keys": ["qualys cloud agent", "qualysagent"],
        "process_names": ["QualysAgent.exe", "qualys-cloud-agent"],
        "service_names": ["QualysAgent"],
        "reg_keys": [r"HKLM\SOFTWARE\Qualys"],
        "win_config_paths": [],
        "lin_config_paths": ["/etc/qualys/cloud-agent/"],
        "dest_patterns": [],
        "evtx_channels": [],
        "note": "Qualys Cloud Agent - check the Qualys VMDR/EDR portal for this asset's vulnerability "
                "and detection history.",
    },
    {
        "id": "tenable_nessus_agent", "name": "Tenable Nessus Agent", "type": epr_AT_CLOUD,
        "detection_keys": ["nessus agent", "tenable agent", "nessusagent"],
        "process_names": ["nessus-agent", "NessusAgent.exe"],
        "service_names": ["Tenable Nessus Agent"],
        "reg_keys": [],
        "win_config_paths": [],
        "lin_config_paths": ["/opt/nessus_agent/"],
        "dest_patterns": [],
        "evtx_channels": [],
        "note": "Tenable Nessus Agent - check Tenable.io/sc for this asset's scan history.",
    },
    {
        "id": "crowdstrike_logscale", "name": "CrowdStrike LogScale / Humio Collector", "type": epr_AT_SIEM,
        "detection_keys": ["logscale", "humio", "crowdstrike logscale"],
        "process_names": ["humio-log-collector", "logscale-collector"],
        "service_names": ["humio-log-collector"],
        "reg_keys": [],
        "win_config_paths": [],
        "lin_config_paths": ["/etc/humio-log-collector.conf"],
        "dest_patterns": [
            (r"url:\s*['\"]?([^'\"\s]+)['\"]?", "LogScale host"),
        ],
        "evtx_channels": [],
        "note": "CrowdStrike LogScale/Humio collector - query the LogScale instance for historical logs.",
    },
]

# Linux-specific syslog daemons (these don't appear on Windows)
epr_SYSLOG_PROFILES = [
    {
        "id": "rsyslog", "name": "rsyslog", "type": epr_AT_SYSLOG,
        "process_names": ["rsyslogd"],
        "config_paths": ["/etc/rsyslog.conf", "/etc/rsyslog.d/"],
        "dest_patterns": [
            (r"(?:@@?|action\(type=\"omfwd\"[^)]*target=\")([^\s\"]+)\"?\s+port=\"?([0-9]+)", "forwarding to"),
            (r"@@([^:]+):([0-9]+)", "TCP forwarding to"),
            (r"@([^:]+):([0-9]+)", "UDP forwarding to"),
        ],
        "note": "rsyslog is forwarding events - check the remote syslog collector for historical data.",
    },
    {
        "id": "syslog_ng", "name": "syslog-ng", "type": epr_AT_SYSLOG,
        "process_names": ["syslog-ng"],
        "config_paths": ["/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng.conf"],
        "dest_patterns": [
            (r"ip\(\"([^\"]+)\"\);\s*port\(([0-9]+)\)", "forwarding to"),
            (r"host\(['\"]([^'\"]+)['\"]\).*?port\(['\"]?([0-9]+)['\"]?\)", "forwarding to"),
        ],
        "note": "syslog-ng is forwarding events - check the remote syslog collector.",
    },
    {
        "id": "journald_remote", "name": "systemd-journal-remote / journal-upload", "type": epr_AT_SYSLOG,
        "process_names": ["systemd-journal-remote", "systemd-journal-upload"],
        "config_paths": ["/etc/systemd/journal-upload.conf", "/etc/systemd/journal-remote.conf"],
        "dest_patterns": [
            (r"URL\s*=\s*([^\s]+)", "journal remote destination"),
        ],
        "note": "systemd journal is being forwarded to a remote host.",
    },
    {
        "id": "auditd_audisp", "name": "auditd + audisp (audit remote plugin)", "type": epr_AT_SYSLOG,
        "process_names": ["auditd", "audispd"],
        "config_paths": ["/etc/audit/auditd.conf", "/etc/audisp/plugins.d/au-remote.conf",
                         "/etc/audit/plugins.d/au-remote.conf"],
        "dest_patterns": [
            (r"remote_server\s*=\s*([^\s]+)", "audit remote server"),
            (r"port\s*=\s*([0-9]+)", "port"),
        ],
        "note": "auditd is running - audit events may be forwarded to a remote host or SIEM.",
    },
]


def epr__read_config_file(path, log):
    """Safely read a text config file. Returns content string or empty string."""
    try:
        p = Path(path)
        if p.is_dir():
            content = ""
            for f in p.glob("**/*.conf"):
                try:
                    content += f.read_text(encoding="utf-8", errors="replace") + "\n"
                except Exception:
                    pass
            return content
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def epr__extract_destinations(config_text, dest_patterns, log):
    dests = []
    for pattern, label in dest_patterns:
        for m in re.finditer(pattern, config_text, re.IGNORECASE | re.MULTILINE):
            if m.lastindex and m.lastindex >= 2:
                dests.append(f"{label}: {m.group(1)}:{m.group(2)}")
            elif m.lastindex:
                dests.append(f"{label}: {m.group(1)}")
    return list(dict.fromkeys(dests))[:6]  # deduplicate, cap at 6


def epr__is_service_running_win(service_name):
    """Quick Windows service state check. Returns True/False/None(unknown)."""
    try:
        r = subprocess.run(f'sc query "{service_name}"', shell=True, capture_output=True,
                           text=True, timeout=10)
        return "running" in (r.stdout or "").lower()
    except Exception:
        return None


def epr__is_process_running_lin(proc_names):
    """Quick Linux process check via /proc."""
    try:
        running = set()
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                cmd = (pid_dir / "comm").read_text().strip()
                running.add(cmd.lower())
            except Exception:
                pass
        return any(p.lower().rstrip(".exe") in running for p in proc_names)
    except Exception:
        return None


def epr_detect_agents(base_dir, log, platform_override=None):
    import platform as _pf
    system = platform_override or _pf.system()
    results = []

    def check_profile(profile, config_paths, dest_patterns):
        """Returns a result dict if the agent is detected, else None."""
        found_by = []
        running = None
        destinations = []

        if system == "Windows":
            # Service check from live or from collected services artifact
            svc_dump = ""
            if base_dir:
                for f in ["artifacts\\services.txt", "artifacts/services.txt"]:
                    p = Path(base_dir) / f
                    svc_dump = epr__read_config_file(p, log)
                    if svc_dump:
                        break
            else:
                for svc in profile.get("service_names", []):
                    st = epr__is_service_running_win(svc)
                    if st is True:
                        running = True
                        found_by.append(f"service '{svc}' running")
                        break
                    elif st is False:
                        found_by.append(f"service '{svc}' installed (stopped)")
                        break

            if svc_dump:
                for svc in profile.get("service_names", []):
                    if svc.lower() in svc_dump.lower():
                        running = "running" in svc_dump[max(0,svc_dump.lower().find(svc.lower())-5):
                                                         svc_dump.lower().find(svc.lower())+200].lower()
                        found_by.append(f"service '{svc}' in services dump")
                        break

            # Process check from live or from tasklist artifact
            proc_dump = ""
            if base_dir:
                for f in ["artifacts\\processes.csv", "artifacts/processes.csv",
                          "artifacts\\tasklist.txt", "artifacts/tasklist.txt"]:
                    p = Path(base_dir) / f
                    proc_dump = epr__read_config_file(p, log)
                    if proc_dump:
                        break
            if proc_dump:
                for proc in profile.get("process_names", []):
                    if proc.lower() in proc_dump.lower():
                        found_by.append(f"process '{proc}' in process dump")
                        break

        elif system == "Linux":
            if not base_dir:
                running = epr__is_process_running_lin(profile.get("process_names", []))
                if running:
                    found_by.append("process running")
            else:
                proc_dump = ""
                for f in ["artifacts/processes.csv", "artifacts/process_list.txt"]:
                    p = Path(base_dir) / f
                    proc_dump = epr__read_config_file(p, log)
                    if proc_dump:
                        break
                if proc_dump:
                    for proc in profile.get("process_names", []):
                        if proc.lower() in proc_dump.lower():
                            found_by.append(f"process '{proc}' in process dump")
                            break

        # Config file check (works both live and artifact mode)
        for cfg_path in config_paths:
            full = Path(base_dir) / cfg_path.lstrip("/\\") if base_dir else Path(cfg_path)
            txt = epr__read_config_file(full, log)
            if txt:
                found_by.append(f"config: {cfg_path}")
                dests = epr__extract_destinations(txt, dest_patterns, log)
                destinations.extend(dests)
                break

        if not found_by:
            return None

        return {
            "id": profile["id"],
            "name": profile["name"],
            "type": profile["type"],
            "found_by": found_by[0],
            "running": running,
            "destinations": list(dict.fromkeys(destinations)),
            "note": profile.get("note", ""),
        }

    # Check AGENT_PROFILES (Windows + cross-platform)
    for profile in epr_AGENT_PROFILES:
        cfg_paths = (profile.get("win_config_paths", []) if system == "Windows"
                     else profile.get("lin_config_paths", []))
        r = check_profile(profile, cfg_paths, profile.get("dest_patterns", []))
        if r:
            results.append(r)

    # Check SYSLOG_PROFILES (Linux only)
    if system in ("Linux", "Darwin"):
        for profile in epr_SYSLOG_PROFILES:
            r = check_profile(profile, profile.get("config_paths", []),
                              profile.get("dest_patterns", []))
            if r:
                results.append(r)

    # Deduplicate
    seen, unique = set(), []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique.append(r)

    return unique


def epr_detect_telemetry_gaps(agents, edr_profiles, events, coverage, log):
    gaps = []
    all_profiles = edr_profiles + [a for a in agents if a.get("evtx_channels")]

    # Build a set of EVTX channels that actually had events
    channels_with_events = set()
    for e in events:
        if e.get("log"):
            channels_with_events.add(e["log"].lower().replace(".evtx", "").replace("_", "-"))
    for fn, c in coverage.items():
        if c.get("records", 0) > 0:
            channels_with_events.add(fn.lower().replace(".evtx", "").replace("_", "-"))

    for profile in all_profiles:
        chs = profile.get("evtx_channels", [])
        if not chs:
            continue
        missing = []
        for ch in chs:
            safe = ch.lower().replace("/", "_").replace(" ", "-")
            if not any(safe in existing or ch.lower() in existing
                       for existing in channels_with_events):
                missing.append(ch)
        if missing:
            gaps.append({
                "agent": profile.get("name", profile.get("id", "?")),
                "missing_channels": missing,
                "message": (f"Agent is present but its EVTX channel(s) "
                           f"{missing} had no events in the collected evidence. "
                           f"Possible causes: channel disabled, log cleared/tampered, "
                           f"agent stopped before collection, or channel name mismatch."),
            })
    return gaps


# --------------------------------------------------------------------------- evidence folder normalizer
def epr_normalize_evidence_base(base, out, log):
    import os as _os
    base = Path(base)
    try:
        if not base.exists() or not base.is_dir():
            return base
        entries = list(base.iterdir())
    except Exception as ex:
        log("WARN", f"Could not scan evidence base {base}: {ex}")
        return base
    flat = [p for p in entries if p.is_file() and "\\" in p.name]
    if not flat:
        return base
    norm = Path(out) / "_normalized_evidence"
    made = 0
    try:
        for p in flat:
            parts = p.name.split("\\")
            sub = parts[0]
            fname = parts[-1] if len(parts) == 2 else "_".join(parts[1:])
            dest_dir = norm / sub
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / fname
            if dest.exists():
                continue
            try:
                _os.symlink(p.resolve(), dest)
            except (OSError, NotImplementedError):
                import shutil as _sh
                _sh.copy2(p, dest)
            made += 1
        # carry through everything else (real subfolders, hashes.csv, ...) unchanged so nothing is lost
        for p in entries:
            if "\\" not in p.name:
                dest = norm / p.name
                if not dest.exists():
                    try:
                        _os.symlink(p.resolve(), dest)
                    except (OSError, NotImplementedError):
                        pass
    except Exception as ex:
        log("WARN", f"Evidence normalization failed ({ex}); continuing with the original folder")
        return base
    if made:
        log("OK", f"Normalized {made} flattened 'folder\\\\file' name(s) under {base.name} into real "
                  f"subfolders at {norm} (original evidence untouched)")
        return norm
    return base


# --------------------------------------------------------------------------- public API
def epr_generate(results, out_dir, evtx_dir=None, base=None, memory_dir=None, edr_csv=None, hayabusa_csv=None, log=None,
             use_ai=True, ai_provider=None, ollama_host=None, ollama_model=None,
             ai_key=None, ai_model=None, gemini_key=None, gemini_model=None,
             meta_key=None, meta_model=None, meta_host=None, interactive=True,
             extra_events=None, extra_coverage=None, ai_cfg=None, registry_dir=None, live_notes=None):
    log = log or (lambda lvl, msg: print(f"[{lvl}] {msg}"))
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    log("HEAD", "Entry-point & correlation analysis")
    events, coverage = ([], {})
    if evtx_dir and Path(evtx_dir).exists():
        events, coverage = epr_collect_events(evtx_dir, log)
    if extra_events:
        events = list(events) + list(extra_events)
    if extra_coverage:
        coverage = dict(coverage); coverage.update(extra_coverage)
    hay = hayabusa_csv or (out / "hayabusa_timeline.csv")
    hev = epr_load_hayabusa(hay)
    seen = {(e["kind"], e["ts"]) for e in events}
    events += [e for e in hev if (e["kind"], e["ts"]) not in seen]
    events.sort(key=lambda e: e["ts"])

    detections = epr_load_edr_csv(edr_csv or (out / "edr_detections.csv"))
    own = epr_aggregate_detections(events)
    known = {(d["name"], d["path"].lower()) for d in detections}
    detections += [d for d in own if (d["name"], d["path"].lower()) not in known]
    have_tamper = any(d["kind"] == "tamper" for d in detections)
    if not have_tamper:
        detections += epr_tamper_from_events(events)

    evidence_dirs = []
    if base and Path(base).exists():
        evidence_dirs = [p.name for p in Path(base).rglob("*") if p.is_dir()][:500] + [p.name for p in Path(base).iterdir()]
    collection = None
    m = re.search(r"(\d{8})_(\d{6})", str(base or ""))
    if m:
        collection = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
    ctx = {"base": str(base) if base else None, "memory_dir": memory_dir, "collection": collection, "evtx_given": bool(evtx_dir), "evidence_dirs": evidence_dirs}
    ep = epr_find_entry_point(events, detections, coverage, ctx)

    host = Counter([e["host"] for e in events if e["host"]]).most_common(1)
    host = host[0][0] if host else next((d["endpoint"] for d in detections if d["endpoint"]), "") or (Path(str(base)).name if base else "unknown host")
    meta = {"host": host, "generated": datetime.now().strftime(epr_FMT), "evidence": str(base or evtx_dir or "(CSV inputs only)"),
            "collection": collection, "collection_txt": (epr_fmt(collection) + " (folder name, collector local time)") if collection else "not recorded",
            "inputs": f"{sum(len(results.get(k, [])) for k in ('critical','high','medium')):,} findings, {len(events):,} re-extracted events, {len(detections)} EDR records"}
    # Telemetry stack inventory: detect SIEM forwarders, XDR, cloud agents, syslog daemons
    log("INFO", "Scanning for telemetry agents (SIEM forwarders, XDR, syslog) ...")
    agents = epr_detect_agents(evtx_dir or base, log)
    if agents:
        log("OK", f"Telemetry agents found: " + ", ".join(a["name"] for a in agents))
    else:
        log("INFO", "No additional telemetry agents detected")
    telemetry_gaps = epr_detect_telemetry_gaps(agents, detections, events, coverage, log)
    if telemetry_gaps:
        for g in telemetry_gaps:
            log("WARN", f"Telemetry gap: {g['agent']} - {g['message'][:120]}")

    chart = epr_make_chart(events, detections, ep, coverage, collection, str(out / "_timeline.png"))

    # ---- cross-source correlation (memory <-> hives <-> hive logs <-> event logs)
    cor = None
    try:
        vol_dir = out / "volatility"
        cor = cor_correlate(str(vol_dir) if vol_dir.exists() else None, evtx_dir=evtx_dir, registry_dir=registry_dir, base=base, log=log)
        ce = cor["entry"]
        if ce["status"] in ("DETERMINED", "PROBABLE") and ce.get("time") and (not ep.get("access_event") or ep["status"] in ("NOT DETERMINED", "POSSIBLE ENTRY POINT")):
            ep["status"] = "ENTRY POINT IDENTIFIED" if ce["status"] == "DETERMINED" else "PROBABLE ENTRY POINT"
            ep["confidence"], ep["vector"] = ce["confidence"], ce["vector"]
            ep["access_event"] = {"time": ce["time"], "text": ce["anchor"], "log": ce.get("via", "correlation")}
            for t, src, det in ce["evidence"][:12]:
                if t: ep["evidence"].append((t, f"[{src}] {det}"))
        if ce.get("chain"):
            ep["reasons"].append(("Correlated process chain", " -> ".join(ce["chain"])))
        for area, gap in cor["gaps"]:
            ep["reasons"].append((f"Correlation gap: {area}", gap))
        try: uni_scope("windows", base, str(out / "volatility"), cor, out)
        except Exception as _e: log("WARN", f"Scope summary failed: {_e}")
        uni_save_cor(cor, out)
    except Exception as _ex:
        log("WARN", f"Correlation step failed: {type(_ex).__name__}: {_ex}")
    ai_text, ai_label, ai_stats = None, "", None
    ollama_host = ollama_host or os.environ.get("OLLAMA_HOST") or epr_OLLAMA_HOST_DEFAULT
    ollama_model = ollama_model or os.environ.get("OLLAMA_MODEL") or epr_OLLAMA_MODEL_DEFAULT
    ai_key = ai_key or os.environ.get("ANTHROPIC_API_KEY")
    gemini_key = gemini_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    meta_key = meta_key or os.environ.get("META_API_KEY") or os.environ.get("LLAMA_API_KEY")
    ai_provider = (ai_provider or os.environ.get("EPR_AI_PROVIDER") or "auto").lower()
    if use_ai:
        cfg, skipped_by_choice = ai_cfg, False
        if cfg is None and interactive and ai_provider == "auto":  # only prompt when nothing was explicitly forced via flags/env
            picked = epr_interactive_ai_setup(log, ollama_model, ai_model, gemini_model, meta_model, ollama_host, meta_host)
            if picked == "skip":
                skipped_by_choice = True
            elif picked:
                cfg = picked
            # picked is None -> person hit Enter, or not a real terminal -> fall through to auto-detect below
        if cfg is None and not skipped_by_choice:
            cfg = epr_resolve_ai_cfg(log, ai_provider, ollama_host, ollama_model, ai_key, ai_model,
                                 gemini_key, gemini_model, meta_key, meta_model, meta_host)
        if cfg:
            ai_text, ai_stats = epr_full_artifact_ai_analysis(cfg, meta, ep, detections, events, coverage, results, log)
            ai_label = f"{epr_AI_LABELS[cfg['provider']]} ({cfg['model']})"
        if not ai_text and not skipped_by_choice:
            log("INFO", "Analyst review skipped - no engine selected/reachable; report continues with the rule-based analysis only")
    _cfg_final = locals().get("cfg")
    if use_ai and _cfg_final:
        try:
            _rv = cor_review(_cfg_final, cor, results, log, live_notes)
            if _rv:
                ai_text = _rv
            elif ai_text and not uni_review_ok(ai_text):
                ai_text = None
        except Exception as _ex:
            log("WARN", f"Analyst review failed: {type(_ex).__name__}: {_ex}")
    if ai_text:
        try: (out / "analyst_review.txt").write_text(ai_text, encoding="utf-8")
        except Exception: pass
    pdf = None   # one combined report is built by the reporting module (entry point is a section of it)
    epr_write_detailed_csv(results, out / "findings_detailed.csv")

    def ser(o):
        return o.strftime(epr_FMT) if isinstance(o, datetime) else str(o)
    with open(out / "entry_point.json", "w") as f:
        json.dump({"entry_point": ep, "detections": detections, "coverage": coverage, "host": host}, f, indent=2, default=ser)
    log("OK", f"Entry point: {ep['status']}" + (f" at {epr_fmt(ep['anchor']['time'])}" if ep.get("anchor") else ""))
    return {"pdf": pdf, "json": str(out / "entry_point.json"), "csv": str(out / "findings_detailed.csv"), "entry_point": ep, "correlation": cor, "ai_text": ai_text, "ai_stats": ai_stats}


# ═══════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE (cor_*)  — rule-based, no external tools needed
#   memory (processes / cmdline / network / registry)  <->  on-disk registry hives
#   <->  hive transaction logs  <->  event logs  ->  process chains + entry point
# ═══════════════════════════════════════════════════════════════════════════
import ntpath as _cor_nt

cor_SUSP_PATH = re.compile(r"\\(users\\[^\\]+\\(appdata|downloads|desktop|documents|music|pictures|videos)|programdata|windows\\temp|"
                           r"temp|perflogs|users\\public|\$recycle\.bin|windows\\tasks|windows\\debug)\\", re.I)
cor_FILE_RX = re.compile(r"[A-Za-z]:\\[^\"'<>|\r\n\t,;]+?\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|com|lnk|sys)\b|"
                         r"[\w\-. ]+\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|sys)\b", re.I)
cor_IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
cor_BAD_NAME = re.compile(r"(?<![A-Za-z0-9_])(mimikatz|meterpreter|pwdump|netcat|(?:nc|ncat|wce|procdump(?:64)?|psexec(?:svc)?|"
                          r"lazagne|rubeus|sharphound|cobaltstrike|beacon|plink|chisel|ngrok)\.exe)(?![A-Za-z0-9_])", re.I)
cor_RANSOM_CMD = re.compile(r"(vssadmin[^\n]*delete[^\n]*shadows|wmic[^\n]*shadowcopy[^\n]*delete|bcdedit[^\n]*(recoveryenabled|bootstatuspolicy)|"
                            r"wbadmin[^\n]*delete|cipher[^\n]*/w|wevtutil[^\n]*\bcl\b|powershell[^\n]*(-enc\b|-encodedcommand|downloadstring|"
                            r"invoke-expression|iex\b)|certutil[^\n]*(-urlcache|-decode)|mshta[^\n]*(http|javascript)|rundll32[^\n]*javascript|"
                            r"net\s+user[^\n]*/add|reg(?:\.exe)?\s+add[^\n]*\\run)", re.I)
cor_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe", "acrobat.exe", "msaccess.exe", "mspub.exe"}
cor_BROWSER = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"}
cor_WEBSVC = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "tomcat8.exe", "java.exe", "javaw.exe", "sqlservr.exe", "php-cgi.exe", "php.exe"}
cor_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
              "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe"}
cor_OSNAMES = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
               "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "dwm.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe", "rundll32.exe",
               "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "reg.exe", "schtasks.exe", "net.exe", "net1.exe",
               "wmic.exe", "sc.exe", "taskkill.exe", "vssadmin.exe", "bcdedit.exe", "wevtutil.exe", "cipher.exe", "whoami.exe", "ipconfig.exe",
               "ping.exe", "tasklist.exe", "systeminfo.exe", "notepad.exe", "mmc.exe", "msiexec.exe", "dllhost.exe", "runtimebroker.exe",
               "searchindexer.exe", "spoolsv.exe", "wuauclt.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "microsoft.exe"}
cor_PARENT_RULES = {"svchost.exe": {"services.exe"}, "lsass.exe": {"wininit.exe"}, "services.exe": {"wininit.exe"},
                    "smss.exe": {"system"}, "wininit.exe": {"smss.exe"}, "csrss.exe": {"smss.exe"}}
cor_SOFT_KEYS = [r"Microsoft\Windows\CurrentVersion\Run", r"Microsoft\Windows\CurrentVersion\RunOnce",
                 r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                 r"Microsoft\Windows NT\CurrentVersion\Winlogon", r"Microsoft\Windows NT\CurrentVersion\Windows"]
cor_GENERIC_BASE = {"update.exe", "setup.exe", "install.exe", "installer.exe", "helper.exe", "service.exe", "launcher.exe", "updater.exe", "app.exe",
                    "main.exe", "run.exe", "start.exe", "agent.exe", "client.exe", "host.exe", "tool.exe", "task.exe"}
cor_ACQ_TOOLS = re.compile(r"(winpmem|dumpit|magnetramcapture|ramcapture|belkasoft|ftkimager|osforensics|velociraptor|kape|memoryze|avml|lime-forensics)", re.I)
cor_MALFIND_FP = {"explorer.exe", "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "svchost.exe",
                  "winlogon.exe", "spoolsv.exe", "onedrive.exe", "mmc.exe", "runtimebroker.exe", "textinputhost.exe", "searchhost.exe", "teams.exe",
                  "code.exe", "dwm.exe", "sihost.exe", "taskhostw.exe", "searchindexer.exe", "csrss.exe", "services.exe", "lsass.exe", "smss.exe"}
cor_BENIGN_DIR = re.compile(r"^(?:\\\?\?\\)?(?:[A-Za-z]:)?\\?(?:windows|program files(?: \(x86\))?|programdata\\microsoft\\windows defender)\\", re.I)
cor_BENIGN_APPDATA = re.compile(r"\\appdata\\local\\microsoft\\(?:onedrive|teams|edge|windowsapps|office)\\", re.I)
cor_HIVE_NAMES = {"system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve"}


def cor__ts(v):
    try:
        v = str(v).strip()
        if not v or v in ("-", "N/A", "None"): return None
        return epr_parse_ts(v)
    except Exception:
        return None


def cor__base(p):
    p = (p or "").strip().strip('"').strip("'")
    return _cor_nt.basename(p).lower() if p else ""


def cor__table(path):
    try: lines = Path(path).read_text(errors="ignore").splitlines()
    except Exception: return [], []
    hdr, rows = None, []
    for ln in lines:
        if "\t" not in ln: continue
        parts = [x.strip() for x in ln.split("\t")]
        if hdr is None: hdr = [h.lower() for h in parts]
        else: rows.append(parts)
    return hdr or [], rows


def cor__col(hdr, *names):
    for n in names:
        if n.lower() in hdr: return hdr.index(n.lower())
    return None


def cor__cell(r, i):
    return r[i] if i is not None and i < len(r) else ""


def cor_is_browserlike(name):
    return (name or "").lower() in cor_BROWSER


def cor_reg_suspicious(data):
    d = data or ""
    if not d: return ""
    if cor_BENIGN_APPDATA.search(d) or cor_BENIGN_DIR.search(d.strip('"')): return ""
    if cor_SUSP_PATH.search(d): return "autorun points to user-writable path"
    if cor_RANSOM_CMD.search(d) or any(p.search(d) for p, _ in epr_MAL_PATTERNS): return "autorun runs a malicious command pattern"
    if cor_BAD_NAME.search(d): return "autorun references known attacker tool"
    if re.search(r"(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)\.exe", d, re.I) and re.search(r"(http|\.ps1|\.vbs|\.js|-enc)", d, re.I):
        return "autorun launches script host with payload"
    return ""


def cor_find_hives(root):
    out, logs = [], []
    if not root or not Path(root).exists(): return out, logs
    n = 0
    for p in Path(root).rglob("*"):
        n += 1
        if n > 20000: break
        try:
            if not p.is_file(): continue
            ln = p.name.lower()
            if ln.endswith((".log1", ".log2")) or (ln.endswith(".log") and any(ln.startswith(h) for h in cor_HIVE_NAMES)):
                logs.append(p); continue
            if p.stat().st_size < 8192: continue
            if ln in cor_HIVE_NAMES or ln.endswith((".hiv", ".hive", ".hve", ".dat")) or ln.startswith(("ntuser", "usrclass")):
                with open(p, "rb") as fh:
                    if fh.read(4) == b"regf": out.append(p)
        except Exception:
            continue
    return out, logs


def cor__decode(v):
    try:
        x = v.value()
    except Exception:
        return ""
    if isinstance(x, bytes):
        try: x = x.decode("utf-16le", "ignore").strip("\x00")
        except Exception: x = x.hex()[:80]
    if isinstance(x, list): x = " ".join(str(i) for i in x)
    return str(x)


def cor_read_hives(hive_files, log):
    """Read autorun / service / winlogon / IFEO values from the on-disk hives."""
    entries = []
    try:
        from Registry import Registry as R
    except ImportError:
        try: subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q", "python-registry"],
                            capture_output=True, timeout=120)
        except Exception: pass
        try: from Registry import Registry as R
        except ImportError:
            log("WARN", "python-registry unavailable - on-disk hive cross-check skipped"); return entries
    for hp in hive_files:
        up = hp.name.upper()
        try: reg = R.Registry(str(hp))
        except Exception as ex:
            log("WARN", f"  hive {hp.name}: {ex}"); continue

        def walk_values(path, kind):
            try: k = reg.open(path)
            except Exception: return
            for v in k.values():
                entries.append({"hive": hp.name, "key": path, "name": v.name(), "data": cor__decode(v), "lastwrite": k.timestamp(), "kind": kind})

        if "SYSTEM" in up:
            for cs in ("ControlSet001", "ControlSet002"):
                try: svcs = reg.open(f"{cs}\\Services")
                except Exception: continue
                for sk in svcs.subkeys():
                    ip = sd = ""
                    start = ""
                    for v in sk.values():
                        if v.name().lower() == "imagepath": ip = cor__decode(v)
                        elif v.name().lower() == "start": start = cor__decode(v)
                    try:
                        for v in sk.subkey("Parameters").values():
                            if v.name().lower() == "servicedll": sd = cor__decode(v)
                    except Exception: pass
                    if ip or sd:
                        entries.append({"hive": hp.name, "key": f"{cs}\\Services\\{sk.name()}", "name": sk.name(), "data": (sd or ip),
                                        "lastwrite": sk.timestamp(), "kind": "service", "start": start})
                break
        elif "SOFTWARE" in up:
            for p_ in cor_SOFT_KEYS: walk_values(p_, "autorun")
            try:
                ifeo = reg.open(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
                for sk in ifeo.subkeys():
                    for v in sk.values():
                        if v.name().lower() == "debugger":
                            entries.append({"hive": hp.name, "key": f"IFEO\\{sk.name()}", "name": "Debugger", "data": cor__decode(v),
                                            "lastwrite": sk.timestamp(), "kind": "ifeo"})
            except Exception: pass
        elif "NTUSER" in up:
            for p_ in cor_SOFT_KEYS:
                if p_.startswith("Wow6432"): continue
                walk_values("Software\\" + p_, "autorun")
    log("INFO", f"  on-disk hives: {len(hive_files)} parsed, {len(entries)} autorun/service values collected")
    return entries


def cor_search_hive_logs(log_files, tokens, log, max_mb=300):
    """Search raw hive transaction logs (.LOG1/.LOG2) for tokens as ASCII or UTF-16LE. -> {token: [logname,...]}"""
    found = defaultdict(list)
    toks = [t for t in tokens if t and len(t) >= 4]
    if not toks: return found
    for lf in log_files:
        try:
            if lf.stat().st_size > max_mb * 1048576: continue
            data = lf.read_bytes().lower()
        except Exception:
            continue
        for t in toks:
            tl = t.lower()
            if tl.encode("utf-16le", "ignore") in data or tl.encode("ascii", "ignore") in data:
                if lf.name not in found[t]: found[t].append(lf.name)
    return found


# ------------------------------------------------------------------ event-log pivot scan
def cor_scan_evtx(evtx_dir, tokens, log, max_sec=None):
    """Single pass over every .evtx: events matching any token + process-creation + logon tables."""
    res = {"hits": [], "procs": [], "logons": {}, "coverage": {}, "scanned": 0, "partial": False, "hosts": Counter()}
    if not evtx_dir or not Path(evtx_dir).exists(): return res
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        try: subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q", "python-evtx"], capture_output=True, timeout=180)
        except Exception: pass
        try: from Evtx.Evtx import Evtx
        except ImportError:
            log("WARN", "python-evtx missing - event-log pivot skipped (pip install python-evtx)"); return res
    toks = sorted({t for t in tokens if t and len(t) >= 4}, key=len, reverse=True)
    from xml.sax.saxutils import escape as _x
    alts = set()
    for t in toks:
        alts.add(re.escape(t)); alts.add(re.escape(_x(t)))
    rx = re.compile("|".join(sorted(alts, key=len, reverse=True)), re.I) if alts else None
    max_sec = max_sec or int(os.environ.get("COR_EVTX_MAX_SEC", "1800"))
    t0 = time.time()
    per_tok = Counter()
    for fp in sorted(Path(evtx_dir).rglob("*.evtx")):
        first = last = None; n = 0
        try:
            with Evtx(str(fp)) as lf:
                for rec in lf.records():
                    if time.time() - t0 > max_sec:
                        res["partial"] = True; break
                    try: xml = rec.xml()
                    except Exception: continue
                    n += 1
                    m_eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                    if not m_eid: continue
                    eid = int(m_eid.group(1))
                    is_proc = eid in (4688, 1) and ("Sysmon" in xml or eid == 4688)
                    is_logon = eid == 4624
                    matched = rx.findall(xml) if rx else []
                    if not (matched or is_proc or is_logon): continue
                    ev = epr_parse_event_xml(xml)
                    if not ev or not ev["ts"]: continue
                    if ev.get("computer"): res["hosts"][ev["computer"]] += 1
                    first = ev["ts"] if first is None or ev["ts"] < first else first
                    last = ev["ts"] if last is None or ev["ts"] > last else last
                    d = ev["data"]
                    if is_proc:
                        if eid == 4688:
                            rec_p = {"ts": ev["ts"], "host": ev["computer"], "pid": cor__hex(epr__g(d, "NewProcessId")), "ppid": cor__hex(epr__g(d, "ProcessId")),
                                     "image": epr__g(d, "NewProcessName"), "cmd": epr__g(d, "CommandLine"), "parent": epr__g(d, "ParentProcessName"),
                                     "logon": epr__g(d, "SubjectLogonId"), "user": epr__g(d, "SubjectUserName"), "log": fp.name, "eid": 4688}
                        else:
                            rec_p = {"ts": ev["ts"], "host": ev["computer"], "pid": cor__hex(epr__g(d, "ProcessId")), "ppid": cor__hex(epr__g(d, "ParentProcessId")),
                                     "image": epr__g(d, "Image"), "cmd": epr__g(d, "CommandLine"), "parent": epr__g(d, "ParentImage"),
                                     "logon": epr__g(d, "LogonId"), "user": epr__g(d, "User"), "log": fp.name, "eid": 1}
                        if len(res["procs"]) < 400000: res["procs"].append(rec_p)
                    if is_logon:
                        lid = epr__g(d, "TargetLogonId")
                        if lid and len(res["logons"]) < 300000:
                            res["logons"][lid.lower()] = {"ts": ev["ts"], "type": epr__g(d, "LogonType"), "user": epr__g(d, "TargetUserName"),
                                                          "domain": epr__g(d, "TargetDomainName"), "ip": epr__g(d, "IpAddress"),
                                                          "ws": epr__g(d, "WorkstationName"), "log": fp.name}
                    if matched:
                        key = (matched[0] or "").lower()
                        if per_tok[key] < 60:
                            per_tok[key] += 1
                            res["hits"].append({"ts": ev["ts"], "eid": eid, "log": fp.name, "host": ev["computer"], "data": d,
                                                "matched": sorted({x.lower() for x in matched})[:5]})
        except Exception as ex:
            log("WARN", f"  {fp.name}: {ex}")
        res["coverage"][fp.name] = {"first": first, "last": last, "records": n}
        res["scanned"] += 1
        if res["partial"]:
            log("WARN", f"  event-log pivot stopped after {max_sec}s (set COR_EVTX_MAX_SEC to extend)"); break
    log("INFO", f"  event-log pivot: {res['scanned']} file(s), {len(res['hits'])} matching events, {len(res['procs'])} process-creation events, "
                f"{len(res['logons'])} logons indexed")
    return res


def cor__hex(v):
    try:
        v = str(v).strip()
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except Exception:
        return 0


# ---- part 1: OS profiles + memory loader generalisation + persistence/log adapters
import gzip as _cor_gzip, plistlib as _cor_plist

cor_LIN_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "python", "python2", "python3", "perl", "ruby", "php", "nc", "ncat", "socat", "node", "osascript"}
cor_LIN_WEB = {"nginx", "apache2", "httpd", "php-fpm", "php-fpm8", "php-fpm7", "php", "node", "java", "tomcat", "mysqld", "mariadbd", "redis-server",
               "postgres", "gunicorn", "uwsgi", "jenkins", "docker-proxy", "dockerd"}
cor_LIN_OSNAMES = {"systemd", "init", "kthreadd", "sshd", "sshd-session", "bash", "sh", "dash", "zsh", "cron", "crond", "atd", "rsyslogd", "dbus-daemon",
                   "login", "sudo", "su", "ssh", "agetty", "getty", "systemd-journald", "systemd-logind", "systemd-udevd", "networkd-dispatcher",
                   "python", "python3", "perl", "launchd", "kernel_task", "loginwindow", "finder", "dock", "terminal", "windowserver", "mds",
                   "mds_stores", "syslogd", "notifyd", "securityd", "cfprefsd", "distnoted", "coreaudiod", "sudo.bin", "unattended-upgr", "snapd"}
cor_LIN_BAD = re.compile(r"(?<![A-Za-z0-9_])(mimipenguin|pypykatz|linpeas(?:\.sh)?|linenum(?:\.sh)?|msfconsole|msfvenom|meterpreter|xmrig|kinsing|kdevtmpfsi|"
                         r"cryptcat|socat|hydra|medusa|masscan|zmap|arp-scan|nmap|chisel|ngrok|pspy(?:64)?|diamorphine|reptile|azazel|beurk|suterusu|"
                         r"mettle|empire|sliver|cobaltstrike|beacon)(?![A-Za-z0-9_])", re.I)
cor_LIN_SUSP_PATH = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/run/shm|/Users/Shared|/private/tmp|/private/var/tmp)/|/\.[A-Za-z0-9_][^/]*/", re.I)
cor_LIN_PERSIST_CMD = re.compile(r"(crontab\s+-[ei]|>>?\s*/etc/cron|authorized_keys|rc\.local|ld\.so\.preload|systemctl\s+(?:enable|daemon-reload)|"
                                 r"update-rc\.d|chkconfig|launchctl\s+(?:load|bootstrap)|LaunchAgents|LaunchDaemons|\.bashrc|\.profile|\.zshrc|"
                                 r"/etc/profile\.d|useradd|adduser|usermod|visudo|sudoers)", re.I)
cor_LOG_RX = re.compile(r"(auth|secure|syslog|messages|audit|cron|access|error|system|install|kern|daemon|boot|\.log)", re.I)
_COR_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def cor_profile(os_type):
    o = (os_type or "windows").lower()
    if o in ("linux", "kali", "ubuntu", "centos", "debian"):
        return {"os": "linux", "shells": cor_LIN_SHELLS, "web": cor_LIN_WEB, "office": set(), "browser": {"firefox", "chrome", "chromium"},
                "osnames": cor_LIN_OSNAMES, "bad": cor_LIN_BAD, "susp_path": cor_LIN_SUSP_PATH, "remote_types": ("ssh",),
                "store": "Persistence file", "logs": "System log", "parent_rules": {}}
    if o in ("macos", "mac", "darwin"):
        return {"os": "macos", "shells": cor_LIN_SHELLS, "web": cor_LIN_WEB, "office": {"microsoft word", "microsoft excel", "microsoft powerpoint", "preview", "mail", "microsoft outlook"},
                "browser": {"safari", "google chrome", "firefox", "microsoft edge", "brave browser"},
                "osnames": cor_LIN_OSNAMES, "bad": cor_LIN_BAD, "susp_path": cor_LIN_SUSP_PATH, "remote_types": ("ssh",),
                "store": "Persistence file", "logs": "System log", "parent_rules": {}}
    return {"os": "windows", "shells": cor_SHELLS, "web": cor_WEBSVC, "office": cor_OFFICE, "browser": cor_BROWSER, "osnames": cor_OSNAMES,
            "bad": cor_BAD_NAME, "susp_path": cor_SUSP_PATH, "remote_types": ("3", "10"), "store": "Registry hive", "logs": "Event log",
            "parent_rules": cor_PARENT_RULES}


def cor_cmd_suspicious(prof, text):
    """True/'reason' if a command / autorun line looks malicious for this OS."""
    t = text or ""
    if prof["os"] == "windows":
        return cor_reg_suspicious(t)
    for pat, nm in SUSP_CMDS:
        if pat.search(t): return f"suspicious command pattern: {nm}"
    if prof["bad"].search(t): return "references known attacker tool"
    if re.search(r"(?:^|[\s;|&=\"'])(?:/tmp|/var/tmp|/dev/shm|/run/shm|/Users/Shared|/private/tmp)/", t): return "runs from world-writable location"
    if re.search(r"(?:curl|wget)[^|;\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh", t, re.I): return "download piped to shell"
    if re.search(r"osascript[^\n]*(?:do shell script|curl)", t, re.I): return "osascript downloads/executes"
    return ""


def cor__log_ts(line, year_hint):
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", line)
    if m:
        try: return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        except Exception: pass
    m = re.search(r"audit\((\d{9,11})\.\d+:", line)
    if m:
        try: return datetime(1970, 1, 1) + timedelta(seconds=int(m.group(1)))
        except Exception: pass
    m = re.search(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})", line)
    if m and m.group(2) in _COR_MON:
        try: return datetime.strptime(f"{m.group(3)}-{_COR_MON[m.group(2)]:02d}-{m.group(1)} {m.group(4)}", "%Y-%m-%d %H:%M:%S")
        except Exception: pass
    m = re.match(r"\s*(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", line)
    if m and m.group(1) in _COR_MON:
        try: return datetime.strptime(f"{year_hint}-{_COR_MON[m.group(1)]:02d}-{int(m.group(2)):02d} {m.group(3)}", "%Y-%m-%d %H:%M:%S")
        except Exception: pass
    return None


def cor__read_lines(path, max_bytes=300 * 1048576):
    try:
        ln = str(path).lower()
        if ln.endswith(".gz"):
            with _cor_gzip.open(path, "rb") as f: data = f.read(max_bytes)
        else:
            with open(path, "rb") as f: data = f.read(max_bytes)
        return data.decode("utf-8", "ignore").splitlines()
    except Exception:
        return []


def cor_read_persistence(os_type, base, log):
    """Linux/macOS persistence stores (cron, systemd, rc, ld.so.preload, authorized_keys, shell rc, launchd plists)."""
    prof = cor_profile(os_type)
    entries = []
    if not base or not Path(base).exists(): return entries
    n = 0
    for p in Path(base).rglob("*"):
        n += 1
        if n > 60000: break
        try:
            if not p.is_file() or p.stat().st_size > 5 * 1048576: continue
            pl = str(p).lower().replace("\\", "/"); nm = p.name.lower()
            mt = datetime.fromtimestamp(p.stat().st_mtime)
        except Exception:
            continue
        kind = None
        if nm.endswith(".plist") and ("launchagents" in pl or "launchdaemons" in pl or "startupitems" in pl): kind = "launchd"
        elif "/cron" in pl or nm in ("crontab", "anacrontab"): kind = "cron"
        elif nm.endswith((".service", ".timer")) and "systemd" in pl: kind = "systemd"
        elif nm in ("rc.local",) or "/init.d/" in pl: kind = "init"
        elif nm == "ld.so.preload": kind = "preload"
        elif nm == "authorized_keys" or nm == "authorized_keys2": kind = "ssh_key"
        elif nm in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_login") or "/profile.d/" in pl: kind = "shellrc"
        if not kind: continue
        try:
            if kind == "launchd":
                pdict = _cor_plist.loads(p.read_bytes())
                prog = " ".join(pdict.get("ProgramArguments") or ([pdict["Program"]] if pdict.get("Program") else []))
                entries.append({"hive": p.name, "key": str(p), "name": pdict.get("Label", p.stem), "data": prog, "lastwrite": mt, "kind": kind,
                                "runatload": bool(pdict.get("RunAtLoad"))})
                continue
        except Exception:
            pass
        for i, line in enumerate(cor__read_lines(p, 2 * 1048576)[:3000], 1):
            t = line.strip()
            if not t or t.startswith("#"): continue
            if kind == "systemd" and not re.match(r"(Exec\w+|ExecStart)\s*=", t, re.I): continue
            if kind == "shellrc" and not cor_cmd_suspicious(prof, t): continue
            if kind == "ssh_key":
                parts = t.split()
                nm2 = parts[-1] if len(parts) > 2 else f"key{i}"
                entries.append({"hive": p.name, "key": str(p), "name": nm2, "data": t[:220], "lastwrite": mt, "kind": kind}); continue
            entries.append({"hive": p.name, "key": str(p), "name": f"{p.name}:{i}", "data": t[:300], "lastwrite": mt, "kind": kind})
    log("INFO", f"  persistence stores: {len(entries)} entr(ies) from cron/systemd/launchd/rc/ssh/shell files")
    return entries


def cor_scan_textlogs(os_type, base, tokens, log, max_sec=None):
    """Linux/macOS system logs -> same structure as cor_scan_evtx (hits / procs / logons / coverage)."""
    res = {"hits": [], "procs": [], "logons": {}, "coverage": {}, "scanned": 0, "partial": False, "hosts": Counter()}
    if not base or not Path(base).exists(): return res
    toks = sorted({t for t in tokens if t and len(t) >= 4}, key=len, reverse=True)
    rx = re.compile("|".join(re.escape(t) for t in toks), re.I) if toks else None
    max_sec = max_sec or int(os.environ.get("COR_EVTX_MAX_SEC", "1800"))
    t0 = time.time(); per_tok = Counter(); host = "host"
    aud = {}
    files = []
    for p in Path(base).rglob("*"):
        try:
            if p.is_file() and p.stat().st_size < 600 * 1048576 and cor_LOG_RX.search(p.name) and not p.name.lower().endswith((".evtx", ".dmp", ".raw", ".mem", ".vmem", ".pdf", ".docx", ".zip")):
                files.append(p)
        except Exception: continue
    for d_ in UNI_CTX.get("extra_log_dirs", []):
        try: files += [q for q in Path(d_).glob("*.log")]
        except Exception: pass
    for fp in sorted(files)[:4000]:
        if time.time() - t0 > max_sec: res["partial"] = True; break
        try: year = datetime.fromtimestamp(fp.stat().st_mtime).year
        except Exception: year = datetime.now().year
        first = last = None; n = 0
        for ln_no, line in enumerate(cor__read_lines(fp), 1):
            if not line.strip(): continue
            n += 1
            if n <= 300:
                mh = re.match(r"\s*\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s", line)
                if mh and not mh.group(1).startswith(("[", "(")): res["hosts"][mh.group(1)] += 1
            ts = cor__log_ts(line, year)
            if ts:
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
            # logons / exec records
            low = line.lower()
            if "accepted " in low and "sshd" in low:
                m = re.search(r"Accepted (\w[\w-]*) for (\S+) from (\S+) port (\d+)", line)
                if m and ts and len(res["logons"]) < 200000:
                    res["logons"][f"{m.group(2)}@{ts.isoformat()}"] = {"ts": ts, "type": "ssh", "user": m.group(2), "domain": "", "ip": m.group(3),
                                                                      "ws": m.group(1), "log": fp.name}
            elif "sudo:" in low and "command=" in low and ts:
                m = re.search(r"sudo:\s+(\S+)\s*:.*?USER=(\S+)\s*;\s*COMMAND=(.*)$", line)
                if m and len(res["procs"]) < 300000:
                    cmd = m.group(3).strip()
                    res["procs"].append({"ts": ts, "host": host, "pid": 0, "ppid": 0, "image": cmd.split()[0] if cmd.split() else "", "cmd": cmd, "parent": "sudo",
                                         "logon": "", "user": m.group(1), "log": fp.name, "eid": f"line {ln_no}"})
            elif "cron[" in low and " cmd (" in low and ts:
                m = re.search(r"CRON\[(\d+)\]:\s+\((\S+)\)\s+CMD\s+\((.*)\)\s*$", line)
                if m and len(res["procs"]) < 300000:
                    cmd = m.group(3).strip()
                    res["procs"].append({"ts": ts, "host": host, "pid": int(m.group(1)), "ppid": 0, "image": cmd.split()[0] if cmd.split() else "", "cmd": cmd,
                                         "parent": "cron", "logon": "", "user": m.group(2), "log": fp.name, "eid": f"line {ln_no}"})
            elif "type=syscall" in low or "type=execve" in low:
                mid = re.search(r"audit\(([\d.]+:\d+)\)", line)
                if mid:
                    d = aud.setdefault(mid.group(1), {"ts": ts, "log": fp.name, "ln": ln_no})
                    if "type=syscall" in low:
                        for k in ("pid", "ppid", "auid", "uid", "ses"):
                            mm = re.search(rf"\b{k}=(\S+)", line)
                            if mm: d[k] = mm.group(1)
                        mm = re.search(r'exe="([^"]*)"', line)
                        if mm: d["exe"] = mm.group(1)
                    else:
                        args = re.findall(r'\ba\d+="?([^"\s]+)"?', line)
                        if args: d["args"] = " ".join(args)
            if rx:
                mt = rx.findall(line)
                if mt and ts:
                    key = mt[0].lower()
                    if per_tok[key] < 60:
                        per_tok[key] += 1
                        res["hits"].append({"ts": ts, "eid": f"line {ln_no}", "log": fp.name, "host": host, "data": {"Line": line.strip()[:260]},
                                            "matched": sorted({x.lower() for x in mt})[:5]})
        res["coverage"][fp.name] = {"first": first, "last": last, "records": n}
        res["scanned"] += 1
    for k, d in aud.items():
        if d.get("exe") and d.get("ts") and d.get("pid", "").isdigit() and len(res["procs"]) < 400000:
            res["procs"].append({"ts": d["ts"], "host": host, "pid": int(d["pid"]), "ppid": int(d["ppid"]) if str(d.get("ppid", "")).isdigit() else 0,
                                 "image": d["exe"], "cmd": d.get("args", d["exe"]), "parent": "", "logon": d.get("ses", ""),
                                 "user": d.get("auid", d.get("uid", "")), "log": d["log"], "eid": f"audit line {d['ln']}"})
    for k_, v_ in (UNI_CTX.get("extra_logons") or {}).items():
        if k_ not in res["logons"]: res["logons"][k_] = v_
    log("INFO", f"  system-log pivot: {res['scanned']} file(s), {len(res['hits'])} matching lines, {len(res['procs'])} exec/cron/sudo records, {len(res['logons'])} ssh logons")
    return res


def cor_classify_chain(names, prof=None):
    """names: lowercase process basenames root -> leaf. Returns (vector, reason)."""
    prof = prof or cor_profile("windows")
    s = set(names)
    if prof["os"] == "windows":
        if s & cor_OFFICE: return "User-executed malicious document (email / Office / PDF)", f"chain passes through {sorted(s & cor_OFFICE)[0]}"
        if s & cor_BROWSER: return "Browser download / drive-by execution", f"chain passes through {sorted(s & cor_BROWSER)[0]}"
        if s & cor_WEBSVC: return "Exploited internet-facing service (web/app/database)", f"chain passes through {sorted(s & cor_WEBSVC)[0]}"
        if "wmiprvse.exe" in s: return "Remote WMI execution (lateral movement)", "spawned by wmiprvse.exe"
        if "wsmprovhost.exe" in s or "winrshost.exe" in s: return "Remote PowerShell / WinRM session", "spawned by WinRM host process"
        if "psexesvc.exe" in s: return "Remote service execution (PsExec-style)", "spawned by psexesvc.exe"
        if "mstsc.exe" in s or "rdpclip.exe" in s: return "Interactive RDP session", "RDP session processes in chain"
        if "taskeng.exe" in s or "taskhostw.exe" in s: return "Scheduled-task execution", "spawned by task scheduler host"
        if "services.exe" in s and len(names) <= 3: return "Service execution (service installed/abused)", "spawned directly by services.exe"
        if "explorer.exe" in s: return "Interactive user execution (desktop session) / autorun", "spawned from explorer.exe"
        if names and names[-1] == "svchost.exe":
            return "Shell launched by a service host (remote service execution, scheduled task or exploited service)", "direct parent is svchost.exe"
        return "", ""
    nm = {re.sub(r"\.(exe|app)$", "", n) for n in s}
    if nm & prof["web"]: return "Exploited internet-facing service / web application", f"chain passes through {sorted(nm & prof['web'])[0]}"
    if nm & {"sshd", "sshd-session", "ssh"}: return "SSH remote login session", "chain passes through sshd"
    if nm & {"cron", "crond", "atd", "anacron"}: return "Scheduled job (cron/at) execution", "spawned by cron/at"
    if nm & {"launchd"} and prof["os"] == "macos" and len(names) <= 3: return "launchd job (LaunchAgent/LaunchDaemon) execution", "spawned by launchd"
    if nm & prof["office"]: return "User-opened document / mail attachment", f"chain passes through {sorted(nm & prof['office'])[0]}"
    if nm & prof["browser"]: return "Browser download / drive-by execution", f"chain passes through {sorted(nm & prof['browser'])[0]}"
    if nm & {"systemd"} and len(names) <= 3: return "Systemd service / unit execution", "spawned by systemd"
    if nm & {"sudo", "su"}: return "Privilege escalation via sudo/su from an existing session", "chain passes through sudo/su"
    if nm & {"login", "gnome-session", "loginwindow", "terminal", "tty"}: return "Interactive console / terminal session", "chain passes through a local login/terminal"
    return "", ""


def cor_load_memory(vol_dir):
    """Parse Volatility3 text outputs (Windows / Linux / macOS plugin names, any filename prefix)."""
    m = {"procs": {}, "conns": [], "regvals": [], "services": [], "malfind": set(), "hidden": set(), "files": [], "bash": []}
    vd = Path(vol_dir) if vol_dir else None
    if not vd or not vd.exists(): return m

    def fl(*tags): return sorted({f for f in vd.glob("*.txt") if any(t in f.name.lower() for t in tags)})
    for f in fl("pslist", "psaux"):
        h, rows = cor__table(f)
        ip, ipp, inm = cor__col(h, "pid"), cor__col(h, "ppid"), cor__col(h, "imagefilename", "name", "comm")
        ict, iex, iargs = cor__col(h, "createtime", "creation time", "start time"), cor__col(h, "exittime"), cor__col(h, "args", "arguments")
        for r in rows:
            try: pid = int(cor__cell(r, ip))
            except Exception: continue
            ppid = cor__cell(r, ipp)
            p = m["procs"].setdefault(pid, {"pid": pid, "ppid": 0, "name": "", "created": None, "exited": None, "cmd": "", "path": ""})
            if ppid.isdigit(): p["ppid"] = int(ppid)
            if cor__cell(r, inm): p["name"] = cor__cell(r, inm)
            if cor__ts(cor__cell(r, ict)): p["created"] = cor__ts(cor__cell(r, ict))
            if cor__ts(cor__cell(r, iex)): p["exited"] = cor__ts(cor__cell(r, iex))
            if iargs is not None and cor__cell(r, iargs):
                p["cmd"] = cor__cell(r, iargs); p["path"] = p["cmd"].split()[0] if p["cmd"].split() else ""
        m["files"].append(f.name)
    for f in fl("cmdline"):
        h, rows = cor__table(f)
        ip, ia = cor__col(h, "pid"), cor__col(h, "args")
        for r in rows:
            try: pid = int(cor__cell(r, ip))
            except Exception: continue
            a = cor__cell(r, ia)
            p = m["procs"].setdefault(pid, {"pid": pid, "ppid": 0, "name": cor__cell(r, cor__col(h, "process")), "created": None,
                                            "exited": None, "cmd": "", "path": ""})
            p["cmd"] = a
            mm = re.match(r'\s*"([^"]+)"|\s*(\S+)', a)
            p["path"] = (mm.group(1) or mm.group(2)) if mm else ""
        m["files"].append(f.name)
    for f in fl("psxview"):
        h, rows = cor__table(f)
        ip, il, isc = cor__col(h, "pid"), cor__col(h, "pslist"), cor__col(h, "psscan")
        for r in rows:
            if cor__cell(r, il).lower() == "false" and cor__cell(r, isc).lower() == "true":
                try: m["hidden"].add(int(cor__cell(r, ip)))
                except Exception: pass
    for f in fl("netscan", "netstat", "sockstat"):
        h, rows = cor__table(f)
        ix = {"proto": cor__col(h, "proto"), "laddr": cor__col(h, "localaddr", "source addr", "local ip", "local address"),
              "lport": cor__col(h, "localport", "source port", "local port"),
              "faddr": cor__col(h, "foreignaddr", "destination addr", "remote ip", "foreign addr", "remote address"),
              "fport": cor__col(h, "foreignport", "destination port", "remote port"), "state": cor__col(h, "state"),
              "pid": cor__col(h, "pid"), "owner": cor__col(h, "owner", "process name", "process", "name", "comm"), "created": cor__col(h, "created")}
        for r in rows:
            try: pid = int(cor__cell(r, ix["pid"]))
            except Exception: pid = 0
            m["conns"].append({"proto": cor__cell(r, ix["proto"]), "laddr": cor__cell(r, ix["laddr"]), "lport": cor__cell(r, ix["lport"]),
                               "faddr": cor__cell(r, ix["faddr"]), "fport": cor__cell(r, ix["fport"]), "state": cor__cell(r, ix["state"]),
                               "pid": pid, "owner": cor__cell(r, ix["owner"]), "created": cor__ts(cor__cell(r, ix["created"]))})
    for f in fl("malfind"):
        h, rows = cor__table(f)
        ip = cor__col(h, "pid")
        for r in rows:
            try: m["malfind"].add(int(cor__cell(r, ip)))
            except Exception: pass
    for f in fl("printkey"):
        h, rows = cor__table(f)
        ik, inm, idt, itm = cor__col(h, "key"), cor__col(h, "name"), cor__col(h, "data"), cor__col(h, "last write time")
        for r in rows:
            if cor__cell(r, idt) or cor__cell(r, inm):
                m["regvals"].append({"key": cor__cell(r, ik), "name": cor__cell(r, inm), "data": cor__cell(r, idt),
                                     "lastwrite": cor__ts(cor__cell(r, itm)), "src": f.name})
    for f in fl("bash", "zsh"):
        h, rows = cor__table(f)
        ip, itm, ic = cor__col(h, "pid"), cor__col(h, "commandtime", "command time", "time"), cor__col(h, "command")
        for r in rows:
            if cor__cell(r, ic):
                try: pid = int(cor__cell(r, ip))
                except Exception: pid = 0
                m["bash"].append({"pid": pid, "time": cor__ts(cor__cell(r, itm)), "cmd": cor__cell(r, ic)})
    for f in fl("svcscan"):
        h, rows = cor__table(f)
        inm, ib, ist, ipid = cor__col(h, "name"), cor__col(h, "binary", "binary (registry)"), cor__col(h, "state"), cor__col(h, "pid")
        for r in rows:
            m["services"].append({"name": cor__cell(r, inm), "binary": cor__cell(r, ib), "state": cor__cell(r, ist), "pid": cor__cell(r, ipid)})
    return m


def cor_memory_indicators(m, prof=None):
    """Score every memory process / connection / registry value / shell command; return indicator dict."""
    prof = prof or cor_profile("windows")
    win = prof["os"] == "windows"
    inds = {}

    def add(key, kind, name, path, reasons, score, **kw):
        i = inds.setdefault(key, {"kind": kind, "name": name, "path": path, "reasons": [], "score": 0, "tokens": set(), "mem": {}, "pids": set()})
        for r in reasons:
            if r not in i["reasons"]: i["reasons"].append(r)
        i["score"] += score
        for k, v in kw.items():
            if k == "tokens": i["tokens"] |= set(v)
            elif k == "pids": i["pids"] |= set(v)
            else: i["mem"][k] = v
        return i

    procs = m["procs"]
    ext_by_pid = defaultdict(list)
    for c in m["conns"]:
        fa = c["faddr"]
        if fa and fa not in ("*", "-", "0.0.0.0", "::", "") and not epr_is_private_ip(fa) and not fa.startswith(("127.", "::1")):
            ext_by_pid[c["pid"]].append(c)
    cmd_pats = [p for p, _ in epr_MAL_PATTERNS] if win else [p for p, _ in SUSP_CMDS]
    for pid, p in procs.items():
        name = (p["name"] or cor__base(p["path"])).lower()
        reasons, score, toks = [], 0, set()
        full = f"{p['path']} {p['cmd']}"
        if cor_ACQ_TOOLS.search(full) or cor_ACQ_TOOLS.search(name): continue          # evidence-acquisition tool, not an attacker
        benign_loc = bool(win and p["path"] and (cor_BENIGN_DIR.search(p["path"].strip('"')) or cor_BENIGN_APPDATA.search(p["path"])))
        if prof["bad"].search(full) or prof["bad"].search(name) or (not win and name in {x.lower() for x in SUSP_PROCS} and name not in ("nc", "john") ):
            reasons.append("known attacker tool name"); score += 5
        if (win and cor_RANSOM_CMD.search(p["cmd"] or "")) or any(pt.search(p["cmd"] or "") for pt in cmd_pats):
            reasons.append("malicious command-line pattern"); score += 4
        if p["path"] and prof["susp_path"].search(p["path"]) and name not in prof["browser"] and not benign_loc:
            reasons.append("running from user-writable / temporary path"); score += 2
        par = procs.get(p["ppid"])
        pname = (par["name"].lower() if par else "")
        if win and name in cor_PARENT_RULES and par and pname not in cor_PARENT_RULES[name]:
            reasons.append(f"abnormal parent ({par['name']}) for {name}"); score += 3
        if name in prof["shells"] and pname and (pname in prof["office"] or pname in prof["web"] or pname in prof["browser"]):
            reasons.append(f"shell/interpreter spawned by {par['name']}"); score += 3
        elif win and name in cor_SHELLS and pname in ("svchost.exe", "services.exe", "wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe", "taskeng.exe", "psexesvc.exe"):
            reasons.append(f"shell spawned by service host ({par['name']})"); score += 2
        if prof["susp_path"].search(p["cmd"] or "") and name not in prof["browser"] and not benign_loc and not (p["path"] and prof["susp_path"].search(p["path"])):
            reasons.append("command line references user-writable / temporary path"); score += 2
        if pid in m["malfind"]:
            fp_name = name in cor_MALFIND_FP
            reasons.append("injected/RWX memory region (malfind)" + (" - low confidence for this process" if fp_name else "")); score += 1 if fp_name else 2
        if pid in m["hidden"]:
            reasons.append("hidden from process list (psxview)"); score += 2
        if pid in ext_by_pid and name not in prof["browser"] and name not in ("svchost.exe", "system", "msedgewebview2.exe", "sshd", "chronyd", "systemd-resolved", "apt", "dnf", "yum"):
            reasons.append("external network connection"); score += 2
        if not reasons: continue
        for c in ext_by_pid.get(pid, []): toks.add(c["faddr"])
        for fm in cor_FILE_RX.findall(p["cmd"] or ""):
            b = cor__base(fm)
            if b and b not in prof["osnames"] and b not in cor_GENERIC_BASE: toks.add(b)
            if win and "\\" in fm and not benign_loc: toks.add(fm.lower())
        for fm in re.findall(r"(?:/[\w.\-]+){2,}", p["cmd"] or ""):
            b = cor__base(fm)
            if b and b not in prof["osnames"] and len(b) >= 4: toks.add(b.lower())
        for ip in cor_IP_RX.findall(p["cmd"] or ""):
            if not epr_is_private_ip(ip): toks.add(ip)
        if p["path"] and win and "\\" in p["path"] and name not in prof["osnames"]: toks.add(p["path"].strip('"').lower())
        if name not in prof["osnames"] and name not in cor_GENERIC_BASE: toks.add(name)
        elif not toks and p["cmd"]:
            toks.add(re.sub(r"\s+", " ", p["cmd"])[:90].lower())
        key = (name if name not in prof["osnames"] else f"{name}#{pid}")
        add(key, "process", p["name"] or name, p["path"], reasons, score, tokens=toks, pids=[pid],
            created=p["created"], cmd=p["cmd"], ppid=p["ppid"], parent=(par["name"] if par else ""),
            conns=[f"{c['faddr']}:{c['fport']} ({c['state']})" for c in ext_by_pid.get(pid, [])][:8])
    if win:
        for rv in m["regvals"]:
            why = cor_reg_suspicious(rv["data"])
            if not why: continue
            for fm in cor_FILE_RX.findall(rv["data"]):
                b = cor__base(fm)
                if not b: continue
                tk = {fm.lower(), (rv["name"] or "").lower()} | ({b} if b not in cor_GENERIC_BASE else set())
                add(b, "registry", b, fm, [f"memory registry: {why}"], 3, tokens=tk - {""},
                    regkey=rv["key"], regname=rv["name"], regdata=rv["data"], lastwrite=rv["lastwrite"])
        for sv in m["services"]:
            b = sv.get("binary") or ""
            if b and not cor_BENIGN_DIR.search(b.strip('"')) and "windows defender" not in b.lower() and (cor_SUSP_PATH.search(b) or cor_BAD_NAME.search(b) or cor_RANSOM_CMD.search(b)):
                base = cor__base(re.split(r'\s+-', b.strip('"'))[0])
                add(base or sv["name"].lower(), "service", base or sv["name"], b, [f"service '{sv['name']}' runs from suspicious location"], 3,
                    tokens={(sv["name"] or "").lower(), base} - {""})
    else:
        # shell history recovered from memory: persistence / attacker commands
        for b in m.get("bash", []):
            why = cor_cmd_suspicious(prof, b["cmd"])
            pers = cor_LIN_PERSIST_CMD.search(b["cmd"])
            if not (why or pers): continue
            files = [cor__base(x) for x in re.findall(r"(?:/[\w.\-]+){2,}", b["cmd"])]
            files = [x for x in files if x and x not in prof["osnames"] and len(x) >= 4] or [re.sub(r"\s+", " ", b["cmd"])[:70].lower()]
            for x in files[:3]:
                add(x, "command", x, b["cmd"][:160], [f"memory shell history: {why or 'persistence-related command'}"], 3 if pers else 2,
                    tokens={x}, regkey="shell history", regname=str(b["pid"]), regdata=b["cmd"][:200], lastwrite=b["time"])
    return inds


def cor__evsrc(prof, h):
    if isinstance(h.get("eid"), int): return f"{prof['logs']} ({h['log']} EID {h['eid']})"
    return f"{prof['logs']} ({h['log']}, {h['eid']})"


def cor__ev_text(h):
    d = h["data"]
    for k in ("CommandLine", "NewProcessName", "Image", "ImagePath", "ServiceFileName", "TaskName", "ScriptBlockText", "TargetFilename", "Details", "Line"):
        if d.get(k): return f"{k}: {str(d[k])[:150]}"
    return " | ".join(f"{k}={str(v)[:60]}" for k, v in list(d.items())[:4])


def cor_store_why(prof, he):
    d = he.get("data") or ""
    if prof["os"] == "windows":
        why = cor_reg_suspicious(d)
        if he["kind"] == "service" and not why:
            if cor_SUSP_PATH.search(d) or cor_BAD_NAME.search(d): why = "service runs from suspicious location"
        if he["kind"] == "ifeo" and d: why = why or "IFEO debugger hijack"
        if he["kind"] == "autorun" and he["name"].lower() in ("shell", "userinit") and d.lower().strip() not in (
                "explorer.exe", "c:\\windows\\system32\\userinit.exe,", "userinit.exe,", "c:\\windows\\system32\\userinit.exe"):
            why = why or "Winlogon Shell/Userinit modified"
        return why
    k = he["kind"]
    if k == "preload": return "ld.so.preload entry (userland rootkit technique)"
    if k == "ssh_key": return "authorized_keys forced command" if "command=" in d else ""
    if k == "launchd":
        why = cor_cmd_suspicious(prof, d)
        if not why and d and not d.startswith(("/System/", "/usr/", "/Library/Apple", "/Applications/", "/bin/", "/sbin/", "/opt/homebrew", "/Library/")):
            why = "LaunchAgent/Daemon runs a non-standard program"
        return why
    return cor_cmd_suspicious(prof, d)


def cor_correlate(vol_dir=None, evtx_dir=None, registry_dir=None, base=None, log=None, os_type="windows"):
    log = log or (lambda lvl, msg: print(f"[{lvl}] {msg}"))
    prof = cor_profile(os_type); win = prof["os"] == "windows"
    log("HEAD", f"Cross-source correlation ({prof['os']}): memory <-> {prof['store'].lower()}s <-> " + ("hive logs <-> " if win else "") + f"{prof['logs'].lower()}s")
    mem = cor_load_memory(vol_dir)
    inds = cor_memory_indicators(mem, prof)
    log("INFO", f"  memory: {len(mem['procs'])} processes, {len(mem['conns'])} connections, {len(mem['regvals']) + len(mem.get('bash', []))} registry/shell records -> {len(inds)} indicator(s)")

    hives, hlogs, store = [], [], []
    if win:
        for root in (registry_dir, base):
            if root and not hives: hives, hlogs = cor_find_hives(root)
        store = cor_read_hives(hives, log) if hives else []
    else:
        store = cor_read_persistence(os_type, base, log)
    for he in store:
        why = cor_store_why(prof, he)
        he["why"] = why
        if not why: continue
        if win: files = [cor__base(x) for x in cor_FILE_RX.findall(he["data"])] or [he["name"].lower()]
        else:
            files = [cor__base(x) for x in re.findall(r"(?:/[\w.\-]+){2,}", he["data"])] or [he["name"].lower()]
            files = [x for x in files if x and x not in prof["osnames"] and len(x) >= 4] or [he["name"].lower()]
        for b in files:
            if not b: continue
            i = inds.setdefault(b, {"kind": "registry" if win else "persistence", "name": b, "path": he["data"], "reasons": [], "score": 0, "tokens": set(), "mem": {}, "pids": set()})
            r = f"on-disk {prof['store'].lower()} {he['hive']}: {why}"
            if r not in i["reasons"]: i["reasons"].append(r)
            i["score"] += 3; i["tokens"] |= ({b, he["name"].lower()} - {""} - prof["osnames"])
            i.setdefault("disk", []).append(he)

    tokens = set()
    for i in inds.values(): tokens |= {t for t in i["tokens"] if t not in prof["osnames"] or len(t) > 12}
    empty = {"hits": [], "procs": [], "logons": {}, "coverage": {}, "scanned": 0, "partial": False}
    if win:
        scan = cor_scan_evtx(evtx_dir or (base if base and any(Path(base).rglob("*.evtx")) else None), tokens, log, None) if (evtx_dir or base) else empty
    else:
        scan = cor_scan_textlogs(os_type, base, tokens, log) if base else empty
    hl_found = cor_search_hive_logs(hlogs, tokens, log) if hlogs else {}

    tokmap = defaultdict(list)
    for k, i in inds.items():
        for t in i["tokens"]: tokmap[t.lower()].append(k)
    import html as _html
    for h in scan["hits"]:
        for mt in h["matched"]:
            for k in tokmap.get(_html.unescape(mt).lower(), []):
                inds[k].setdefault("events", []).append(h)
    procblob = [(p, f"{p['image']} {p['cmd']}".lower()) for p in scan["procs"]]
    for k, i in inds.items():
        sg = []
        mm = i["mem"]
        if mm.get("created"): sg.append((mm["created"], "Memory (process list)", f"process started, PID {','.join(map(str, sorted(i['pids'])))} parent {mm.get('parent') or mm.get('ppid')}"))
        if mm.get("conns"): sg.append((mm.get("created"), "Memory (network)", "connections: " + ", ".join(mm["conns"])))
        if mm.get("regkey"): sg.append((mm.get("lastwrite"), "Memory (registry)" if win else "Memory (shell history)", f"{mm['regkey']} \\ {mm.get('regname')} = {mm.get('regdata')}"))
        for he in i.get("disk", []): sg.append((he["lastwrite"], f"{prof['store']} ({he['hive']})", f"{he['key']} \\ {he['name']} = {he['data'][:140]}"))
        for t in i["tokens"]:
            for hf in hl_found.get(t, []): sg.append((None, "Hive transaction log", f"'{t}' present in {hf}"))
        evs = sorted(i.get("events", []), key=lambda x: x["ts"])
        for h in evs[:12]: sg.append((h["ts"], cor__evsrc(prof, h), cor__ev_text(h)))
        firstproc = None
        toks = [t.lower() for t in i["tokens"] if t]
        for p, blob in procblob:
            if any(t in blob for t in toks):
                firstproc = p; break
        i["first_proc"] = firstproc
        if firstproc: sg.append((firstproc["ts"], cor__evsrc(prof, firstproc),
                                 f"process executed: {firstproc['image']} {firstproc['cmd'][:120]} (parent {cor__base(firstproc['parent'])}, user {firstproc['user']})"))
        sg.sort(key=lambda x: (x[0] is None, x[0] or datetime.max))
        i["sightings"] = sg
        i["event_count"] = len(i.get("events", []))
        i["in_memory"] = bool(i["pids"] or mm)
        i["in_events"] = bool(evs or firstproc)
        i["in_hive"] = bool(i.get("disk"))
        i["in_hive_log"] = any(hl_found.get(t) for t in i["tokens"])

    cross = []
    rvs = []
    if win:
        for rv in mem["regvals"]:
            why = cor_reg_suspicious(rv["data"])
            if why: rvs.append((rv["key"], rv["name"], rv["data"], why, rv["lastwrite"]))
    else:
        for b in mem.get("bash", []):
            why = cor_cmd_suspicious(prof, b["cmd"]) or ("persistence-related command" if cor_LIN_PERSIST_CMD.search(b["cmd"]) else "")
            if why: rvs.append(("shell history", f"pid {b['pid']}", b["cmd"], why, b["time"]))
    for key, name, data, why, lw in rvs:
        if win: bq = cor__base((cor_FILE_RX.findall(data) or [""])[0])
        else:
            fs = [cor__base(x) for x in re.findall(r"(?:/[\w.\-]+){2,}", data)]
            bq = next((x for x in fs if x and x not in prof["osnames"] and len(x) >= 4), "")
        if win:
            disk = [he for he in store if he["name"].lower() == (name or "").lower() and (not bq or bq in he["data"].lower())]
        else:
            disk = [he for he in store if bq and (bq in he["data"].lower() or bq in he["key"].lower())]
        hl = sorted({f for t in (bq, (name or "").lower()) for f in hl_found.get(t, [])}) if win else []
        ev_count = len(inds.get(bq, {}).get("events", [])) if bq else 0
        cross.append({"key": key, "name": name, "data": data, "why": why, "mem_lastwrite": lw,
                      "disk": (f"present ({disk[0]['hive']}), last write " + epr_fmt(disk[0]["lastwrite"])) if disk else (f"ABSENT from on-disk {prof['store'].lower()}s" if store else f"{prof['store'].lower()}s not provided"),
                      "hive_log": (", ".join(hl) if hl else ("not found" if hlogs else "no hive logs provided")) if win else "n/a on this OS",
                      "events": f"{ev_count} matching entr(ies)" if scan["scanned"] else f"{prof['logs'].lower()}s not provided"})

    ep = cor_derive_entry(inds, scan, mem, store, prof)
    entries = {}
    for k_, i_ in sorted(inds.items(), key=lambda kv: -kv[1]["score"])[:25]:
        if i_["score"] >= 3:
            t_ = cor__when(i_)
            if t_:
                try: entries[k_] = cor_entry_for(inds, k_, t_, scan, mem, prof)
                except Exception: pass
    gaps = cor_gaps(inds, scan, mem, store, hlogs, ep, prof)
    cor = {"indicators": inds, "cross": cross, "entry": ep, "entries": entries, "gaps": gaps, "labels": {"store": prof["store"], "logs": prof["logs"], "os": prof["os"]},
           "meta": {"hosts": dict(scan.get("hosts", {})), "coverage": scan["coverage"],
                    "remote_logons": [[str(l["ts"]), l["user"], l["ip"], l["type"], l["log"]] for l in sorted(scan["logons"].values(), key=lambda x: x["ts"])
                                      if l["type"] in prof["remote_types"] and l["ip"] not in ("", "-", "::1", "127.0.0.1")][:300],
                    "accounts": dict(Counter([str(pr["user"]) for pr in scan["procs"] if pr.get("user") and str(pr["user"]) not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")] +
                                             [(l["domain"] + "\\" + l["user"]) if l["domain"] else l["user"] for l in scan["logons"].values()]).most_common(10))},
           "stats": {"processes": len(mem["procs"]), "indicators": len(inds), "stores": len(hives) if win else len(store), "hive_logs": len(hlogs),
                     "log_files": scan["scanned"], "log_hits": len(scan["hits"])}}
    log("OK", f"Correlation done: {len(inds)} indicator(s); entry point {ep['status']}" + (f" - {ep['vector']}" if ep.get("vector") else ""))
    return cor


def cor__when(i):
    ts = []
    if i.get("first_proc"): ts.append(i["first_proc"]["ts"])
    if i["mem"].get("created"): ts.append(i["mem"]["created"])
    if i["mem"].get("lastwrite"): ts.append(i["mem"]["lastwrite"])
    for he in i.get("disk", []):
        if he.get("lastwrite"): ts.append(he["lastwrite"])
    if not ts: ts = [h["ts"] for h in i.get("events", [])]
    return min(ts) if ts else None


def cor_derive_entry(inds, scan, mem, store, prof=None):
    prof = prof or cor_profile("windows")
    ep = {"status": "NOT DETERMINED", "confidence": "n/a", "vector": "", "time": None, "account": "", "source_ip": "", "anchor": "",
          "chain": [], "evidence": [], "reasons": []}
    strong = [(k, i) for k, i in inds.items() if i["score"] >= 4] or [(k, i) for k, i in inds.items() if i["score"] >= 3]
    if not strong:
        ep["reasons"].append("No indicator reached the suspicion threshold in the supplied evidence.")
        return ep

    ranked = sorted(((cor__when(i), -i["score"], k) for k, i in strong if cor__when(i)), key=lambda x: (x[1], x[0]))
    if not ranked:
        ep["reasons"].append("Suspicious items found but none carries a timestamp.")
        return ep
    t0, _, key = ranked[0]
    return cor_entry_for(inds, key, t0, scan, mem, prof)


def cor_entry_for(inds, key, t0, scan, mem, prof):
    """Entry-point analysis anchored on ONE indicator (chain, logon link, vector, evidence)."""
    ep = {"status": "NOT DETERMINED", "confidence": "n/a", "vector": "", "time": None, "account": "", "source_ip": "", "anchor": "",
          "chain": [], "evidence": [], "reasons": []}
    a = inds[key]
    ep["time"], ep["anchor"] = t0, f"{a['name']} ({'; '.join(a['reasons'][:2])})"
    idx = cor__idx_procs(scan["procs"]) if scan["procs"] else {}
    chain_names, chain_txt, via = [], [], ""
    fp = a.get("first_proc")
    if fp and idx:
        ch = cor_chain_events(fp, idx)
        chain_names = [cor__base(p["image"]) for p in ch]
        chain_txt = [f"{cor__base(p['image'])} (PID {p['pid']}, {epr_fmt(p['ts'])})" for p in ch]
        rp = cor__base(ch[0].get("parent", "")) if ch and ch[0].get("parent") else ""
        if rp and rp not in chain_names[:1]:
            chain_names.insert(0, rp); chain_txt.insert(0, f"{rp} (parent named in the process record)")
        elif ch and ch[0].get("ppid") in mem["procs"]:
            mc = cor_chain_memory(ch[0]["ppid"], mem["procs"])
            chain_names = [(p["name"] or "").lower() for p in mc] + chain_names
            chain_txt = [f"{p['name']} (PID {p['pid']}, from memory)" for p in mc] + chain_txt
        via = "event log" if prof["os"] == "windows" else "system log"
    elif a["pids"]:
        ch = cor_chain_memory(sorted(a["pids"])[0], mem["procs"])
        chain_names = [(p["name"] or "").lower() for p in ch]
        chain_txt = [f"{p['name']} (PID {p['pid']}" + (f", {epr_fmt(p['created'])}" if p["created"] else "") + ")" for p in ch]
        via = "memory"
    ep["chain"] = chain_txt
    vector, why = cor_classify_chain(chain_names[:-1] if len(chain_names) > 1 else chain_names, prof)
    logon = None
    if fp and fp.get("logon"):
        logon = scan["logons"].get(str(fp["logon"]).lower())
        if logon: ep["evidence"].append((logon["ts"], f"{prof['logs']} ({logon['log']} logon)",
                                         f"Logon ID {fp['logon']}: {logon['domain']}\\{logon['user']} type {logon['type']} from {logon['ip'] or logon['ws'] or '-'}"))
    if not logon and scan["logons"]:
        uname = str(fp["user"]).lower() if fp and fp.get("user") and not str(fp["user"]).isdigit() else ""
        cand = [(l["ts"], l) for l in scan["logons"].values() if l["type"] in prof["remote_types"] and l["ip"] not in ("", "-", "::1", "127.0.0.1")
                and t0 - timedelta(hours=6) <= l["ts"] <= t0 and (not uname or l["user"].lower() == uname)]
        if cand:
            cand.sort(key=lambda x: x[0])
            logon = cand[-1][1]
            ep["evidence"].append((logon["ts"], f"{prof['logs']} ({logon['log']} logon)",
                                   f"Nearest preceding remote logon (<=6h before first malicious activity): {(logon['domain'] + chr(92)) if logon['domain'] else ''}{logon['user']} type {logon['type']} from {logon['ip'] or '-'}"))
            ep["reasons"].append("Logon matched by time proximity" + (" + user" if uname else "") + " (no session-ID link).")
    if logon:
        ep["account"] = (f"{logon['domain']}\\{logon['user']}" if logon["domain"] else logon["user"]).strip("\\")
        ep["source_ip"] = logon["ip"] or logon["ws"]
        lt = logon["type"]
        lv = ({"10": "Remote Desktop (RDP) logon", "3": "Network logon (SMB / WinRM / remote service)", "2": "Interactive console logon",
               "11": "Cached interactive logon", "7": "Workstation unlock / reconnect"}.get(lt, f"Logon type {lt}") if prof["os"] == "windows"
              else f"SSH login ({logon['ws']})" if logon["ws"] else "SSH login")
        vector = (vector + " via " if vector else "") + lv + (f" from {ep['source_ip']}" if ep["source_ip"] else "")
        ep["evidence"].append((logon["ts"], "Entry vector", lv))
    if vector: ep["reasons"].append(why or "derived from logon evidence")
    ep["vector"] = vector or "Process chain root could not be classified"
    for ts, src, det in a["sightings"][:10]: ep["evidence"].append((ts, src, det))
    for k, i in inds.items():
        if i["kind"] in ("registry", "service", "persistence", "command") and (a["name"].lower() in " ".join(i["tokens"]) or k == key or any(
                a["name"].lower() in (he["data"] or "").lower() for he in i.get("disk", []))):
            for ts, src, det in i["sightings"][:3]:
                if src.startswith(("Registry", "Memory (registry)", "Hive", "Persistence", "Memory (shell")): ep["evidence"].append((ts, "Persistence - " + src, det))
    ep["evidence"].sort(key=lambda x: (x[0] is None, x[0] or datetime.max))
    pts = (1 if via in ("event log", "system log") else 0) + (1 if logon else 0) + (1 if vector and why else 0) + (1 if a["in_memory"] and a["in_events"] else 0)
    if pts >= 3: ep["status"], ep["confidence"] = "DETERMINED", "High"
    elif pts == 2: ep["status"], ep["confidence"] = "PROBABLE", "Medium"
    else: ep["status"], ep["confidence"] = "PARTIAL", "Low"
    if via == "memory" and not logon:
        ep["reasons"].append("Chain taken from memory only - not corroborated by logs.")
    ep["via"] = via
    return ep


def cor_gaps(inds, scan, mem, store, hlogs, ep, prof=None):
    prof = prof or cor_profile("windows")
    win = prof["os"] == "windows"
    g = []
    if not mem["procs"]: g.append(("Memory", "No process list available - process chains rely on logs only."))
    if not scan["scanned"]: g.append((prof["logs"] + "s", "No log files scanned - entry point cannot be confirmed from logs."))
    else:
        if not scan["procs"]:
            g.append((prof["logs"] + "s", "No process-creation events (Security 4688 / Sysmon 1) found - enable command-line process auditing." if win
                      else "No exec records (auditd EXECVE / sudo / cron) found - enable auditd execve logging for process-level attribution."))
        if not scan["logons"]:
            g.append((prof["logs"] + "s", "No 4624 logon events found - logon / source-IP linkage not possible." if win
                      else "No SSH 'Accepted' logins found - login / source-IP linkage not possible (auth log missing or rotated)."))
        if scan["partial"]: g.append((prof["logs"] + "s", "Scan stopped at time limit - results partial."))
        t0 = ep.get("time")
        if t0:
            for fn, c in scan["coverage"].items():
                if c["first"] and t0 < c["first"] and (not win or fn.lower().startswith(("security", "system", "microsoft-windows-sysmon"))):
                    g.append((prof["logs"] + "s", f"{fn} starts at {epr_fmt(c['first'])}, after first malicious activity ({epr_fmt(t0)}) - earlier access may be lost (log rolled over)."))
    if not store: g.append((prof["store"] + "s", "No persistence stores could be parsed - memory records not verified against disk."))
    elif win and not hlogs: g.append(("Registry", "No hive transaction logs (.LOG1/.LOG2) supplied - recent un-merged registry changes cannot be checked."))
    if any(i["in_memory"] and not i["in_events"] and scan["scanned"] for i in inds.values() if i["score"] >= 3):
        g.append(("Correlation", "Some memory indicators have no log trace (logs cleared, not audited, or fileless activity)."))
    return g


def cor_sections(cor):
    """-> list of (title, headers, rows) for DOCX/PDF/dashboard."""
    if not cor: return []
    ep, S = cor["entry"], []
    lb = cor.get("labels") or {"store": "Registry hive", "logs": "Event log", "os": "windows"}
    win = lb["os"] == "windows"
    f = lambda t: epr_fmt(t) if isinstance(t, datetime) else (str(t) if t else "-")
    S.append(("Entry Point Determination", ["Field", "Value"], [
        ["Status", f"{ep['status']} (confidence: {ep['confidence']})"], ["Initial access vector", ep["vector"] or "-"],
        ["First malicious activity", f(ep["time"])], ["Anchor indicator", ep["anchor"] or "-"],
        ["Account", ep["account"] or "-"], ["Source IP / host", ep["source_ip"] or "-"],
        ["Process chain", "  ->  ".join(ep["chain"]) if ep["chain"] else "-"],
        ["Reasoning", "; ".join(ep["reasons"]) or "-"]]))
    if ep["evidence"]:
        S.append(("Entry Point Evidence Timeline", ["Time", "Source", "Detail"], [[f(t), s, d[:300]] for t, s, d in ep["evidence"]]))
    rows = []
    for k, i in sorted(cor["indicators"].items(), key=lambda kv: -kv[1]["score"]):
        row = [i["name"], i["kind"], "; ".join(i["reasons"])[:200], "yes" if i["in_memory"] else "-", "yes" if i["in_hive"] else "-"]
        if win: row.append("yes" if i["in_hive_log"] else "-")
        row.append(f"{i['event_count']} hit(s)" + (" + exec" if i.get("first_proc") else "") if i["in_events"] else "-")
        rows.append(row)
    hdr = ["Indicator", "Type", "Why suspicious", "Memory", lb["store"].split()[-1].capitalize()] + (["Hive log"] if win else []) + [lb["logs"]]
    if rows: S.append(("Cross-Source Correlation Matrix", hdr, rows[:150]))
    if cor["cross"]:
        S.append((("Registry: Memory vs Disk Hive vs Hive Log vs Events" if win else "Shell History in Memory vs Persistence Files vs System Logs"),
                  ["Key / Value" if win else "Source / PID", "Data", "On-disk " + ("hive" if win else "persistence"), "Hive log" if win else "Note", lb["logs"]],
                  [[f"{c['key']} \\ {c['name']}" if win else f"{c['key']} ({c['name']})", c["data"][:160], c["disk"], c["hive_log"], c["events"]] for c in cor["cross"]]))
    pc = []
    for k, i in cor["indicators"].items():
        if i["kind"] == "process" and i["score"] >= 3:
            fp = i.get("first_proc")
            pc.append([i["name"], ", ".join(map(str, sorted(i["pids"]))) or "-", i["mem"].get("parent") or "-", f(i["mem"].get("created") or (fp or {}).get("ts")),
                       (i["mem"].get("cmd") or (fp or {}).get("cmd") or "-")[:200]])
    if pc: S.append(("Suspicious Processes", ["Process", "PID", "Parent", "Started", "Command line"], pc[:100]))
    if cor["gaps"]: S.append(("Evidence Gaps & Limitations", ["Area", "Gap"], [list(x) for x in cor["gaps"]]))
    return S


def cor__idx_procs(procs):
    idx = defaultdict(list)
    for p in procs: idx[(p["host"], p["pid"])].append(p)
    for v in idx.values(): v.sort(key=lambda x: x["ts"])
    return idx


def cor_chain_events(start, idx):
    chain, cur = [start], start
    for _ in range(14):
        cands = [p for p in idx.get((cur["host"], cur["ppid"]), []) if p["ts"] <= cur["ts"]]
        if not cands: break
        par = cands[-1]
        if par in chain: break
        chain.append(par); cur = par
    return list(reversed(chain))


def cor_chain_memory(pid, procs):
    chain, seen, cur = [], set(), procs.get(pid)
    while cur and cur["pid"] not in seen and len(chain) < 14:
        chain.append(cur); seen.add(cur["pid"]); cur = procs.get(cur["ppid"])
    return list(reversed(chain))


import queue as _cor_queue
import threading as _cor_threading

cor_LIVE_SYSTEM = (
    "You are a senior DFIR analyst reviewing tool output while the tools are still running. The JSON has 'tool_flagged' (what the "
    "tool already flagged) and 'output_excerpt' (raw tool output lines). Find anything suspicious in the excerpt that the tool did NOT "
    "flag: odd processes or parents, user-writable paths, encoded or download commands, external IPs, persistence keys, new services or "
    "accounts, log clearing, ransomware behaviour. Reply with a short bullet list: item - why suspicious - where seen. If the tool "
    "missed nothing reply exactly: NOTHING MISSED. Use only facts present in the data. Plain text.")

cor_REVIEW_SYSTEM = (
    "You are a senior DFIR analyst writing the incident narrative of a forensic report. The user message is an INVESTIGATION BRIEFING of facts: "
    "deduplicated findings, attack windows, correlation result, indicators, registry/shell cross-check, IOC reputation table, evidence gaps and a "
    "fact-based draft narrative. Use ONLY these facts, never invent hosts, IPs, users, tools or times. Do NOT describe or summarise the briefing itself and "
    "never mention JSON, fields or 'the text'; write the report text directly, starting with the first heading. Use exactly these CAPS headings, in order: "
    "ATTACK NARRATIVE - chronological paragraphs saying when each phase happened, what was done, how (tools, persistence, execution) and the impact; "
    "ENTRY POINT - if proven: time, account, source IP/host, vector and the exact evidence; if NOT proven: say so plainly, explain why, then list the closest "
    "correlated log evidence (remote logons before the first attack window, first activity, coverage gaps) and what must be collected to prove it; "
    "IOC ASSESSMENT - for each reputation-checked IOC state verdict, ASN/owner and country and what it means; "
    "COMPLETENESS CHECK - suspicious findings NOT tied to the intrusion chain and whether they look related; "
    "Write 450-800 words of plain prose (short bullet lists allowed), no markdown symbols.")


class AnalystLive:
    """Background reviewer: reads tool output as it is produced and notes what the tools missed."""
    def __init__(self, cfg, log):
        self.cfg, self.log, self.notes = cfg, log, []
        self.q = _cor_queue.Queue()
        self.t = None
        if cfg:
            self.t = _cor_threading.Thread(target=self._run, daemon=True)
            self.t.start()

    def feed(self, step, lines, flagged=None):
        if self.cfg and lines:
            self.q.put((step, list(lines)[:140], list(flagged or [])[:40]))

    def _run(self):
        while True:
            it = self.q.get()
            if it is None: break
            step, lines, flagged = it
            try:
                payload = json.dumps({"step": step, "tool_flagged": flagged, "output_excerpt": lines}, default=str)[:30000]
                txt = epr_ai_call(self.cfg, cor_LIVE_SYSTEM, payload, lambda l, m: None, max_tokens=900)
                if txt and "NOTHING MISSED" not in txt.upper():
                    self.notes.append((step, txt.strip()))
                    self.log("INFO", f"  [analyst] {step}: extra observations noted ({len(txt.split())} words)")
                elif txt:
                    self.log("INFO", f"  [analyst] {step}: nothing missed by tools")
            except Exception as ex:
                self.log("WARN", f"  [analyst] {step}: review failed ({type(ex).__name__})")

    def finish(self, timeout=900):
        if self.t:
            self.q.put(None); self.t.join(timeout)
        return self.notes


def cor_review_payload(cor, results, live_notes):
    d = {}
    if cor:
        ce = cor["entry"]
        d["entry_point"] = {k: (str(v) if isinstance(v, datetime) else v) for k, v in ce.items() if k != "evidence"}
        d["entry_point"]["evidence"] = [[str(t), s, x[:200]] for t, s, x in ce["evidence"][:25]]
        d["indicators"] = [{"name": i["name"], "type": i["kind"], "score": i["score"], "why": i["reasons"][:4], "in_memory": i["in_memory"],
                            "in_hive": i["in_hive"], "in_hive_log": i["in_hive_log"], "event_hits": i["event_count"],
                            "first_seen": str(i["sightings"][0][0]) if i["sightings"] else ""}
                           for i in sorted(cor["indicators"].values(), key=lambda x: -x["score"])[:40]]
        d["registry_cross_check"] = [{k: str(v)[:200] for k, v in c.items() if k != "why"} for c in cor["cross"][:30]]
        d["gaps"] = cor["gaps"]
    digest = []
    for sev in ("critical", "high"):
        for it in (results.get(sev) or [])[:100]:
            digest.append(f"[{sev.upper()}] {it.get('source', '')}: {str(it.get('desc', ''))[:160]}")
    d["tool_findings_digest"] = digest
    d["tool_finding_counts"] = {k: len(results.get(k) or []) for k in ("critical", "high", "medium")}
    if live_notes: d["notes_made_while_tools_ran"] = [f"{st}: {tx[:600]}" for st, tx in live_notes][:20]
    return json.dumps(d, default=str)[:55000]


def cor_review(cfg, cor, results, log, live_notes=None, ioc_rows=None, narrative=None):
    """Post-analysis correlation + completeness review. Returns plain text or None."""
    if not cfg: return None
    log("HEAD", "Analyst review: correlating all findings and checking for gaps")
    briefing = uni_briefing(uni_results_payload(results), cor, ioc_rows, narrative)
    if live_notes: briefing += "\nNOTES FROM LIVE REVIEW OF TOOL OUTPUT:\n" + "\n".join(f"- {st}: {tx[:500]}" for st, tx in live_notes[:15])
    txt = epr_ai_call(cfg, cor_REVIEW_SYSTEM, briefing, log, max_tokens=3500)
    if txt and not uni_review_ok(txt):
        log("WARN", "Analyst review discarded: reply did not analyse the briefing")
        return None
    return txt


def win_live_feed(live, step, results, marks, out):
    """Hand the newest tool output to the live reviewer (non-blocking)."""
    if not live: return
    new = []
    for sev in ("critical", "high", "medium"):
        for it in (results.get(sev) or [])[marks.get(sev, 0):][:80]:
            new.append(f"[{sev.upper()}] {it.get('source', '')}: {str(it.get('desc', ''))[:160]}")
        marks[sev] = len(results.get(sev) or [])
    raw = []
    vol = Path(out) / "volatility"
    if step == "memory" and vol.exists():
        for f in sorted(vol.glob("*.txt")):
            if any(k in f.name.lower() for k in ("pslist", "cmdline", "netscan", "svcscan", "printkey", "malfind", "psxview")):
                raw.append(f"--- {f.name}")
                try: raw += f.read_text(errors="ignore").splitlines()[:60]
                except Exception: pass
    elif step == "evtx":
        for f in sorted(Path(out).glob("*hayabusa*.csv"))[:1] + sorted(Path(out).glob("*chainsaw*"))[:0]:
            try: raw += f.read_text(errors="ignore").splitlines()[:120]
            except Exception: pass
    live.feed(step, raw or new, new)


# ═══════════════════════════════════════════════════════════════════════════
# UNIFIED POST-ANALYSIS (same method for every OS): live review hooks, correlation,
# analyst review, dashboard injection
# ═══════════════════════════════════════════════════════════════════════════
UNI_CTX = {"vol_dir": None}


def uni_add_engine_args(parser):
    parser.add_argument("--no-review", dest="no_ai", action="store_true", help="Skip the analyst-engine review")
    parser.add_argument("--engine", dest="ai_provider", choices=["auto", "ollama", "anthropic", "gemini", "meta"], default="auto", help="Analyst backend")
    parser.add_argument("--engine-key", dest="ai_key", help="Anthropic (Claude) API key")
    parser.add_argument("--engine-model", dest="ai_model", help="Anthropic model name")
    parser.add_argument("--gemini-key", help="Google Gemini API key")
    parser.add_argument("--gemini-model", help="Gemini model name")
    parser.add_argument("--meta-key", help="Meta/Llama API key")
    parser.add_argument("--meta-model", help="Meta/Llama model name")
    parser.add_argument("--ollama-host", help="Ollama host URL")
    parser.add_argument("--ollama-model", help="Ollama model name")
    parser.add_argument("--non-interactive", action="store_true", help="Never prompt for an engine choice/key")


def uni_engine_cfg(args, log):
    """Resolve the analyst engine from CLI flags (same logic for every OS). None = rule-based only."""
    if getattr(args, "no_ai", False): return None
    try:
        picked = None
        if not getattr(args, "non_interactive", False) and getattr(args, "ai_provider", "auto") == "auto" and sys.stdin.isatty():
            picked = epr_interactive_ai_setup(log, args.ollama_model, args.ai_model, args.gemini_model, args.meta_model, args.ollama_host, args.meta_host if hasattr(args, "meta_host") else None)
        if picked == "skip": return None
        if picked: return picked
        return epr_resolve_ai_cfg(log, getattr(args, "ai_provider", "auto"), args.ollama_host, args.ollama_model,
                                  args.ai_key or os.environ.get("ANTHROPIC_API_KEY"), args.ai_model,
                                  args.gemini_key or os.environ.get("GEMINI_API_KEY"), args.gemini_model,
                                  args.meta_key or os.environ.get("META_API_KEY"), args.meta_model, None)
    except Exception as e:
        log("WARN", f"Analyst engine setup failed: {e}")
        return None


def uni_live_feed(live, step, results, marks, files=None, vol_dir=None):
    """Hand newest tool output (new findings + raw excerpts) to the background reviewer."""
    if not live: return
    new = []
    for sev in ("critical", "high", "medium"):
        for it in (results.get(sev) or [])[marks.get(sev, 0):][:80]:
            new.append(f"[{sev.upper()}] {it.get('source', '')}: {str(it.get('desc', ''))[:160]}")
        marks[sev] = len(results.get(sev) or [])
    raw = []
    for f in list(files or [])[:4]:
        try:
            raw.append(f"--- {Path(f).name}")
            raw += cor__read_lines(f, 2 * 1048576)[:50]
        except Exception: pass
    if vol_dir and Path(vol_dir).exists():
        for f in sorted(Path(vol_dir).glob("*.txt")):
            if any(k in f.name.lower() for k in ("pslist", "psaux", "cmdline", "netstat", "sockstat", "bash", "malfind")):
                raw.append(f"--- {f.name}")
                try: raw += f.read_text(errors="ignore").splitlines()[:50]
                except Exception: pass
    live.feed(step, raw or new, new)


def uni_html_block(sections, review):
    from xml.sax.saxutils import escape as E
    h = ['<div id="correlation-report" style="max-width:1200px;margin:28px auto;padding:0 16px;font-family:system-ui,sans-serif">',
         '<h2 style="margin:0 0 10px">Cross-Source Correlation</h2>']
    for t, hd, rows in sections:
        h.append(f'<h3 style="margin:18px 0 6px">{E(str(t))}</h3><div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:12.5px">')
        h.append("<tr>" + "".join(f'<th style="text-align:left;border:1px solid #8884;padding:5px 8px;background:#8881">{E(str(c))}</th>' for c in hd) + "</tr>")
        for r in rows[:300]:
            h.append("<tr>" + "".join(f'<td style="border:1px solid #8884;padding:4px 8px;vertical-align:top">{E(str(c))[:400]}</td>' for c in r) + "</tr>")
        h.append("</table></div>")
    if review:
        h.append('<h2 style="margin:26px 0 8px">Analyst Review</h2><div style="white-space:pre-wrap;line-height:1.5;border:1px solid #8884;border-radius:8px;padding:12px">'
                 + E(review) + "</div>")
    h.append("</div>")
    return "\n".join(h)


def uni_inject_html(html_path, sections, review):
    try:
        p = Path(html_path)
        if not p.exists() or (not sections and not review): return
        t = p.read_text(encoding="utf-8", errors="ignore")
        if 'id="correlation-report"' in t: return
        blk = uni_html_block(sections, review)
        t = t.replace("</body>", blk + "\n</body>", 1) if "</body>" in t else t + blk
        p.write_text(t, encoding="utf-8")
    except Exception:
        pass


def uni_finalize(os_type, out, base, results, cfg, live, log, vol_dir=None, evtx_dir=None, registry_dir=None, html_path=None):
    """Correlate every source for this OS, run the analyst review, write outputs. Same flow for all OS."""
    out = Path(out)
    cor, review = None, None
    try:
        vd = vol_dir or UNI_CTX.get("vol_dir") or (out / "volatility")
        cor = cor_correlate(str(vd) if Path(vd).exists() else None, evtx_dir=evtx_dir, registry_dir=registry_dir, base=base, log=log, os_type=os_type)
        secs = uni_save_cor(cor, out)
        try: uni_scope(os_type, base, str(vd), cor, out)
        except Exception as _e: log("WARN", f"Scope summary failed: {_e}")
        notes = live.finish() if live else []
        if cfg:
            review = cor_review(cfg, cor, results, log, notes)
            if review: (out / "analyst_review.txt").write_text(review, encoding="utf-8")
        elif live is None:
            pass
        if html_path: uni_inject_html(html_path, secs, review)
    except Exception as ex:
        log("WARN", f"Correlation step failed: {type(ex).__name__}: {ex}")
    return cor, review


def uni_memory_dumps(base):
    out = []
    try:
        for p in Path(base).rglob("*"):
            if p.is_file() and p.suffix.lower() in (".raw", ".mem", ".vmem", ".lime", ".dmp", ".bin", ".vmsn") and p.stat().st_size >= 1048576:
                out.append(p)
    except Exception: pass
    return out


def uni_memory_analysis(os_type, dumps, vol_dir, log, live=None):
    """Volatility plugins for macOS / generic dumps; outputs saved as text for the correlation engine."""
    if not dumps: return
    chk = subprocess.run("vol --help 2>/dev/null", shell=True, capture_output=True)
    if chk.returncode != 0:
        log("WARN", "  Volatility3 not found - install: pip3 install volatility3"); return
    pre = "mac" if os_type in ("macos", "mac") else "linux"
    plugins = [f"{pre}.pslist.PsList", f"{pre}.psaux.Psaux", f"{pre}.pstree.PsTree", f"{pre}.netstat.Netstat", f"{pre}.bash.Bash", f"{pre}.malfind.Malfind"]
    Path(vol_dir).mkdir(parents=True, exist_ok=True)
    for dump in dumps:
        log("INFO", f"  {dump.name}")
        for pl in plugins:
            try:
                r = subprocess.run(f'vol -q -f "{dump}" {pl} 2>/dev/null', shell=True, capture_output=True, text=True,
                                   timeout=int(os.environ.get("VOL_TIMEOUT", 0)) or 3600)
                if r.stdout.strip():
                    (Path(vol_dir) / f"{dump.stem}_{pl.split('.')[0]}_{pl.split('.')[1]}.txt").write_text(r.stdout, encoding="utf-8", errors="replace")
                    log("OK", f"    {pl}: {len(r.stdout.splitlines())} lines")
            except subprocess.TimeoutExpired:
                log("WARN", f"    {pl}: timeout")


# ═══════════════════════════════════════════════════════════════════════════
# REPORT MODEL v2 — grouped / de-duplicated / narrative report (same for every OS)
# ═══════════════════════════════════════════════════════════════════════════
rpt_NOISE = [  # (bucket name, regex on "source desc data") -> informational, collapsed into one line
    ("AppX/MSIX package installs", re.compile(r"MSIX|AppX Package|AppxMetadata", re.I)),
    ("Driver / system service registrations flagged by generic rules", re.compile(r"Suspicious Service (?:Path|Name)[\s\S]*(?:DriverStore|%SystemRoot%|\\System32\\|\\SysWOW64\\|\\Windows\\System32)", re.I)),
    ("Microsoft Defender service paths", re.compile(r"Service with suspicious path[\s\S]*Windows Def", re.I)),
    ("Windows app-package registry hives mis-flagged as persistence", re.compile(r"Registry persistence in memory[\s\S]*(?:\\Packages\\|AppRepository|\\Microsoft\.|\\MicrosoftWindows\.)", re.I)),
]
rpt_EXPLAIN = [  # (regex, short title, why it matters, recommended action)
    (re.compile(r"EID\s*(104|1102)|log cleared", re.I), "Event log cleared", "Clearing System/Security logs is a classic anti-forensics step (T1070.001); evidence before the clear time may be lost.", "Treat host as compromised; recover logs from backups/SIEM and check who held admin rights at the clear time."),
    (re.compile(r"Ransomware Activity|ransom", re.I), "Ransomware behaviour reported by EDR", "The EDR itself raised ransomware-type alerts on this host.", "Isolate the host, confirm encrypted files, and preserve the EDR console data."),
    (re.compile(r"File Quarantined|EID\s*5007|quarantin|malware detected|Defender.*(detect|threat)", re.I), "Defender quarantined / detected a file", "Antivirus caught a malicious or unwanted file; the file name/threat name show what was dropped.", "Review the quarantined item and its path, and hunt for sibling files and the process that wrote it."),
    (re.compile(r"EID\s*7045|New Service", re.I), "New service installed", "Malware and remote-exec tools commonly install services (T1543.003).", "Verify each service binary path/signature; remove unknown ones."),
    (re.compile(r"EID\s*4104|Script Block|PowerShell", re.I), "PowerShell script-block activity", "Encoded/obfuscated PowerShell is used for download cradles and in-memory payloads (T1059.001).", "Decode the script blocks and extract URLs/IPs/files."),
    (re.compile(r"MEMORY_INJECT|malfind|injection", re.I), "Code injection indicator in memory", "RWX/injected regions can mean process injection (frequent false positives in browsers/.NET).", "Dump and inspect the regions only for processes that are also suspicious for other reasons."),
    (re.compile(r"MEMORY_CMDLI|cmdline in memory|Malicious cmd", re.I), "Malicious command line in memory", "A live process was started with a command line matching attacker tradecraft.", "Identify the parent chain and the account that started it."),
    (re.compile(r"registry|autorun|persist|Run key|REGISTRY", re.I), "Registry persistence", "Autorun keys make malware survive reboots (T1547.001).", "Check the referenced binaries; delete the value and quarantine the file."),
    (re.compile(r"Dump|lsass|Mimikatz|credential|Whoami|sensitive hives", re.I), "Credential access / discovery", "Dumping hives/LSASS or enumerating privileges precedes lateral movement (T1003).", "Reset exposed credentials and review authentication logs."),
    (re.compile(r"Auditpol|audit policy|Disable.*Defender|tamper", re.I), "Defence evasion / tampering", "Disabling auditing or AV prevents detection (T1562).", "Restore policy via GPO and look for who changed it."),
]


def rpt__ts(f):
    d = f.get("data") if isinstance(f.get("data"), dict) else {}
    for k in ("ts", "timestamp_event", "time", "TimeCreated", "SystemTime", "timestamp"):
        v = f.get(k) or d.get(k)
        if v and str(v)[:4].isdigit(): return str(v)[:19].replace("T", " ")
    return ""


def rpt_norm(desc):
    t = re.sub(r"0x[0-9a-fA-F]+", "#", str(desc))
    t = re.sub(r"\b\d{2,}\b", "#", t)
    return re.sub(r"\s+", " ", t).strip()[:110]


def rpt_explain(text):
    for rx, title, why, act in rpt_EXPLAIN:
        if rx.search(text): return title, why, act
    return None


def rpt_group(data):
    """Collapse duplicates -> [{sev,source,desc,count,first,last,sample,explain}] + noise buckets."""
    groups, noise = {}, Counter()
    for sev in ("critical", "high", "medium"):
        for f in data.get(sev, []) or []:
            src, desc = str(f.get("source", "")), str(f.get("desc", ""))
            blob = f"{src} {desc} {f.get('data', '')}"
            skip = next((n for n, rx in rpt_NOISE if rx.search(blob)), None)
            if skip: noise[skip] += 1; continue
            key = (sev, src, rpt_norm(desc))
            g = groups.setdefault(key, {"sev": sev.upper(), "source": src, "desc": desc, "count": 0, "ts": [], "sample": str(f.get("data", ""))[:160]})
            g["count"] += 1
            t = rpt__ts(f)
            if t: g["ts"].append(t)
    out = []
    for g in groups.values():
        g["first"], g["last"] = (min(g["ts"]), max(g["ts"])) if g["ts"] else ("", "")
        g["explain"] = rpt_explain(f"{g['source']} {g['desc']}")
        out.append(g)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    out.sort(key=lambda g: (order[g["sev"]], -g["count"]))
    return out, noise


def rpt_episodes(data, gap_min=60):
    """Cluster CRITICAL/HIGH timeline events into attack windows."""
    ev = []
    for e in data.get("timeline", []) or []:
        sev = str(e.get("sev", "")).upper()
        if sev not in ("CRITICAL", "HIGH"): continue
        blob = f"{e.get('src', '')} {e.get('desc', '')} {e.get('det', e.get('detail', ''))}"
        if any(rx.search(blob) for _, rx in rpt_NOISE): continue
        try: t = datetime.strptime(str(e.get("ts", ""))[:19], "%Y-%m-%d %H:%M:%S")
        except Exception: continue
        ev.append((t, sev, blob))
    ev.sort()
    eps, cur = [], None
    for t, sev, blob in ev:
        if cur and (t - cur["end"]).total_seconds() <= gap_min * 60:
            cur["end"] = t; cur["ev"].append((sev, blob)); cur["evt"].append((t, sev, blob))
        else:
            cur = {"start": t, "end": t, "ev": [(sev, blob)], "evt": [(t, sev, blob)]}; eps.append(cur)
    rows = []
    for e in eps:
        cats = Counter()
        for sev, blob in e["ev"]:
            x = rpt_explain(blob)
            cats[x[0] if x else rpt_norm(blob)[:50]] += 1
        crit = sum(1 for s, _ in e["ev"] if s == "CRITICAL")
        e["score"] = crit * 3 + len(e["ev"])
        e["cats"] = cats
        rows.append(e)
    return rows


def rpt_signals(data, groups, noise, cor):
    """Plain-language key points computed from the facts."""
    pts = []
    def cnt(rx): return sum(g["count"] for g in groups if re.search(rx, f"{g['source']} {g['desc']}", re.I))
    def span(rx):
        ts = [t for g in groups if re.search(rx, f"{g['source']} {g['desc']}", re.I) for t in g["ts"]]
        return (min(ts)[:10], max(ts)[:10]) if ts else None
    n = cnt(r"EID\s*(104|1102)|log cleared")
    if n: s = span(r"EID\s*(104|1102)|log cleared"); pts.append(f"System/Audit logs were cleared {n} time(s)" + (f" ({s[0]} to {s[1]})" if s else "") + " - anti-forensics; earlier evidence may be lost.")
    n = cnt(r"Ransomware Activity")
    if n: pts.append(f"The EDR raised {n} ransomware-activity alert(s).")
    n = cnt(r"File Quarantined|EID\s*5007")
    if n: s = span(r"File Quarantined|EID\s*5007"); pts.append(f"Defender/EDR quarantined {n} file(s)" + (f" between {s[0]} and {s[1]}" if s and s[0] != s[1] else (f" on {s[0]}" if s else "")) + ".")
    n = cnt(r"EID\s*7045|New Service")
    if n: pts.append(f"{n} new service installation event(s) were recorded.")
    n = cnt(r"EID\s*4104|Script Block")
    if n: pts.append(f"{n} PowerShell script-block event(s) were flagged - decode them for download cradles / payloads.")
    n = cnt(r"MEMORY_CMDLI|Malicious cmd")
    if n: pts.append(f"{n} malicious command line(s) were found in memory.")
    reg = [i for i in (cor or {}).get("indicators", {}).values() if i["kind"] in ("registry", "persistence") and i["score"] >= 3]
    if reg: pts.append("Autorun persistence points to non-standard locations: " + ", ".join(sorted({i["name"] for i in reg})[:6]) + ".")
    return pts


def rpt_blocks(os_type, evidence, data, summary, cor_secs, review, cor, mem_sections=None, case=None, scope=None, ioc_rows=None):
    """-> blocks: ('h1',t) ('h2',t) ('p',t) ('b',[..]) ('t',headers,rows) ('risk',lvl) ('title',t)"""
    B = []
    _n = [0]
    def H1(t):
        _n[0] += 1; B.append(("h1", f"{_n[0]}. {t}"))
    groups, noise = rpt_group(data)
    eps = rpt_episodes(data)
    crit_u = sum(1 for g in groups if g["sev"] == "CRITICAL"); high_u = sum(1 for g in groups if g["sev"] == "HIGH")
    raw_c, raw_h = len(data.get("critical", []) or []), len(data.get("high", []) or [])
    lvl = "CRITICAL" if crit_u else "HIGH" if high_u else "MEDIUM" if groups else "LOW"
    ce = (cor or {}).get("entry") or {}
    bad_ioc = [r for r in (ioc_rows or []) if r["verdict"] == "MALICIOUS"]
    sus_ioc = [r for r in (ioc_rows or []) if r["verdict"] == "SUSPICIOUS"]
    B.append(("title", "Forensic Investigation Report" + (f" - {case}" if case else "")))
    _host = ", ".join((scope or {}).get("hosts", [])[:2]) or "not identified"
    B.append(("p", (f"Case: {case}   |   " if case else "") + f"Host: {_host}   |   Platform: {os_type.upper()}   |   Evidence: {evidence}   |   Generated: {datetime.now():%Y-%m-%d %H:%M:%S}"))

    # 1 ---------------------------------------------------------------- executive summary
    H1("Executive Summary")
    B.append(("risk", lvl))
    sig = rpt_signals(data, groups, noise, cor)
    if ce.get("status") in ("DETERMINED", "PROBABLE"):
        tt = ce.get("time"); tt = epr_fmt(tt) if isinstance(tt, datetime) else tt
        sig.insert(0, f"Entry point ({ce['status'].lower()}): {ce.get('vector')} at {tt}.")
    elif ce.get("status") in ("PARTIAL", "NOT DETERMINED"):
        sig.insert(0, "Entry point could not be proven from the supplied evidence - see the Incident Narrative for the closest correlated log evidence and what is missing.")
    if bad_ioc: sig.append("Reputation check: " + ", ".join(f"{r['value']} ({r['mal']}/{r['total']} engines, {r['country']})" for r in bad_ioc[:4]) + " flagged malicious.")
    if not sig: sig = ["No high-confidence attacker activity was identified in the supplied evidence."]
    B.append(("b", sig))
    B.append(("t", ["Metric", "Value"], [
        ["Unique critical findings", f"{crit_u}  (from {raw_c} raw hits)"], ["Unique high findings", f"{high_u}  (from {raw_h} raw hits)"],
        ["Attack windows detected", str(len(eps))], ["Malicious / suspicious IOCs (reputation)", f"{len(bad_ioc)} / {len(sus_ioc)}"],
        ["Informational items omitted", str(sum(noise.values()))], ["External IPs observed", str(len(data.get("external_ips", []) or []))]]))

    # 2 ---------------------------------------------------------------- host & scope
    if scope:
        H1("Host & Evidence Scope")
        B.append(("h2", "Affected host")); B.append(("t", ["Field", "Value"], scope["host_rows"]))
        B.append(("h2", "Evidence provided"))
        B.append(("t", ["Artifact", "Files", "Size", "File dates", "Names"], scope["inventory"] or [["-", "no recognised artifacts", "", "", ""]]))
        B.append(("h2", "Artifacts NOT provided (limits what this report can prove)"))
        B.append(("t", ["Artifact", "Status", "What it would show"], scope["missing"] or [["-", "all expected artifacts present", ""]]))
        if scope.get("coverage"):
            B.append(("h2", "Log coverage (time range actually present in each log)"))
            B.append(("t", ["Log", "Records scanned", "First event", "Last event"], scope["coverage"][:40]))

    # 3 ---------------------------------------------------------------- incident narrative
    H1("Incident Narrative - what happened and how")
    if review:
        para = []
        for ln in review.splitlines():
            t = ln.strip().replace("**", "")
            if not t: continue
            if t.isupper() and len(t) < 60:
                if para: B.append(("p", " ".join(para))); para = []
                B.append(("h2", t.title()))
            elif t[:2] in ("- ", "* ", "• ") or re.match(r"\d+[.)] ", t):
                if para: B.append(("p", " ".join(para))); para = []
                B.append(("b", [re.sub(r"^(?:[-*•]|\d+[.)])\s+", "", t)]))
            else: para.append(t)
        if para: B.append(("p", " ".join(para)))
    else:
        for t, txt in rpt_narrative(os_type, data, groups, eps, cor, scope, ioc_rows):
            B.append(("h2", t)); B.append(("p", txt))
    if ce.get("status") not in ("DETERMINED", "PROBABLE"):
        rows, notes = rpt_entry_logs(cor, eps, scope)
        B.append(("h2", "Entry point not proven - closest correlated log evidence"))
        for nt in notes: B.append(("p", nt))
        B.append(("t", ["Time", "Source", "Detail", "Log"], rows or [["-", "-", "No remote logon or first-activity record found in the supplied logs", ""]]))

    # 4 ---------------------------------------------------------------- timeline mapping
    H1("Timeline Mapping")
    if eps:
        top = sorted(eps, key=lambda e: -e["score"])[:12]; top.sort(key=lambda e: e["start"])
        rows = []
        for e in top:
            act = "; ".join(f"{k} x{v}" for k, v in e["cats"].most_common(5))
            rows.append([f"{e['start']:%Y-%m-%d %H:%M} - {e['end']:%H:%M}" if e["start"].date() == e["end"].date() else f"{e['start']:%Y-%m-%d %H:%M} - {e['end']:%Y-%m-%d %H:%M}", str(len(e["ev"])), act])
        B.append(("h2", "Attack windows")); B.append(("t", ["Window", "Events", "Activity"], rows))
        B.append(("h2", "Key events inside the windows (first occurrence of each activity type)"))
        B.append(("t", ["Sev", "First seen", "Activity", "Count", "Example"], rpt_timeline_rows(eps)))
    else:
        B.append(("p", "No clustered high-severity activity with timestamps was found."))

    # 5 ---------------------------------------------------------------- correlation tables
    if cor_secs:
        H1("Entry Point & Cross-Source Correlation")
        for t, hd, rows in cor_secs:
            if t == "Cross-Source Correlation Matrix": rows = rows[:25]
            if t == "Entry Point Evidence Timeline": rows = rows[:15]
            B.append(("h2", t)); B.append(("t", hd, rows))
    if mem_sections:
        H1("Memory Analysis")
        for t, hd, rows in mem_sections:
            if t in ("Suspicious Findings", "Memory Image Info", "Services", "All Network Connections", "Processes (by creation time)", "Command Lines"): rows = rows[:60]
            B.append(("h2", t)); B.append(("t", hd, rows[:150]))

    # 6 ---------------------------------------------------------------- key findings
    H1("Key Findings (de-duplicated)")
    rows = []
    for g in groups[:60]:
        when = g["first"] if g["first"] == g["last"] else f"{g['first']} -> {g['last']}" if g["first"] else "-"
        rows.append([g["sev"], g["desc"][:130], g["source"][:30], str(g["count"]), when, (g["explain"][1] if g["explain"] else "")[:170]])
    B.append(("t", ["Sev", "Finding", "Source", "Count", "First -> Last seen", "Why it matters"], rows or [["-", "No findings", "", "", "", ""]]))
    if len(groups) > 60: B.append(("p", f"{len(groups) - 60} further lower-priority finding groups are in the supporting data."))
    if noise: B.append(("p", "Informational items omitted from this report: " + "; ".join(f"{k} ({v})" for k, v in noise.items()) + "."))

    # 7 ---------------------------------------------------------------- IOCs + reputation
    H1("Indicators of Compromise & Reputation")
    if ioc_rows:
        hd, rws = ioc_table(ioc_rows)
        B.append(("h2", "Network / hash IOCs with VirusTotal reputation")); B.append(("t", hd, rws))
        if any(r["verdict"].startswith("not checked") for r in ioc_rows):
            B.append(("p", "Rows marked 'not checked' were not looked up (no API key, or the free-tier rate limit / call budget was reached). Re-run Analyze to continue; results are cached."))
    else:
        B.append(("p", "No network IOCs were extracted for reputation checking."))
    ioc = []
    for i in sorted((cor or {}).get("indicators", {}).values(), key=lambda x: -x["score"])[:30]:
        if i["score"] >= 3 and i["kind"] in ("registry", "persistence", "service", "process", "command"):
            ioc.append([i["kind"], i["name"], (i["path"] or "")[:110], "; ".join(i["reasons"])[:150]])
    for r in (data.get("registry_hits") or [])[:25]:
        ioc.append(["registry", str(r.get("name", ""))[:40], f"{r.get('key', '')}"[:110], str(r.get("data", ""))[:150]])
    B.append(("h2", "Host-based IOCs (files, processes, persistence)"))
    B.append(("t", ["Type", "Indicator", "Location", "Why"], ioc or [["-", "No host indicator reached the reporting threshold", "", ""]]))

    # 8 ---------------------------------------------------------------- recommendations
    acts, seen = [], set()
    for r in bad_ioc[:5]: acts.append(f"Block {r['value']} ({r['asn']}, {r['country']}) at the firewall/proxy and search all logs for other hosts that contacted it.")
    for g in groups:
        if g["explain"] and g["explain"][0] not in seen:
            seen.add(g["explain"][0]); acts.append(f"{g['explain'][0]}: {g['explain'][2]}")
    for i in (cor or {}).get("indicators", {}).values():
        if i["kind"] in ("registry", "persistence") and i["score"] >= 3 and "Registry persistence" not in seen:
            seen.add("Registry persistence"); acts.append("Persistence: remove the autorun entries listed in the IOC section and quarantine the referenced files.")
    if ce.get("status") not in ("DETERMINED", "PROBABLE"):
        acts.append("Entry point: obtain the missing log sources listed under Artifacts NOT provided (especially authentication and process-creation logs) and re-run the analysis.")
    acts.append("Preserve all evidence and keep the host isolated until scoping is complete.")
    H1("Recommended Actions")
    B.append(("b", acts[:12]))
    return B


def rpt_docx(blocks, out_dir, stem="forensics_report"):
    from docx import Document
    from docx.shared import Pt, RGBColor, Cm
    from docx.enum.section import WD_ORIENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    for side in ("left_margin", "right_margin", "top_margin", "bottom_margin"): setattr(sec, side, Cm(1.6))
    st = doc.styles["Normal"]; st.font.name = "Calibri"; st.font.size = Pt(10)
    colors = {"CRITICAL": RGBColor(0xC0, 0x39, 0x2B), "HIGH": RGBColor(0xE6, 0x7E, 0x22), "MEDIUM": RGBColor(0xB7, 0x95, 0x0B), "LOW": RGBColor(0x1E, 0x84, 0x49)}

    def shade(cell, hexcol):
        tcPr = cell._tc.get_or_add_tcPr(); shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hexcol); tcPr.append(shd)
    for b in blocks:
        k = b[0]
        if k == "title": doc.add_heading(b[1], 0)
        elif k == "h1": doc.add_heading(b[1], 1)
        elif k == "h2": doc.add_heading(b[1], 2)
        elif k == "p": doc.add_paragraph(b[1])
        elif k == "risk":
            p = doc.add_paragraph(); r = p.add_run("Overall risk: "); r.bold = True
            r2 = p.add_run(b[1]); r2.bold = True; r2.font.size = Pt(14); r2.font.color.rgb = colors.get(b[1], RGBColor(0, 0, 0))
        elif k == "b":
            for x in b[1]: doc.add_paragraph(str(x), style="List Bullet")
        elif k == "t":
            hd, rows = b[1], b[2]
            t = doc.add_table(rows=1, cols=len(hd)); t.style = "Table Grid"
            for i, x in enumerate(hd):
                c = t.rows[0].cells[i]; c.text = ""; run = c.paragraphs[0].add_run(str(x)); run.bold = True; run.font.size = Pt(9)
                run.font.color.rgb = RGBColor(255, 255, 255); shade(c, "1F3A5F")
            for r in rows:
                cells = t.add_row().cells
                for i, v in enumerate(list(r)[:len(hd)]):
                    cells[i].text = ""; run = cells[i].paragraphs[0].add_run(str(v)[:400]); run.font.size = Pt(8.5)
                    if str(v) in colors and i == 0: run.bold = True; run.font.color.rgb = colors[str(v)]
            doc.add_paragraph()
    doc.add_paragraph(f"Generated by Forensics Master Analyzer - {datetime.now():%Y-%m-%d %H:%M:%S}")
    out = Path(out_dir) / f"{stem}.docx"
    doc.save(str(out)); return str(out)


def rpt_pdf(blocks, out_dir, stem="forensics_report"):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors as C
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from xml.sax.saxutils import escape as E
    ss = getSampleStyleSheet()
    T = ParagraphStyle("T", parent=ss["Title"], fontSize=22, textColor=C.HexColor("#1F3A5F"))
    H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=14, textColor=C.HexColor("#1F3A5F"), spaceBefore=12, spaceAfter=5)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11, textColor=C.HexColor("#2E5C8A"), spaceBefore=8, spaceAfter=3)
    Bd = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9, leading=12)
    Bl = ParagraphStyle("Bl", parent=Bd, leftIndent=12, bulletIndent=2)
    Cl = ParagraphStyle("Cl", parent=Bd, fontSize=7.5, leading=9)
    Ch = ParagraphStyle("Ch", parent=Cl, textColor=C.white, fontName="Helvetica-Bold")
    sevc = {"CRITICAL": "#C0392B", "HIGH": "#E67E22", "MEDIUM": "#B7950B", "LOW": "#1E8449"}
    W = landscape(A4)[0] - 2.4 * cm
    S = []
    for b in blocks:
        k = b[0]
        if k == "title": S.append(Paragraph(E(b[1]), T))
        elif k == "h1": S.append(Paragraph(E(b[1]), H1))
        elif k == "h2": S.append(Paragraph(E(b[1]), H2))
        elif k == "p": S.append(Paragraph(E(b[1]), Bd)); S.append(Spacer(1, 3))
        elif k == "risk":
            S.append(Paragraph(f'<b>Overall risk:</b> <font size="14" color="{sevc.get(b[1], "#000000")}"><b>{E(b[1])}</b></font>', Bd)); S.append(Spacer(1, 4))
        elif k == "b":
            for x in b[1]: S.append(Paragraph(E(str(x)), Bl, bulletText="•"))
            S.append(Spacer(1, 4))
        elif k == "t":
            hd, rows = b[1], b[2]
            n = max(1, len(hd))
            lens = [max([len(str(hd[i]))] + [min(len(str(r[i])) if i < len(r) else 0, 60) for r in rows[:40]]) + 6 for i in range(n)]
            tot = float(sum(lens)); cw = [max(W * l / tot, 1.6 * cm) for l in lens]
            sc = W / sum(cw); cw = [c * sc for c in cw]
            data = [[Paragraph(E(str(x)), Ch) for x in hd]]
            for r in rows:
                row = []
                for i in range(n):
                    v = str(r[i]) if i < len(r) else ""
                    if i == 0 and v in sevc: row.append(Paragraph(f'<font color="{sevc[v]}"><b>{E(v)}</b></font>', Cl))
                    else: row.append(Paragraph(E(v[:300]), Cl))
                data.append(row)
            tb = Table(data, colWidths=cw, repeatRows=1)
            tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), C.HexColor("#1F3A5F")), ("GRID", (0, 0), (-1, -1), 0.3, C.HexColor("#B8C2CC")),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C.white, C.HexColor("#F3F6F9")]),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
            S.append(tb); S.append(Spacer(1, 6))
    S.append(Paragraph(f"Generated by Forensics Master Analyzer - {datetime.now():%Y-%m-%d %H:%M:%S}", Cl))
    out = Path(out_dir) / f"{stem}.pdf"
    def foot(canv, doc_):
        canv.saveState(); canv.setFont("Helvetica", 7); canv.setFillColor(C.grey)
        canv.drawRightString(landscape(A4)[0] - 1.2 * cm, 0.8 * cm, f"Page {doc_.page}"); canv.restoreState()
    SimpleDocTemplate(str(out), pagesize=landscape(A4), leftMargin=1.2 * cm, rightMargin=1.2 * cm, topMargin=1.2 * cm, bottomMargin=1.4 * cm).build(S, onFirstPage=foot, onLaterPages=foot)
    return str(out)


def uni_tidy(out):
    """Keep the output root clean: final report files + analysis_* only; everything else -> supporting_data/."""
    out = Path(out); sup = out / "supporting_data"
    try: sup.mkdir(exist_ok=True)
    except Exception: return
    keep = re.compile(r"(_report|^forensics_report)(_\d{8}_\d{4}-\d{8}_\d{4})?\.(pdf|docx|html)$")
    for p in list(out.iterdir()):
        if p.name == "supporting_data" or p.name.startswith("analysis_") or keep.search(p.name): continue
        dest = sup / p.name
        if dest.exists(): dest = sup / f"{p.stem}_{int(time.time())}{p.suffix}"
        try: shutil.move(str(p), str(dest))
        except Exception: pass


def uni_cli_finish(out, os_type, evidence, html_path, vt_key=None, abuse_key=None):
    """CLI runs: build the ONE combined report (PDF + DOCX + HTML) and tidy the folder. Web runs do this themselves."""
    if UNI_CTX.get("web"): return html_path
    try:
        job = {"output_dir": str(out), "os_type": os_type, "evidence": str(evidence or ""), "log": [], "analyses": {}, "case": None, "ai": None,
               "vt_key": vt_key, "abuse_key": abuse_key}
        rw_run(job, "full", None, None, False)
        a = job["analyses"].get("full", {})
        uni_tidy(out)
        if a.get("state") == "done":
            return str(Path(out) / Path(a["html"]).name)
    except Exception:
        pass
    return html_path


def uni_results_payload(results):
    """Normalise a results dict (any OS) into report-model data."""
    def row(f):
        d = f.get("data") if isinstance(f.get("data"), dict) else {"value": str(f.get("data", ""))}
        ts = ""
        for k in ("timestamp", "time", "TimeCreated", "SystemTime", "ts"):
            if d.get(k) and str(d[k])[:4].isdigit(): ts = str(d[k])[:19].replace("T", " "); break
        short = " | ".join(f"{k}={str(v)[:80]}" for k, v in list(d.items())[:5])
        return {"severity": f.get("severity", ""), "source": f.get("source", ""), "desc": f.get("desc", ""), "ts": ts, "data": short[:300], "file": f.get("file", "")}
    try:
        tl = []
        for e in (results.get("timeline") or [])[:20000]:
            tl.append({"ts": str(e.get("ts", ""))[:19], "sev": e.get("sev", ""), "src": e.get("src", ""), "desc": e.get("desc", ""),
                       "det": str(e.get("detail", e.get("det", "")))[:200]})
        if not tl:      # derive from timestamped findings (event time)
            for sev in ("critical", "high"):
                for f in results.get(sev, [])[:8000]:
                    r_ = row(f)
                    if r_["ts"]: tl.append({"ts": r_["ts"], "sev": sev.upper(), "src": r_["source"], "desc": r_["desc"], "det": r_["data"][:200]})
            tl.sort(key=lambda x: x["ts"])
        payload = {"critical": [row(f) for f in results.get("critical", [])[:6000]], "high": [row(f) for f in results.get("high", [])[:6000]],
                   "medium": [row(f) for f in results.get("medium", [])[:3000]], "timeline": tl,
                   "external_ips": sorted(str(x) for x in (results.get("external_ips") or [])),
                   "registry_hits": [{k: str(v)[:200] for k, v in r.items()} for r in (results.get("registry_hits") or [])[:200]],
                   "c2_indicators": [{k: str(v)[:200] for k, v in r.items()} if isinstance(r, dict) else {"ip": str(r)} for r in (results.get("c2_indicators") or [])[:200]],
                   "threat_intel": [{k: str(v)[:120] for k, v in r.items()} for r in (results.get("threat_intel") or [])[:200] if isinstance(r, dict)]}
        return payload
    except Exception:
        return {"critical": [], "high": [], "medium": [], "timeline": [], "external_ips": []}


def uni_dump_results(results, out):
    try: Path(out, "report_data.json").write_text(json.dumps(uni_results_payload(results), default=str), encoding="utf-8")
    except Exception: pass


def uni_save_cor(cor, out):
    out = Path(out)
    secs = [[t, h, [[str(c) for c in r] for r in rows]] for t, h, rows in cor_sections(cor)]
    (out / "correlation_sections.json").write_text(json.dumps(secs, default=str), encoding="utf-8")
    (out / "correlation.json").write_text(json.dumps({"entry": cor["entry"], "stats": cor["stats"], "gaps": cor["gaps"], "cross": cor["cross"], "meta": cor.get("meta", {}), "entries": cor.get("entries", {}), "labels": cor.get("labels", {}),
        "indicators": {k: {**{kk: vv for kk, vv in v.items() if kk not in ("tokens", "pids", "events", "first_proc", "disk")},
                           "tokens": sorted(v["tokens"]), "pids": sorted(v["pids"])} for k, v in cor["indicators"].items()}},
        indent=2, default=str), encoding="utf-8")
    return secs


def uni_review_ok(text):
    """Reject replies that merely describe the input (small-model failure mode)."""
    if not text or len(text.split()) < 60: return False
    bad = re.compile(r"(provided text|appears to be a series|the text (?:includes|starts|suggests)|tool_finding_counts|notes_made_while|JSON object|breakdown of the content|log entries (?:labeled|are)|large log file|summary of the content|this log file|divided into \d+ batches)", re.I)
    return not bad.search(text)


def uni_briefing(data, cor, ioc_rows=None, narrative=None):
    """Readable briefing (plain text) for the analyst engine - far better than raw JSON for small models."""
    groups, noise = rpt_group(data)
    L = ["INVESTIGATION BRIEFING (facts only)"]
    L.append("TOP FINDINGS (deduplicated, count, first-last):")
    for g in groups[:25]:
        L.append(f"- [{g['sev']}] {g['desc'][:110]} | x{g['count']} | {g['first']} -> {g['last']}")
    eps = rpt_episodes(data)
    if eps:
        L.append("ATTACK WINDOWS:")
        for e in sorted(eps, key=lambda x: -x["score"])[:8]:
            L.append(f"- {e['start']:%Y-%m-%d %H:%M} to {e['end']:%H:%M}: " + "; ".join(f"{k} x{v}" for k, v in e["cats"].most_common(4)))
    if cor:
        ce = cor["entry"]
        L.append(f"ENTRY POINT RESULT: status={ce['status']} vector={ce['vector']} time={ce['time']} account={ce['account']} source={ce['source_ip']}")
        L.append("PROCESS CHAIN: " + " -> ".join(ce["chain"]) if ce["chain"] else "PROCESS CHAIN: none")
        L.append("INDICATORS:")
        for i in sorted(cor["indicators"].values(), key=lambda x: -x["score"])[:15]:
            L.append(f"- {i['name']} ({i['kind']}, score {i['score']}): {'; '.join(i['reasons'][:3])} | memory={i['in_memory']} disk={i['in_hive']} logs={i['event_count']}")
        L.append("REGISTRY/SHELL CROSS-CHECK:")
        for c in cor["cross"][:12]: L.append(f"- {c['key']} {c['name']} = {c['data'][:110]} | disk: {c['disk']} | logs: {c['events']}")
        L.append("GAPS: " + " | ".join(f"{a}: {g}" for a, g in cor["gaps"]))
        meta = cor.get("meta") or {}
        if meta.get("remote_logons"):
            L.append("REMOTE LOGONS SEEN IN LOGS (time, user, source, type):")
            for l in meta["remote_logons"][:20]: L.append(f"- {l[0]} {l[1]} from {l[2]} type {l[3]}")
    if ioc_rows:
        L.append("IOC REPUTATION:")
        for r in ioc_rows[:20]: L.append(f"- {r['value']} ({r['kind']}) verdict={r['verdict']} vt={r['mal']}/{r['total']} asn={r['asn']} country={r['country']} | {r['ctx'][:80]}")
    if narrative:
        L.append("FACT-BASED DRAFT NARRATIVE (improve the wording, do not add facts):")
        for t, txt in narrative: L.append(f"[{t}] {txt}")
    return "\n".join(L)[:28000]


# ═══════════════════════════════════════════════════════════════════════════
# HOST & EVIDENCE SCOPE: which machine, what artifacts were supplied, what is missing
# ═══════════════════════════════════════════════════════════════════════════
_SC_MEM_EXT = (".raw", ".mem", ".vmem", ".lime", ".dmp", ".bin", ".vmsn", ".aff4", ".core")

# (key, label, impact-if-missing) per OS; matchers live in uni__classify
sc_EXPECTED = {
    "windows": [
        ("evtx_security", "Security.evtx", "Logons (4624/4625), process creation (4688), account changes - needed to prove WHO got in and HOW"),
        ("evtx_system", "System.evtx", "Service installs (7045), log clearing (104), shutdowns"),
        ("evtx_sysmon", "Sysmon Operational log", "Process tree, network connections, file/registry changes with hashes"),
        ("evtx_ps", "PowerShell Operational log", "Script blocks (4104) - payloads and download cradles"),
        ("evtx_task", "Task Scheduler log", "Scheduled-task persistence / execution"),
        ("evtx_defender", "Windows Defender log", "Detections, quarantines, protection disabled"),
        ("evtx_rdp", "Terminal Services / RDP logs", "Remote Desktop sessions and source IPs"),
        ("evtx_any", "Any .evtx event logs", "All log-based correlation"),
        ("hive_system", "SYSTEM hive", "Services, ControlSet, timezone, USB history"),
        ("hive_software", "SOFTWARE hive", "Run keys, installed software, IFEO, OS version"),
        ("hive_sam", "SAM / SECURITY hive", "Local accounts, last logons"),
        ("hive_ntuser", "NTUSER.DAT (per user)", "User Run keys, RecentDocs, UserAssist, typed paths"),
        ("hive_usrclass", "UsrClass.dat", "Shellbags, user COM hijacks"),
        ("amcache", "Amcache.hve", "First-execution evidence with SHA1 hashes"),
        ("hive_logs", "Hive transaction logs (.LOG1/.LOG2)", "Recent registry changes not yet merged into the hive"),
        ("prefetch", "Prefetch (*.pf)", "Which programs ran, how many times, last 8 run times"),
        ("mft", "$MFT", "File creation/deletion/timestomp timeline"),
        ("usn", "$UsnJrnl ($J)", "File create/rename/delete history (ransomware encryption trail)"),
        ("lnk", "LNK / Jump Lists", "Files and programs the user opened"),
        ("srum", "SRUM (SRUDB.dat)", "Per-app network usage and execution history"),
        ("browser", "Browser history", "Download source / phishing URL"),
        ("tasks", "Scheduled task XML files", "Task actions and triggers"),
        ("pshist", "PowerShell history (ConsoleHost_history.txt)", "Interactive commands typed by the user"),
        ("memory", "Memory dump", "Live processes, network, injected code, registry in RAM"),
        ("pcap", "Network capture (pcap)", "C2 traffic, exfiltration volume"),
    ],
    "linux": [
        ("auth", "auth.log / secure", "SSH / sudo / su logins and source IPs"),
        ("syslog", "syslog / messages", "Service and kernel events"),
        ("audit", "audit.log (auditd)", "Process execution (EXECVE), file access, user sessions"),
        ("journal", "systemd journal", "Unit start/stop and logs"),
        ("history", "Shell history (.bash_history / .zsh_history)", "Commands typed by users"),
        ("cron", "Cron files", "Scheduled persistence"),
        ("wtmp", "wtmp / btmp / lastlog", "Login history and failed logins"),
        ("accounts", "passwd / shadow / group / sudoers", "Accounts, privilege and backdoor users"),
        ("sshkeys", "authorized_keys", "SSH key persistence"),
        ("weblogs", "Web server logs", "Web-shell / exploit requests"),
        ("snapshots", "Process / network snapshots (ps, lsof, netstat, ss)", "Live state when collected"),
        ("memory", "Memory dump", "Live processes, network, shell history in RAM"),
        ("pcap", "Network capture (pcap)", "C2 traffic, exfiltration"),
    ],
    "macos": [
        ("unified", "Unified log / logarchive", "Process, network and auth events"),
        ("syslog", "system.log / install.log", "System and install history"),
        ("launchd", "LaunchAgents / LaunchDaemons plists", "Persistence"),
        ("quarantine", "QuarantineEventsV2", "Where downloaded files came from"),
        ("tcc", "TCC.db", "Privacy permission grants"),
        ("history", "Shell history (.zsh_history / .bash_history)", "Commands typed by users"),
        ("fsevents", "FSEvents", "File activity timeline"),
        ("cron", "Cron files", "Scheduled persistence"),
        ("memory", "Memory dump", "Live processes and network in RAM"),
        ("pcap", "Network capture (pcap)", "C2 traffic, exfiltration"),
    ],
}


def uni__classify(os_type, p, nl, pl):
    """Return the artifact keys a file satisfies. nl = lowercase name, pl = lowercase posix path."""
    k = []
    o = cor_profile(os_type)["os"]
    ext = Path(nl).suffix
    if ext in _SC_MEM_EXT: k.append("memory")
    if ext in (".pcap", ".pcapng", ".cap"): k.append("pcap")
    if o == "windows":
        if ext == ".evtx":
            k.append("evtx_any")
            if nl == "security.evtx": k.append("evtx_security")
            if nl == "system.evtx": k.append("evtx_system")
            if "sysmon" in nl: k.append("evtx_sysmon")
            if "powershell" in nl: k.append("evtx_ps")
            if "taskscheduler" in nl: k.append("evtx_task")
            if "defender" in nl: k.append("evtx_defender")
            if "terminalservices" in nl or "remotedesktop" in nl: k.append("evtx_rdp")
        if nl == "system" and not ext: k.append("hive_system")
        if nl == "software" and not ext: k.append("hive_software")
        if nl in ("sam", "security") and not ext: k.append("hive_sam")
        if nl.startswith("ntuser.dat") and not nl.endswith((".log1", ".log2")): k.append("hive_ntuser")
        if nl.startswith("usrclass.dat") and not nl.endswith((".log1", ".log2")): k.append("hive_usrclass")
        if nl.startswith("amcache.hve"): k.append("amcache")
        if nl.endswith((".log1", ".log2")): k.append("hive_logs")
        if ext == ".pf": k.append("prefetch")
        if nl in ("$mft", "mft", "$mft.bin") or nl.endswith("$mft"): k.append("mft")
        if "usnjrnl" in nl or nl in ("$j",): k.append("usn")
        if ext == ".lnk" or "automaticdestinations-ms" in nl or "customdestinations-ms" in nl: k.append("lnk")
        if nl == "srudb.dat": k.append("srum")
        if nl in ("history", "places.sqlite", "webcachev01.dat") and any(x in pl for x in ("chrome", "edge", "firefox", "mozilla", "brave", "microsoft")) or nl == "places.sqlite": k.append("browser")
        if "/system32/tasks/" in pl or "/windows/tasks/" in pl: k.append("tasks")
        if nl == "consolehost_history.txt": k.append("pshist")
    elif o == "linux":
        if re.match(r"(auth\.log|secure)(\.\d+|\.gz)*$", nl): k.append("auth")
        if re.match(r"(syslog|messages|kern\.log|daemon\.log)(\.\d+|\.gz)*$", nl): k.append("syslog")
        if nl.startswith("audit.log"): k.append("audit")
        if ext == ".journal" or "journal" in pl and nl.endswith((".txt", ".log", ".json")): k.append("journal")
        if nl in (".bash_history", "bash_history", ".zsh_history", "zsh_history", ".sh_history"): k.append("history")
        if "/cron" in pl or nl in ("crontab", "anacrontab"): k.append("cron")
        if nl in ("wtmp", "btmp", "lastlog", "utmp") or nl.startswith(("wtmp.", "btmp.")): k.append("wtmp")
        if nl in ("passwd", "shadow", "group", "sudoers"): k.append("accounts")
        if nl in ("authorized_keys", "authorized_keys2"): k.append("sshkeys")
        if re.match(r"(access|error)\.log", nl) and any(x in pl for x in ("apache", "nginx", "httpd", "www", "web")): k.append("weblogs")
        if re.search(r"(^|[_\-.])(ps|pslist|lsof|netstat|ss|ifconfig)([_\-.]|$)", nl): k.append("snapshots")
    else:
        if ext == ".logarchive" or ext == ".tracev3" or "logarchive" in pl: k.append("unified")
        if nl in ("system.log", "install.log", "secure.log", "wifi.log") or nl.startswith(("system.log.", "install.log.")): k.append("syslog")
        if ext == ".plist" and ("launchagents" in pl or "launchdaemons" in pl): k.append("launchd")
        if "quarantineevents" in nl: k.append("quarantine")
        if nl == "tcc.db": k.append("tcc")
        if nl in (".zsh_history", ".bash_history", "zsh_history", "bash_history"): k.append("history")
        if "fseventsd" in pl: k.append("fsevents")
        if "/cron" in pl or nl == "crontab": k.append("cron")
    return k


def uni_fix_command(path):
    import getpass
    u = getpass.getuser()
    if os.name == "nt": return f'icacls "{path}" /grant "{u}:(OI)(CI)F" /T /C   (run in an Administrator prompt)'
    return f'sudo chown -R {u}:{u} "{path}" && sudo chmod -R u+rwX "{path}"'


def uni_fix_permissions(path):
    """Make an evidence folder readable by the user running this tool. Needs root (or passwordless sudo) on Linux/macOS."""
    import getpass
    path = str(path); user = getpass.getuser()
    try:
        if os.name == "nt":
            r = subprocess.run(f'icacls "{path}" /grant "{user}:(OI)(CI)F" /T /C /Q', shell=True, capture_output=True, text=True, timeout=300)
            return r.returncode == 0, (r.stderr or r.stdout).strip()[:200]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            uid = os.environ.get("SUDO_UID"); gid = os.environ.get("SUDO_GID")
            if not uid:
                st = Path(path).parent.stat(); uid, gid = st.st_uid, st.st_gid
            for p_ in [Path(path)] + list(Path(path).rglob("*")):
                try:
                    os.chown(p_, int(uid), int(gid or uid), follow_symlinks=False)
                    if not p_.is_symlink(): os.chmod(p_, p_.stat().st_mode | 0o640 | (0o110 if p_.is_dir() else 0))
                except Exception: pass
            return True, f"ownership set to uid {uid}"
        r1 = subprocess.run(["sudo", "-n", "chown", "-R", f"{user}:{user}", path], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        if r1.returncode != 0: return False, "sudo needs a password - run the command shown in a terminal"
        subprocess.run(["sudo", "-n", "chmod", "-R", "u+rwX", path], capture_output=True, timeout=300, stdin=subprocess.DEVNULL)
        return True, "ownership changed with sudo"
    except Exception as e:
        return False, str(e)[:200]


def uni_unreadable(path, limit=60000):
    """Evidence files / folders this process cannot open (permission denied). Returns (count, examples)."""
    bad = []
    try:
        pth = Path(path)
        if pth.is_file():
            try: open(pth, "rb").close()
            except PermissionError: bad.append(str(pth))
            return len(bad), bad[:5]
        def _err(e):
            if isinstance(e, PermissionError): bad.append(str(getattr(e, "filename", "") or pth))
        seen = 0
        for root, dirs, files in os.walk(pth, onerror=_err):
            for fn in files:
                seen += 1
                if seen > limit: return len(bad), bad[:5]
                fp = os.path.join(root, fn)
                try: open(fp, "rb").close()
                except PermissionError: bad.append(fp)
                except Exception: pass
    except Exception: pass
    return len(bad), bad[:5]


def uni_scope(os_type, base, vol_dir, cor, out):
    """Collect host identity, evidence inventory, missing artifacts and log coverage."""
    prof = cor_profile(os_type); o = prof["os"]
    found = defaultdict(list)
    total_files = total_bytes = 0
    if base and Path(base).exists():
        n = 0
        for p in Path(base).rglob("*"):
            n += 1
            if n > 80000: break
            try:
                if not p.is_file(): continue
                st = p.stat()
            except Exception: continue
            total_files += 1; total_bytes += st.st_size
            for key in uni__classify(os_type, p, p.name.lower(), str(p).lower().replace("\\", "/")):
                found[key].append((p, st.st_size, st.st_mtime))
    # memory dumps the web memory-only flow analysed (base may be a single file)
    if base and Path(base).is_file() and Path(base).suffix.lower() in _SC_MEM_EXT:
        st = Path(base).stat(); found["memory"].append((Path(base), st.st_size, st.st_mtime))
    # ---- host identity
    meta = (cor or {}).get("meta") or {}
    hosts = [h for h, _ in Counter(meta.get("hosts", {})).most_common(5) if h]
    mem_info = {}
    vd = Path(vol_dir) if vol_dir else None
    if vd and vd.exists():
        for f in sorted(vd.glob("*info*.txt")):
            h, rows = cor__table(f)
            for r in rows:
                if len(r) >= 2: mem_info[r[0]] = r[1]
            if mem_info: break
    osname = ""
    if mem_info:
        lab = mem_info.get("NTBuildLab", "")
        mb = re.match(r"(\d+)", lab)
        build = int(mb.group(1)) if mb else 0
        if o == "windows":
            ver = ("Windows 11" if build >= 22000 else "Windows 10") if mem_info.get("NtMajorVersion") == "10" else f"Windows NT {mem_info.get('NtMajorVersion', '?')}.{mem_info.get('NtMinorVersion', '?')}"
            osname = f"{ver} (build {lab or build})" + (" 64-bit" if str(mem_info.get("Is64Bit", "")).lower() == "true" else "")
        else:
            osname = mem_info.get("Banner") or mem_info.get("Kernel Version") or ""
    accounts = Counter(meta.get("accounts", {}))
    cov = meta.get("coverage", {})
    firsts = [c["first"] for c in cov.values() if c.get("first")]; lasts = [c["last"] for c in cov.values() if c.get("last")]
    def fts(v): return epr_fmt(v) if isinstance(v, datetime) else str(v or "-")
    host_rows = [["Hostname(s)", ", ".join(hosts) or "not found in supplied logs"],
                 ["Operating system", osname or ("see evidence" if total_files else "unknown")],
                 ["Accounts seen", ", ".join(f"{a} ({n})" for a, n in accounts.most_common(8)) or "-"],
                 ["Memory capture time (system clock)", mem_info.get("SystemTime", "-")],
                 ["Log time span", f"{fts(min(firsts))}  ->  {fts(max(lasts))}" if firsts and lasts else "-"],
                 ["Evidence location", str(base) if base else "memory dump only"],
                 ["Evidence size", f"{total_files} file(s), {total_bytes / 1048576:.1f} MB" if total_files else "-"]]
    # ---- inventory + missing
    inv, missing = [], []
    for key, label, impact in sc_EXPECTED.get(o, []):
        fl = found.get(key, [])
        if key == "evtx_any" and any(found.get(k) for k in ("evtx_security", "evtx_system", "evtx_sysmon", "evtx_ps", "evtx_task", "evtx_defender", "evtx_rdp")): continue
        if fl:
            mt = [x[2] for x in fl]
            inv.append([label, f"{len(fl)} file(s)", f"{sum(x[1] for x in fl) / 1048576:.1f} MB",
                        f"{datetime.fromtimestamp(min(mt)):%Y-%m-%d} -> {datetime.fromtimestamp(max(mt)):%Y-%m-%d}",
                        ", ".join(sorted({x[0].name for x in fl}))[:90]])
        else:
            missing.append([label, "MISSING", impact])
    n_bad, ex_bad = uni_unreadable(base) if base else (0, [])
    if n_bad:
        missing.insert(0, ["Unreadable evidence files (permission denied)", f"{n_bad} file(s), e.g. {Path(ex_bad[0]).name}",
                           "Run the tool as Administrator / with sudo, or fix ownership of the evidence folder (e.g. sudo chown -R $USER:$USER <folder>), then re-run the analysis"])
    # hive logs only matter when hives are present
    if not found.get("hive_system") and not found.get("hive_software") and not found.get("hive_ntuser"):
        missing = [m for m in missing if not m[0].startswith("Hive transaction")]
    cov_rows = []
    for fn, c in sorted(cov.items(), key=lambda kv: (kv[1].get("first") is None, kv[1].get("first") or datetime.max)):
        cov_rows.append([fn, str(c.get("records", "")), fts(c.get("first")), fts(c.get("last"))])
    data = {"host_rows": host_rows, "inventory": inv, "missing": missing, "coverage": cov_rows, "hosts": hosts, "os": osname}
    try: Path(out, "scope.json").write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception: pass
    return data


# ═══════════════════════════════════════════════════════════════════════════
# REPORTING DASHBOARD: time-window analysis per completed task (rule-based correlation + optional analyst review)
# ═══════════════════════════════════════════════════════════════════════════
def rw_parse(s):
    if isinstance(s, datetime): return s
    s = (s or "").strip().replace("T", " ")
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try: return datetime.strptime(s[:19] if f.endswith("%S") else s[:16] if f.endswith("%M") else s[:10], f)
        except Exception: pass
    return None


def rw_range(data):
    ts = []
    for sev in ("critical", "high", "medium"):
        for f in data.get(sev, []) or []:
            t = rw_parse(f.get("ts", ""))
            if t: ts.append(t)
    for e in data.get("timeline", []) or []:
        t = rw_parse(e.get("ts", ""))
        if t: ts.append(t)
    return (min(ts), max(ts), len(ts)) if ts else (None, None, 0)


def rw_presets(data):
    """Full range + the strongest attack windows (padded 5 min) for the picker."""
    t0, t1, n = rw_range(data)
    out = []
    if t0:
        out.append({"label": f"Whole evidence ({t0:%Y-%m-%d %H:%M} -> {t1:%Y-%m-%d %H:%M})", "from": t0.strftime("%Y-%m-%dT%H:%M"), "to": (t1 + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M")})
        eps = sorted(rpt_episodes(data), key=lambda e: -e["score"])[:6]
        for i, e in enumerate(sorted(eps, key=lambda e: e["start"])):
            a, b = e["start"] - timedelta(minutes=5), e["end"] + timedelta(minutes=5)
            top = ", ".join(k for k, _ in e["cats"].most_common(2))
            out.append({"label": f"Attack window {i + 1}: {e['start']:%Y-%m-%d %H:%M} ({len(e['ev'])} events) - {top}"[:140], "from": a.strftime("%Y-%m-%dT%H:%M"), "to": b.strftime("%Y-%m-%dT%H:%M")})
    return out


def rw_filter(data, t0, t1):
    def keep(ts):
        t = rw_parse(ts)
        return True if t is None else (t0 <= t <= t1)
    d = {k: v for k, v in data.items()}
    undated = 0
    for sev in ("critical", "high", "medium"):
        lst = []
        for f in data.get(sev, []) or []:
            if not f.get("ts"): undated += 1
            if keep(f.get("ts", "")): lst.append(f)
        d[sev] = lst
    d["timeline"] = [e for e in data.get("timeline", []) or [] if rw_parse(e.get("ts", "")) and t0 <= rw_parse(e["ts"]) <= t1]
    return d, undated


def rw_cor_window(cor, scope, t0, t1):
    """Re-derive the correlation view for a time window from the saved correlation data (no re-scan)."""
    if not cor: return None
    inds = {}
    for k, i in (cor.get("indicators") or {}).items():
        sg = []
        for s in i.get("sightings", []) or []:
            t = rw_parse(s[0]) if s and s[0] and s[0] != "None" else None
            sg.append((t, s[1], s[2]))
        dated = [x for x in sg if x[0]]
        inw = [x for x in sg if x[0] is None or (t0 <= x[0] <= t1)]
        if dated and not any(x[0] and t0 <= x[0] <= t1 for x in sg): continue
        j = dict(i); j["sightings"] = inw
        j["in_memory"] = any(x[1].startswith("Memory") for x in inw) or i.get("in_memory", False)
        j["event_count"] = sum(1 for x in inw if x[1].startswith(("Event log", "System log")))
        j["in_events"] = j["event_count"] > 0
        j["in_hive"] = any(not x[1].startswith(("Memory", "Event log", "System log", "Hive transaction")) for x in inw)
        j["in_hive_log"] = any(x[1].startswith("Hive transaction") for x in inw)
        j["pids"] = i.get("pids", []); j["mem"] = i.get("mem", {}) or {}
        inds[k] = j
    best = None
    for k, ep in (cor.get("entries") or {}).items():
        t = rw_parse(ep.get("time"))
        if t and t0 <= t <= t1 and k in inds:
            sc = inds[k].get("score", 0)
            if best is None or (sc, -t.timestamp()) > (best[0], -best[1].timestamp()): best = (sc, t, ep)
    ce = cor.get("entry") or {}
    if best is None and rw_parse(ce.get("time")) and t0 <= rw_parse(ce["time"]) <= t1: best = (0, rw_parse(ce["time"]), ce)
    if best:
        ep = dict(best[2]); ep["evidence"] = [(rw_parse(e[0]) if e and e[0] and e[0] != "None" else None, e[1], e[2]) for e in ep.get("evidence", [])]
    else:
        ep = {"status": "NOT DETERMINED", "confidence": "n/a", "vector": "", "time": None, "account": "", "source_ip": "", "anchor": "", "chain": [], "evidence": [],
              "reasons": ["No suspicious activity with a determinable start time falls inside the selected window."]}
    gaps = [tuple(g) for g in cor.get("gaps", []) if "starts at" not in g[1]]
    for fn, c in ((scope or {}).get("coverage") and [(r[0], r) for r in scope["coverage"]]) or []:
        f, l = rw_parse(c[2]), rw_parse(c[3])
        if f and f > t0: gaps.append(("Logs", f"{fn} begins at {c[2]}, after the window start ({t0:%Y-%m-%d %H:%M}) - earlier activity in this window is not covered."))
    return {"indicators": inds, "entry": ep, "gaps": gaps, "labels": cor.get("labels") or {"store": "Registry hive", "logs": "Event log", "os": "windows"},
            "cross": [c for c in cor.get("cross", []) if not rw_parse(c.get("mem_lastwrite")) or t0 <= rw_parse(c["mem_lastwrite"]) <= t1]}


def rw_series(data, t0, t1):
    span = max((t1 - t0).total_seconds(), 60)
    step = 300 if span <= 3 * 3600 else 3600 if span <= 3 * 86400 else 86400 if span <= 90 * 86400 else 7 * 86400
    b = {}
    for e in data.get("timeline", []) or []:
        t = rw_parse(e.get("ts", ""))
        if not t or not (t0 <= t <= t1): continue
        sev = str(e.get("sev", "")).upper()
        if sev not in ("CRITICAL", "HIGH"): continue
        if any(rx.search(f"{e.get('src', '')} {e.get('desc', '')}") for _, rx in rpt_NOISE): continue
        k = int((t - t0).total_seconds() // step)
        c = b.setdefault(k, [0, 0]); c[0 if sev == "CRITICAL" else 1] += 1
    return [(t0 + timedelta(seconds=k * step), v[0], v[1]) for k, v in sorted(b.items())], step


def rw_dashboard_html(title, kpis, series, step, blocks, meta):
    from xml.sax.saxutils import escape as E
    sevc = {"CRITICAL": "#f85149", "HIGH": "#f97316", "MEDIUM": "#e3b341", "LOW": "#3fb950"}
    k = "".join(f'<div class="kpi"><div class="kv" style="color:{c}">{E(str(v))}</div><div class="kl">{E(l)}</div></div>' for l, v, c in kpis)
    chart = ""
    if series:
        W, H, pad = 1000, 170, 26
        mx = max(c + h for _, c, h in series) or 1
        bw = max(2, (W - 2 * pad) / max(len(series), 1) - 2)
        bars = []
        for i, (t, c, h) in enumerate(series):
            x = pad + i * ((W - 2 * pad) / max(len(series), 1))
            hc, hh = (H - 2 * pad) * c / mx, (H - 2 * pad) * h / mx
            lab = f"{t:%Y-%m-%d %H:%M}: {c} critical, {h} high"
            bars.append(f'<g><title>{E(lab)}</title><rect x="{x:.1f}" y="{H - pad - hh - hc:.1f}" width="{bw:.1f}" height="{hh:.1f}" fill="#f97316"/><rect x="{x:.1f}" y="{H - pad - hc:.1f}" width="{bw:.1f}" height="{hc:.1f}" fill="#f85149"/></g>')
        ticks = "".join(f'<text x="{pad + i * ((W - 2 * pad) / max(len(series), 1)):.0f}" y="{H - 8}" fill="#8b949e" font-size="10">{series[i][0]:%m-%d %H:%M}</text>' for i in range(0, len(series), max(1, len(series) // 8)))
        unit = "5-min" if step == 300 else "hourly" if step == 3600 else "daily" if step == 86400 else "weekly"
        chart = f'<div class="card"><h3>Activity over time ({unit} buckets: <span style="color:#f85149">critical</span> / <span style="color:#f97316">high</span>)</h3><svg viewBox="0 0 {W} {H}" width="100%" style="max-height:200px">{"".join(bars)}{ticks}</svg></div>'
    body = []
    for b in blocks:
        t = b[0]
        if t == "title" or t == "risk": continue
        if t == "h1": body.append(f"<h2>{E(b[1])}</h2>")
        elif t == "h2": body.append(f"<h3>{E(b[1])}</h3>")
        elif t == "p": body.append(f"<p>{E(b[1])}</p>")
        elif t == "b": body.append("<ul>" + "".join(f"<li>{E(str(x))}</li>" for x in b[1]) + "</ul>")
        elif t == "t":
            hd, rows = b[1], b[2]
            tr = "".join("<tr>" + "".join(
                (f'<td style="color:{sevc[str(c)]};font-weight:700">{E(str(c))}</td>' if i == 0 and str(c) in sevc else f"<td>{E(str(c)[:400])}</td>") for i, c in enumerate(list(r)[:len(hd)])) + "</tr>" for r in rows[:400])
            body.append('<div class="tw"><table><tr>' + "".join(f"<th>{E(str(h))}</th>" for h in hd) + f"</tr>{tr}</table></div>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{E(title)}</title><style>
:root{{--bg:#0d1117;--bg2:#161b22;--b:#30363d;--t:#e6edf3;--d:#8b949e}}*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--t);font:13.5px/1.55 'Segoe UI',system-ui,sans-serif;padding:22px 28px}}
h1{{font-size:21px;margin:0 0 4px}}h2{{font-size:16px;margin:26px 0 8px;color:#79c0ff;border-bottom:1px solid var(--b);padding-bottom:5px}}h3{{font-size:13.5px;margin:14px 0 6px;color:#a5d6ff}}
.sub{{color:var(--d);margin-bottom:14px}}.kpis{{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}}
.kpi{{flex:1 1 150px;min-width:140px;background:var(--bg2);border:1px solid var(--b);border-radius:9px;padding:12px 14px}}.kv{{font-size:20px;font-weight:700;word-break:break-word}}.kl{{font-size:11px;color:var(--d);text-transform:uppercase;letter-spacing:.4px}}
.card{{background:var(--bg2);border:1px solid var(--b);border-radius:9px;padding:10px 14px;margin:12px 0}}.card h3{{margin:0 0 6px}}
.tw{{overflow-x:auto;margin:6px 0 10px}}table{{border-collapse:collapse;width:100%;font-size:12px}}th{{text-align:left;background:#1c2128;border:1px solid var(--b);padding:6px 8px;position:sticky;top:0}}
td{{border:1px solid var(--b);padding:5px 8px;vertical-align:top;word-break:break-word}}tr:nth-child(even) td{{background:#12171e}}ul{{margin:6px 0 10px 20px}}li{{margin:3px 0}}p{{margin:6px 0}}
#q{{width:100%;max-width:420px;padding:7px 10px;background:#1c2128;border:1px solid var(--b);border-radius:6px;color:var(--t);margin:6px 0 4px}}
</style></head><body><h1>{E(title)}</h1><div class="sub">{E(meta)}</div><div class="kpis">{k}</div>{chart}
<input id="q" placeholder="Filter all tables..." oninput="var v=this.value.toLowerCase();document.querySelectorAll('tr').forEach(function(r,i){{if(r.querySelector('th'))return;r.style.display=r.textContent.toLowerCase().indexOf(v)<0?'none':'';}})">
{"".join(body)}</body></html>"""


def rw_load(job):
    """Collect everything needed to build a report for this job (any OS)."""
    out = job["output_dir"]
    def load(name):
        for base_ in (Path(out) / "supporting_data", Path(out)):
            try: return json.loads((base_ / name).read_text(encoding="utf-8"))
            except Exception: continue
        return None
    data = load("report_data.json")
    mem_secs = None
    if job.get("os_type") == "memory":
        md = _mem_report_data(job); mem_secs = [x for x in md["sections"] if x[0] != "Suspicious Findings"]
        fm = job.get("mem", {}).get("findings", [])
        data = {"critical": [{"severity": "CRITICAL", "source": f["plugin"], "desc": f["line"][:160], "ts": "", "data": ""} for f in fm if f["severity"] == "CRITICAL"],
                "high": [{"severity": "HIGH", "source": f["plugin"], "desc": f["line"][:160], "ts": "", "data": ""} for f in fm if f["severity"] == "HIGH"],
                "medium": [], "timeline": [], "external_ips": [], "registry_hits": [], "c2_indicators": []}
    if not data:
        r = job.get("results") or {}
        data = {"critical": [{"severity": "CRITICAL", "source": f.get("source", ""), "desc": f.get("desc", ""), "ts": f.get("ts", ""), "data": f.get("detail", "")} for f in r.get("critical", [])],
                "high": [{"severity": "HIGH", "source": f.get("source", ""), "desc": f.get("desc", ""), "ts": f.get("ts", ""), "data": f.get("detail", "")} for f in r.get("high", [])],
                "medium": [], "timeline": r.get("timeline", []), "external_ips": r.get("external_ips", []), "registry_hits": r.get("registry_hits", []), "c2_indicators": r.get("c2_indicators", [])}
    review = job.get("review_text")
    if not review:
        for base_ in (Path(out) / "supporting_data", Path(out)):
            try: review = (base_ / "analyst_review.txt").read_text(encoding="utf-8"); break
            except Exception: review = None
    if review and not uni_review_ok(review): review = None
    return data, mem_secs, load("correlation.json"), load("scope.json"), review


def rw_run(job, aid, t_from, t_to, use_ai):
    """Build one analysis (window or whole evidence): dashboard HTML + DOCX + PDF."""
    A = job.setdefault("analyses", {})
    a = A.setdefault(aid, {"id": aid, "state": "running", "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    a.update({"state": "running", "error": "", "ai": False})
    try:
        data, mem_secs, cor, scope, review = rw_load(job)
        r0, r1, _n = rw_range(data)
        win = bool(t_from and t_to and r0)
        t0 = rw_parse(t_from) if win else r0
        t1 = rw_parse(t_to) if win else (r1 + timedelta(minutes=1) if r1 else None)
        label = f"{t0:%Y-%m-%d %H:%M} -> {t1:%Y-%m-%d %H:%M}" if t0 else "whole evidence (no timestamps)"
        if win and (not t0 or not t1 or t1 <= t0): raise ValueError("Invalid time window (To must be after From)")
        a.update({"from": t0.strftime("%Y-%m-%dT%H:%M") if t0 else "", "to": t1.strftime("%Y-%m-%dT%H:%M") if t1 else "", "label": label if win else "Whole evidence"})
        dw, undated = (rw_filter(data, t0, t1) if t0 else (data, 0))
        cw = rw_cor_window(cor, scope, t0, t1) if (win and cor) else cor
        csecs = [[t, h, [[str(c) for c in r] for r in rows]] for t, h, rows in cor_sections(cw)] if cw else []
        # IOC reputation (VirusTotal / AbuseIPDB), cached on disk
        lg0 = lambda m: job["log"].append(f"[ioc] {m}")
        ioc_rows = []
        try:
            _bulk = None
            for _b in (Path(job["output_dir"]) / "supporting_data" / "bulk_iocs.json", Path(job["output_dir"]) / "bulk_iocs.json"):
                try: _bulk = json.loads(_b.read_text(encoding="utf-8")); break
                except Exception: pass
            ioc_rows = ioc_enrich(job["output_dir"], ioc_candidates(dw, cw, extra=_bulk), job.get("vt_key") or UNI_CTX.get("vt_key"), job.get("abuse_key") or UNI_CTX.get("abuse_key"), lg0)
        except Exception as ex:
            job["log"].append(f"[ioc] reputation step failed: {ex}")
        groups0, _nz = rpt_group(dw)
        narr = rpt_narrative(job.get("os_type", ""), dw, groups0, rpt_episodes(dw), cw, scope, ioc_rows)
        rv = review if not win else None
        if use_ai and job.get("ai") and job["ai"].get("ai_provider") not in (None, "", "none"):
            lg = lambda lvl, msg: job["log"].append(f"[analyst] {msg}")
            cfg = _ai_cfg_for(job["ai"], lg)
            if cfg:
                brief = ((f"TIME WINDOW UNDER REVIEW: {label}. Only activity inside this window is in scope; evidence outside it was excluded.\n" if win else "")
                         + uni_briefing(dw, cw, ioc_rows, narr))
                txt = epr_ai_call(cfg, cor_REVIEW_SYSTEM, brief, lg, max_tokens=3500)
                if txt and uni_review_ok(txt): rv = txt; a["ai"] = True
        if not win and rv and not a["ai"]: a["ai"] = True
        case = job.get("case") or ""
        blocks = rpt_blocks(job.get("os_type", ""), job.get("evidence", ""), dw, job.get("summary") or {}, csecs, rv, cw, mem_secs, case=case or None, scope=scope, ioc_rows=ioc_rows)
        if win:
            blocks.insert(2, ("p", f"Analysis window: {label}. Findings outside this window are excluded; {undated} undated finding(s) (memory state) are kept."))
        groups, noise = rpt_group(dw)
        eps = rpt_episodes(dw)
        crit_u = sum(1 for g in groups if g["sev"] == "CRITICAL"); high_u = sum(1 for g in groups if g["sev"] == "HIGH")
        lvl = "CRITICAL" if crit_u else "HIGH" if high_u else "MEDIUM" if groups else "LOW"
        ce = (cw or {}).get("entry") or {}
        kpis = [("Overall risk", lvl, {"CRITICAL": "#f85149", "HIGH": "#f97316", "MEDIUM": "#e3b341", "LOW": "#3fb950"}[lvl]), ("Critical (unique)", crit_u, "#f85149"),
                ("High (unique)", high_u, "#f97316"), ("Attack windows", len(eps), "#79c0ff"), ("Indicators", len((cw or {}).get("indicators", {})), "#a5d6ff"),
                ("Entry point", ce.get("status", "n/a"), "#e6edf3"), ("Malicious IOCs", sum(1 for r in ioc_rows if r["verdict"] == "MALICIOUS"), "#f85149"),
                ("Narrative", "analyst-written" if a["ai"] else "rule-based", "#8b949e")]
        series, step = rw_series(dw, t0, t1) if t0 else ([], 3600)
        host = ", ".join((scope or {}).get("hosts", [])[:2]) or "host n/a"
        title = f"Forensic Report{' - ' + case if case else ''}"
        meta = f"{host} | {job.get('os_type', '').upper()} | {label}"
        adir = Path(job["output_dir"]) if not win else Path(job["output_dir"]) / f"analysis_{t0:%Y%m%d_%H%M}_{t1:%Y%m%d_%H%M}"
        adir.mkdir(parents=True, exist_ok=True)
        stem = f"{case or 'forensics'}_report" + ("" if not win else f"_{t0:%Y%m%d_%H%M}-{t1:%Y%m%d_%H%M}")
        (adir / f"{stem}.html").write_text(rw_dashboard_html(title, kpis, series, step, blocks, meta), encoding="utf-8")
        a["docx"] = rpt_docx(blocks, adir, stem); a["pdf"] = rpt_pdf(blocks, adir, stem)
        a["html"] = str(adir / f"{stem}.html"); a["dir"] = str(adir)
        a["kpis"] = {"risk": lvl, "critical": crit_u, "high": high_u, "windows": len(eps)}
        a["state"] = "done"
    except Exception as e:
        import traceback
        a["state"] = "error"; a["error"] = str(e)[:200]
        job["log"].append(f"[x] Analysis failed: {e}"); job["log"].append(traceback.format_exc()[-400:])


# ═══════════════════════════════════════════════════════════════════════════
# IOC REPUTATION (VirusTotal / AbuseIPDB), INCIDENT NARRATIVE, TIMELINE MAPPING
# ═══════════════════════════════════════════════════════════════════════════
import urllib.request as _ur, urllib.error as _ue
_IOC_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")


def ioc_candidates(data, cor, limit=25, extra=None):
    """Collect network IOCs / hashes worth a reputation check, ranked by how suspicious their context is."""
    cand = {}
    def add(val, kind, ctx, w):
        val = str(val).strip()
        if not val: return
        if kind == "ip" and (epr_is_private_ip(val) or val.startswith(("127.", "::1", "fe80", "0.0.0.0")) or ":" in val and val.startswith("64:ff9b")): return
        c = cand.setdefault(val, {"value": val, "kind": kind, "ctx": [], "w": 0})
        if ctx and ctx not in c["ctx"] and len(c["ctx"]) < 3: c["ctx"].append(ctx)
        c["w"] += w
    for c in data.get("c2_indicators", []) or []:
        for k in ("ip", "domain", "remote", "host"):
            if c.get(k): add(c[k], "domain" if k == "domain" else "ip", "flagged C2 indicator" + (f" ({c.get('type')})" if c.get("type") else ""), 6)
    for t in data.get("threat_intel", []) or []:
        if t.get("ip"): add(t["ip"], "ip", "threat-intel match", 6)
        if t.get("hash"): add(t["hash"], "hash", f"file hash ({t.get('name', '')})", 6)
    for i in ((cor or {}).get("indicators") or {}).values():
        for cn in (i.get("mem") or {}).get("conns", []) or []:
            ip = str(cn).split(":")[0]
            if cor_IP_RX.fullmatch(ip): add(ip, "ip", f"connection made by suspicious process {i.get('name')}", 5)
        for tk in i.get("tokens", []) or []:
            if cor_IP_RX.fullmatch(str(tk)): add(tk, "ip", f"referenced by indicator {i.get('name')}", 4)
    for sev in ("critical", "high"):
        for f in (data.get(sev) or [])[:4000]:
            txt = f"{f.get('desc', '')} {f.get('data', '')}"
            if rpt_NOISE and any(rx.search(txt) for _, rx in rpt_NOISE): continue
            for ip in cor_IP_RX.findall(txt): add(ip, "ip", str(f.get("desc", ""))[:70], 3)
            for h in _IOC_HASH.findall(txt): add(h.lower(), "hash", str(f.get("desc", ""))[:70], 3)
    benign_dom = re.compile(r"(microsoft|windows|windowsupdate|msftconnecttest|office|live|bing|google|gstatic|apple|icloud|mozilla|ubuntu|debian|kali|github|digicert|verisign|akamai|cloudflare)\.", re.I)
    for x in sorted(extra or [], key=lambda e: -e.get("count", 0))[:40]:
        if x["kind"] == "ip" and x.get("count", 0) >= 2: add(x["value"], "ip", f"seen {x['count']}x in memory (bulk_extractor)", 2)
        elif x["kind"] == "domain" and x.get("count", 0) >= 2 and not benign_dom.search(x["value"] + "."): add(x["value"], "domain", f"seen {x['count']}x in memory (bulk_extractor)", 2)
    ranked = sorted(cand.values(), key=lambda c: -c["w"])
    for ip in sorted(data.get("external_ips", []) or []):                 # context only (usually cloud / CDN)
        if len(ranked) >= limit: break
        if ip not in cand and not epr_is_private_ip(ip) and ":" not in ip: ranked.append({"value": ip, "kind": "ip", "ctx": ["external connection observed"], "w": 0})
    return ranked[:limit]


def ioc_vt(kind, val, key):
    seg = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
    req = _ur.Request(f"https://www.virustotal.com/api/v3/{seg}/{val}", headers={"x-apikey": key})
    try:
        j = json.load(_ur.urlopen(req, timeout=20))
    except _ue.HTTPError as e:
        return {"error": e.code}
    except Exception as e:
        return {"error": str(e)[:60]}
    a = j.get("data", {}).get("attributes", {}) or {}
    st = a.get("last_analysis_stats", {}) or {}
    return {"mal": st.get("malicious", 0), "sus": st.get("suspicious", 0), "total": sum(st.values()), "asn": a.get("asn"), "owner": a.get("as_owner"),
            "country": a.get("country"), "name": a.get("meaningful_name")}


def ioc_abuse(ip, key):
    req = _ur.Request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers={"Key": key, "Accept": "application/json"})
    try: d = json.load(_ur.urlopen(req, timeout=20)).get("data", {})
    except Exception as e: return {"error": str(e)[:60]}
    return {"score": d.get("abuseConfidenceScore"), "country": d.get("countryCode"), "isp": d.get("isp"), "reports": d.get("totalReports")}


def ioc_enrich(out_dir, cands, vt_key, abuse_key, log=None):
    """Reputation lookups with an on-disk cache; respects the free VT quota (4/min) and a call/time budget."""
    log = log or (lambda m: None)
    cache_file = Path(out_dir) / "supporting_data" / "ioc_enrichment.json"
    legacy = Path(out_dir) / "ioc_enrichment.json"
    cache = {}
    for pth in (cache_file, legacy):
        try: cache = json.loads(pth.read_text(encoding="utf-8")); break
        except Exception: pass
    max_calls = int(os.environ.get("VT_MAX", 12)); delay = float(os.environ.get("VT_DELAY", 15.5)); max_sec = int(os.environ.get("VT_MAX_SEC", 480))
    t0 = time.time(); calls = 0; dead = False
    for c in cands:
        v = c["value"]
        e = cache.get(v, {})
        if vt_key and not dead and "vt" not in e and calls < max_calls and time.time() - t0 < max_sec:
            if calls: time.sleep(delay)
            r = ioc_vt(c["kind"], v, vt_key); calls += 1
            if r.get("error") == 429:
                time.sleep(65); r = ioc_vt(c["kind"], v, vt_key)
            if r.get("error") in (401, 403): dead = True; log("VirusTotal key rejected - skipping reputation checks")
            elif "error" not in r: e["vt"] = r
        if abuse_key and c["kind"] == "ip" and "abuse" not in e and calls < max_calls + 20:
            r = ioc_abuse(v, abuse_key)
            if "error" not in r: e["abuse"] = r
        if e: cache[v] = e
    try:
        cache_file.parent.mkdir(exist_ok=True); cache_file.write_text(json.dumps(cache), encoding="utf-8")
    except Exception: pass
    rows = []
    for c in cands:
        e = cache.get(c["value"], {}); vt = e.get("vt"); ab = e.get("abuse")
        mal, tot = (vt["mal"], vt["total"]) if vt else (None, None)
        score = (ab or {}).get("score")
        if vt and (mal >= 3 or (score or 0) >= 75): verdict = "MALICIOUS"
        elif vt and (mal >= 1 or vt.get("sus", 0) >= 1 or (score or 0) >= 25): verdict = "SUSPICIOUS"
        elif vt or ab: verdict = "No detections"
        else: verdict = "not checked" + ("" if (vt_key or abuse_key) else " (no API key)")
        country = (vt or {}).get("country") or (ab or {}).get("country") or "-"
        asn = f"AS{vt['asn']} {vt.get('owner') or ''}".strip() if vt and vt.get("asn") else ((ab or {}).get("isp") or "-")
        rows.append({"value": c["value"], "kind": c["kind"], "ctx": "; ".join(c["ctx"]), "mal": mal, "total": tot, "asn": asn, "country": country,
                     "abuse": score, "verdict": verdict, "name": (vt or {}).get("name") or ""})
    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "No detections": 2}
    rows.sort(key=lambda r: order.get(r["verdict"], 3))
    return rows


def ioc_table(rows):
    hd = ["IOC", "Type", "Why it is listed", "VirusTotal (malicious / engines)", "ASN / Owner", "Country", "Verdict"]
    out = []
    for r in rows:
        vt = f"{r['mal']} / {r['total']}" if r["mal"] is not None else "-"
        if r.get("abuse") is not None: vt += f"  (AbuseIPDB {r['abuse']}%)"
        out.append([r["value"] + (f" ({r['name']})" if r.get("name") else ""), r["kind"], r["ctx"][:110], vt, r["asn"][:50], r["country"], r["verdict"]])
    return hd, out


def rpt_interpret(cats):
    c = " ".join(cats).lower()
    t = []
    if "ransom" in c: t.append("ransomware-style behaviour")
    if "log cleared" in c or "cleared" in c: t.append("log clearing (anti-forensics)")
    if "quarantin" in c: t.append("malware being caught and quarantined")
    if "powershell" in c and ("service" in c or "scheduled" in c): t.append("scripted payload execution with persistence")
    elif "powershell" in c: t.append("script-based execution")
    if "tamper" in c or "evasion" in c: t.append("defence evasion")
    if "credential" in c: t.append("credential access / discovery")
    return ", ".join(t[:3])


def rpt_narrative(os_type, data, groups, eps, cor, scope, ioc_rows):
    """Rule-based incident narrative (facts only): overview, sequence of events, persistence, entry point, impact."""
    N = []
    host = ", ".join((scope or {}).get("hosts", [])[:2]) or "the analysed host"
    osn = (scope or {}).get("os") or os_type.upper()
    t0, t1, n = rw_range(data)
    crit_u = sum(1 for g in groups if g["sev"] == "CRITICAL"); high_u = sum(1 for g in groups if g["sev"] == "HIGH")
    span = f"between {t0:%Y-%m-%d %H:%M} and {t1:%Y-%m-%d %H:%M}" if t0 else "at the time of capture"
    N.append(("Overview", f"{host} ({osn}) was examined using the supplied evidence. The data covers activity {span}. After removing duplicates and benign noise the analysis "
                          f"left {crit_u} critical and {high_u} high-severity finding groups across {len(eps)} distinct attack window(s)."))
    seq = []
    for e in sorted(sorted(eps, key=lambda x: -x["score"])[:8], key=lambda x: x["start"]):
        top = e["cats"].most_common(4)
        what = "; ".join(f"{k} ({v}x)" for k, v in top)
        meaning = rpt_interpret([k for k, _ in top])
        when = (f"{e['start']:%Y-%m-%d %H:%M} to {e['end']:%H:%M}" if e["start"].date() == e["end"].date() else f"{e['start']:%Y-%m-%d %H:%M} to {e['end']:%Y-%m-%d %H:%M}")
        seq.append(f"From {when} the host recorded {what}" + (f". Together this indicates {meaning}." if meaning else "."))
    if seq: N.append(("Sequence of events (chronological)", "  ".join(seq)))
    inds = [i for i in ((cor or {}).get("indicators") or {}).values() if i.get("score", 0) >= 3]
    pers = [i for i in inds if i.get("kind") in ("registry", "persistence", "service")]
    procs = [i for i in inds if i.get("kind") == "process"]
    parts = []
    if pers: parts.append("Persistence: " + "; ".join(f"{i['name']} ({'; '.join(i.get('reasons', [])[:1])})" for i in pers[:5]) + ".")
    if procs: parts.append("Suspicious processes: " + "; ".join(f"{i['name']} ({'; '.join(i.get('reasons', [])[:2])})" for i in procs[:5]) + ".")
    if parts: N.append(("How it persisted and executed", " ".join(parts)))
    ce = (cor or {}).get("entry") or {}
    if ce.get("status") in ("DETERMINED", "PROBABLE"):
        tt = ce.get("time"); tt = f"{tt:%Y-%m-%d %H:%M:%S}" if isinstance(tt, datetime) else str(tt)
        txt = (f"The intrusion is assessed as {ce['status'].lower()} (confidence {ce.get('confidence')}). It began at {tt} via: {ce.get('vector')}."
               + (f" The session belonged to {ce['account']}" + (f" from {ce['source_ip']}" if ce.get('source_ip') else "") + "." if ce.get("account") else "")
               + (f" Process chain: {' -> '.join(ce['chain'])}." if ce.get("chain") else ""))
    else:
        gaps = "; ".join(g[1] for g in ((cor or {}).get("gaps") or [])[:3]) or "the supplied logs do not contain a proven logon or parent-process link"
        txt = ("The entry point could NOT be proven from the supplied evidence. " + gaps + ". The closest correlated log evidence (remote logons before the first attack window, first activity in the strongest window and evidence gaps) is listed below so the investigation can continue manually.")
    N.append(("Entry point", txt))
    imp = []
    for rx, msg in ((r"Ransomware Activity", "ransomware alerts were raised by the EDR"), (r"EID\s*(104|1102)|log cleared", "event logs were cleared"),
                    (r"File Quarantined|EID\s*5007", "antivirus quarantined files"), (r"Real-time Protection Disabled|Disable Windows Defender", "protection was disabled"),
                    (r"Whoami|Dumping of Sensitive Hives|Credential", "credential-access / discovery commands ran")):
        c = sum(g["count"] for g in groups if re.search(rx, f"{g['source']} {g['desc']}", re.I))
        if c: imp.append(f"{msg} ({c} event(s))")
    bad = [r for r in (ioc_rows or []) if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    if bad: imp.append("reputation checks flagged " + ", ".join(f"{r['value']} ({r['verdict'].lower()}, {r['country']})" for r in bad[:4]))
    if imp: N.append(("Impact and current state", "Observed effects: " + "; ".join(imp) + "."))
    return N


def rpt_timeline_rows(eps, limit=45):
    rows = []
    for e in sorted(sorted(eps, key=lambda x: -x["score"])[:10], key=lambda x: x["start"]):
        first = {}
        cnt = Counter(); order = []
        for t, sev, blob in e.get("evt", []):
            x = rpt_explain(blob); k = x[0] if x else rpt_norm(blob)[:60]
            if k not in first: first[k] = (t, blob, sev); order.append(k)
            cnt[k] += 1
        for k in order:
            t, blob, sev = first[k]
            rows.append([sev, f"{t:%Y-%m-%d %H:%M:%S}", k, str(cnt[k]), rpt_norm(blob)[:120]])
    return rows[:limit]


def rpt_entry_logs(cor, eps, scope):
    rows, notes = [], []
    meta = (cor or {}).get("meta") or {}
    ce = (cor or {}).get("entry") or {}
    top = sorted(eps, key=lambda e: -e["score"])[:1]
    ref = top[0]["start"] if top else None
    for l in meta.get("remote_logons", []) or []:
        t = rw_parse(l[0])
        if ref and t and ref - timedelta(hours=24) <= t <= ref + timedelta(minutes=5):
            rows.append([str(l[0])[:19], "Remote logon", f"{l[1]} from {l[2]} (type {l[3]})", str(l[4])])
    for ev in (ce.get("evidence") or [])[:8]:
        rows.append([str(ev[0])[:19] if ev[0] else "-", str(ev[1])[:40], str(ev[2])[:150], ""])
    if top:
        for t, sev, blob in top[0].get("evt", [])[:4]:
            rows.append([f"{t:%Y-%m-%d %H:%M:%S}", "First activity in strongest window", rpt_norm(blob)[:150], ""])
    for r in (scope or {}).get("coverage", []) or []:
        f = rw_parse(r[2])
        if ref and f and f > ref: notes.append(f"{r[0]} only begins at {r[2]}, after the strongest attack window ({ref:%Y-%m-%d %H:%M}) - the entry event is not covered by this log.")
    rows.sort(key=lambda r: r[0])
    return rows, notes


# ═══════════════════════════════════════════════════════════════════════════
# EXTERNAL TOOL LAYER for Linux / Kali / macOS (like Hayabusa/Chainsaw on Windows):
# YARA (+signature-base rules), ClamAV, auditd (aureport/ausearch), last/lastb, journalctl, bulk_extractor
# ═══════════════════════════════════════════════════════════════════════════
xt_PKG = {
    "linux": {"yara": "yara", "clamscan": "clamav", "aureport": "auditd", "bulk_extractor": "bulk-extractor"},
    "macos": {"yara": "yara", "clamscan": "clamav", "bulk_extractor": "bulk_extractor"},
}
xt_YARA_ZIP = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
xt_CRIT_RULE = re.compile(r"webshell|ransom|backdoor|rootkit|miner|xmrig|cobalt|beacon|mimikatz|meterpreter|apt_|trojan|rat_|implant|stealer", re.I)
_XT_MON = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def xt_os(os_type):
    return "macos" if (os_type or "").lower() in ("macos", "mac", "darwin") else "linux"


def xt_sh(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except Exception as e:
        return "", str(e), 1


def xt_install(os_type, cmd, log):
    o = xt_os(os_type); pkg = xt_PKG[o].get(cmd)
    if not pkg: return None
    if o == "macos":
        if not shutil.which("brew"): return None
        xt_sh(f"brew install {pkg}", 1200)
    else:
        pre = "" if (hasattr(os, "geteuid") and os.geteuid() == 0) else "sudo -n "
        mgr = next((m for m in ("apt-get", "dnf", "yum", "pacman") if shutil.which(m)), None)
        if not mgr: return None
        line = {"apt-get": f"{pre}apt-get install -y {pkg}", "dnf": f"{pre}dnf install -y {pkg}", "yum": f"{pre}yum install -y {pkg}",
                "pacman": f"{pre}pacman -S --noconfirm {pkg}"}[mgr]
        xt_sh(line, 1200)
    return shutil.which(cmd)


def xt_setup(os_type, tools_dir, log, install=True):
    """Check each external tool, try a non-interactive install, fetch YARA rules. Never blocks on a password prompt."""
    o = xt_os(os_type); have = {}
    log("HEAD", f"External tools ({o}): checking / installing")
    for cmd in xt_PKG[o]:
        p = shutil.which(cmd)
        if not p and install:
            p = xt_install(os_type, cmd, log)
        have[cmd] = p
        if p: log("OK", f"  {cmd}: {p}")
        else: log("WARN", f"  {cmd}: not available - install manually ({'brew install' if o == 'macos' else 'sudo apt install'} {xt_PKG[o][cmd]}) to enable it")
    for cmd in ("last", "lastb", "journalctl", "ausearch"):
        if shutil.which(cmd): have[cmd] = shutil.which(cmd)
    if have.get("yara") and install:
        rd = Path(tools_dir) / "yara_rules"
        if not (rd.exists() and list(rd.glob("*.yar"))):
            try:
                import zipfile, io
                log("INFO", "  downloading YARA rules (Neo23x0/signature-base)...")
                data = _ur.urlopen(xt_YARA_ZIP, timeout=120).read()
                rd.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for nm in z.namelist():
                        if "/yara/" in nm and nm.lower().endswith(".yar"):
                            (rd / Path(nm).name).write_bytes(z.read(nm))
                log("OK", f"  YARA rules: {len(list(rd.glob('*.yar')))} file(s)")
            except Exception as e:
                log("WARN", f"  YARA rules download failed ({str(e)[:80]}) - put .yar files in {rd}")
    return have


def xt_files(base, names_rx, limit=300):
    out = []
    if not base or not Path(base).exists(): return out
    for p in Path(base).rglob("*"):
        try:
            if p.is_file() and names_rx.search(p.name): out.append(p)
        except Exception: pass
        if len(out) >= limit: break
    return out


def xt_run_yara(base, tools_dir, results, log, targets=None):
    yara = shutil.which("yara")
    rd = Path(tools_dir) / "yara_rules"
    if not yara or not rd.exists() or not list(rd.glob("*.yar")):
        log("INFO", "  YARA skipped (binary or rules missing)"); return 0
    good = []
    for r in sorted(rd.glob("*.yar")):
        if ".good" in r.name: continue
        _o, e, rc = xt_sh(f'"{yara}" -w "{r}" /dev/null', 60)
        if rc == 0: good.append(r)
    if not good: log("WARN", "  YARA: no rule file compiled cleanly"); return 0
    idx = rd / "_index.good"
    idx.write_text("".join(f'include "{r}"\n' for r in good), encoding="utf-8")
    idx_y = rd / "_index.yar"; idx_y.write_text(idx.read_text(), encoding="utf-8")
    log("INFO", f"  YARA: scanning with {len(good)} rule file(s)...")
    hits = defaultdict(list)
    for tgt in (targets or [base]):
        o, e, rc = xt_sh(f'"{yara}" -r -w "{idx_y}" "{tgt}"', 3600)
        for ln in o.splitlines():
            m = re.match(r"^(\S+)\s+(.+)$", ln.strip())
            if m: hits[m.group(1)].append(m.group(2))
    for rule, files in hits.items():
        lin_add(results, "CRITICAL" if xt_CRIT_RULE.search(rule) else "HIGH", "YARA", f"YARA match: {rule} ({len(files)} file(s))",
             {"rule": rule, "files": " | ".join(files[:4])[:300]}, files[0])
    log("OK" if hits else "INFO", f"  YARA: {len(hits)} rule(s) matched")
    return len(hits)


def xt_run_clam(base, tools_dir, results, log, install=True):
    cs = shutil.which("clamscan")
    if not cs: log("INFO", "  ClamAV skipped (clamscan not installed)"); return 0
    dbdir = Path(tools_dir) / "clamdb"
    dbarg = ""
    fc = shutil.which("freshclam")
    need_db = not (dbdir.exists() and list(dbdir.glob("*.c?d")))
    if fc and need_db and install:
        dbdir.mkdir(parents=True, exist_ok=True)
        xt_sh(f'"{fc}" --quiet --datadir="{dbdir}"', 600)
    if dbdir.exists() and list(dbdir.glob("*.c?d")): dbarg = f'-d "{dbdir}"'
    o, e, rc = xt_sh(f'"{cs}" -r --infected --no-summary --max-filesize=100M --max-scansize=300M {dbarg} "{base}"', 3600)
    if rc == 2 and "database" in (e or "").lower():
        log("WARN", "  ClamAV has no signature database - run: sudo freshclam"); return 0
    n = 0
    for ln in o.splitlines():
        m = re.match(r"^(.*): (\S+) FOUND$", ln.strip())
        if m:
            n += 1
            if n <= 60: lin_add(results, "CRITICAL" if xt_CRIT_RULE.search(m.group(2)) else "HIGH", "CLAMAV", f"ClamAV: {m.group(2)} in {Path(m.group(1)).name}", {"signature": m.group(2), "path": m.group(1)[:200]}, m.group(1))
    log("OK" if n else "INFO", f"  ClamAV: {n} infected file(s)")
    return n


def xt_run_audit(base, results, log):
    ar = shutil.which("aureport")
    files = [p for p in xt_files(base, re.compile(r"^audit\.log(\.\d+)?$"))]
    if not ar or not files: return 0
    fails, anoms = Counter(), Counter()
    for f in files:
        o, e, rc = xt_sh(f'"{ar}" -if "{f}" --auth --failed -i', 120)
        for ln in o.splitlines():
            m = re.match(r"^\d+\.\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)", ln.strip())
            if m and m.group(2) not in ("?", "-", "(null)"): fails[(m.group(2), m.group(1))] += 1
        o, e, rc = xt_sh(f'"{ar}" -if "{f}" --anomaly -i', 120)
        for ln in o.splitlines():
            m = re.match(r"^\d+\.\s+\S+\s+\S+\s+(\S+)", ln.strip())
            if m and m.group(1).startswith(("ANOM", "anom")): anoms[m.group(1)] += 1
    byhost = Counter()
    for (host, acct), n in fails.items(): byhost[host] += n
    for host, n in byhost.most_common(15):
        if n >= 5: lin_add(results, "HIGH", "AUDITD", f"Brute-force pattern: {n} failed authentications from {host} (auditd)", {"host": host, "count": str(n)}, files[0])
    for typ, n in anoms.most_common(10): lin_add(results, "MEDIUM", "AUDITD", f"auditd anomaly {typ} x{n}", {"type": typ, "count": str(n)}, files[0])
    log("OK" if (byhost or anoms) else "INFO", f"  auditd: {sum(byhost.values())} failed auth, {sum(anoms.values())} anomalies")
    return len(byhost) + len(anoms)


def xt__last_ts(parts):
    try: return datetime.strptime(" ".join(parts.split()), "%a %b %d %H:%M:%S %Y")
    except Exception: return None


def xt_run_last(base, results, log):
    """wtmp / btmp via last / lastb: brute-force sources and logins from public IPs. Returns extra logons for correlation."""
    extra = {}
    for rx, cmdname, failed in ((re.compile(r"^wtmp(\.\d+)?$"), "last", False), (re.compile(r"^btmp(\.\d+)?$"), "lastb", True)):
        files = xt_files(base, rx)
        exe = shutil.which(cmdname)
        if not files or not exe: continue
        bad = Counter(); okl = []
        for f in files:
            o, e, rc = xt_sh(f'"{exe}" -f "{f}" -F -i -w', 120)
            for ln in o.splitlines():
                m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})", ln)
                if not m or m.group(1) in ("reboot", "shutdown", "runlevel", "wtmp", "btmp"): continue
                user, tty, ip, ts = m.group(1), m.group(2), m.group(3), xt__last_ts(m.group(4))
                if failed: bad[ip] += 1
                elif ts and ip not in ("0.0.0.0", "::", "-"):
                    okl.append((ts, user, ip))
                    extra[f"{user}@{ts.isoformat()}"] = {"ts": ts, "type": "ssh", "user": user, "domain": "", "ip": ip, "ws": tty, "log": f.name}
        for ip, n in bad.most_common(15):
            if n >= 10: lin_add(results, "HIGH", "BTMP", f"Brute-force: {n} failed logins from {ip} (btmp)", {"ip": ip, "count": str(n)}, files[0])
            if not epr_is_private_ip(ip) and ip not in ("0.0.0.0", "-"): results["external_ips"].add(ip)
        for ts, user, ip in okl:
            if not epr_is_private_ip(ip):
                results["external_ips"].add(ip)
                lin_add(results, "HIGH" if user == "root" else "MEDIUM", "WTMP", f"Login by {user} from public IP {ip}", {"user": user, "ip": ip, "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S")}, files[0])
        log("OK", f"  {cmdname}: {len(okl) if not failed else sum(bad.values())} record(s) from {len(files)} file(s)")
    return extra


def xt_run_journal(base, out, log):
    jc = shutil.which("journalctl")
    files = xt_files(base, re.compile(r"\.journal$"), 100)
    if not jc or not files: return None
    d = Path(out) / "journal_text"; d.mkdir(parents=True, exist_ok=True)
    for f in files:
        o, e, rc = xt_sh(f'"{jc}" --file "{f}" -o short-iso --no-pager', 300)
        if o.strip(): (d / f"journal_{f.stem}.log").write_text(o, encoding="utf-8", errors="replace")
    log("OK", f"  journalctl: exported {len(files)} journal file(s) to text for correlation")
    return d


def xt_run_bulk(dumps, out, log):
    """bulk_extractor net scanners on memory dumps -> IP / domain / URL IOCs (cached in bulk_iocs.json)."""
    be = shutil.which("bulk_extractor")
    if not be or not dumps: return []
    iocs = []
    for d in dumps[:3]:
        od = Path(out) / f"bulk_{Path(d).stem}"
        if od.exists(): shutil.rmtree(od, ignore_errors=True)
        xt_sh(f'"{be}" -q -o "{od}" -x all -e net -e email "{d}"', 3600)
        for fn, kind in (("ip_histogram.txt", "ip"), ("domain_histogram.txt", "domain"), ("url_histogram.txt", "url")):
            fp = od / fn
            if not fp.exists(): continue
            for ln in fp.read_text(errors="ignore").splitlines()[:400]:
                m = re.match(r"^n=(\d+)\t(.+?)(?:\t.*)?$", ln)
                if m: iocs.append({"value": m.group(2).strip(), "kind": kind, "count": int(m.group(1))})
    try: (Path(out) / "bulk_iocs.json").write_text(json.dumps(iocs), encoding="utf-8")
    except Exception: pass
    log("OK" if iocs else "INFO", f"  bulk_extractor: {len(iocs)} network IOC(s) carved from memory")
    return iocs


def xt_run_all(os_type, base, out, results, log, tools_dir, dumps=None, install=True):
    """Run every available external tool for Linux/macOS evidence; findings go straight into results."""
    o = xt_os(os_type)
    log("HEAD", f"Running external tools ({o})")
    summary = {}
    try: have = xt_setup(os_type, tools_dir, log, install)
    except Exception as e: log("WARN", f"  tool setup: {e}"); have = {}
    steps = [("yara", lambda: xt_run_yara(base, tools_dir, results, log)), ("clamav", lambda: xt_run_clam(base, tools_dir, results, log, install))]
    if o == "linux": steps.append(("auditd", lambda: xt_run_audit(base, results, log)))
    for nm, fn in steps:
        try: summary[nm] = fn()
        except Exception as e: log("WARN", f"  {nm}: {type(e).__name__}: {e}")
    try: UNI_CTX["extra_logons"] = xt_run_last(base, results, log)
    except Exception as e: log("WARN", f"  last/lastb: {e}")
    try:
        jd = xt_run_journal(base, out, log)
        if jd: UNI_CTX.setdefault("extra_log_dirs", []).append(str(jd))
    except Exception as e: log("WARN", f"  journalctl: {e}")
    try:
        dl = dumps if dumps is not None else uni_memory_dumps(base)
        xt_run_bulk(dl, out, log)
    except Exception as e: log("WARN", f"  bulk_extractor: {e}")
    return summary


# ═══════════════════════════════════════════════════════════════════════════
# OFFLINE ACQUISITION KIT (for quarantined / air-gapped systems)
#   build on a network-connected machine:   python3 forensics_master_FINAL.py --build-kit --os windows --out ./acq_kit
#   copy the folder to a USB drive, run RUN_ME.bat (Windows) / run_me.sh (Linux, macOS) on the quarantined system
# ═══════════════════════════════════════════════════════════════════════════
KIT_PY_URLS = ["https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip",
               "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip",
               "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"]

KIT_LAUNCHER = r'''#!/usr/bin/env python3
"""Offline acquisition launcher - runs from the USB drive on the quarantined system. No internet needed."""
import os, sys, platform, shutil, tempfile, hashlib, socket, subprocess, getpass
from pathlib import Path
from datetime import datetime

KIT = Path(__file__).resolve().parent
os.environ["FM_OFFLINE"] = "1"                       # never try to download / pip install anything
tdir = KIT / "tools"
if platform.system() != "Windows" and tdir.exists():  # pendrives are often mounted noexec -> run tools from a temp copy
    tmp = Path(tempfile.mkdtemp(prefix="fm_tools_"))
    for f in tdir.iterdir():
        if f.is_file():
            shutil.copy2(f, tmp / f.name); os.chmod(tmp / f.name, 0o755)
    tdir = tmp
os.environ["PATH"] = str(tdir) + os.pathsep + os.environ.get("PATH", "")
sys.dont_write_bytecode = True                       # do not leave a root-owned __pycache__ on the USB drive
sys.path.insert(0, str(KIT))
import forensics_master as fm

args = sys.argv[1:]
osl = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
if not osl:
    print("Unsupported OS"); sys.exit(1)


def is_admin():
    try:
        if osl == "windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def ram_bytes():
    try:
        if osl == "linux":
            for ln in open("/proc/meminfo"):
                if ln.startswith("MemTotal"): return int(ln.split()[1]) * 1024
        if osl == "macos":
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]).strip())
        import ctypes
        class MS(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("m", ctypes.c_ulong), ("tp", ctypes.c_ulonglong)] + [(f"x{i}", ctypes.c_ulonglong) for i in range(5)]
        s = MS(); s.l = ctypes.sizeof(MS); ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)); return s.tp
    except Exception:
        return 0


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b""): h.update(b)
    return h.hexdigest()


host = socket.gethostname()
out = KIT / "output" / f"{host}_{datetime.now():%Y%m%d_%H%M%S}"
out.mkdir(parents=True, exist_ok=True)
print(f"\n=== OFFLINE ACQUISITION  host={host}  os={osl}  output={out} ===")
if not is_admin():
    print("!! NOT running as Administrator/root - collection will be incomplete (RAM capture needs it).")
free = shutil.disk_usage(out).free; ram = ram_bytes()
print(f"   free space on this drive: {free / 1e9:.1f} GB" + (f", RAM: {ram / 1e9:.1f} GB" if ram else ""))
if ram and free < ram * 1.2:
    print("!! USB drive free space is smaller than RAM x1.2 - a full RAM image will NOT fit. Use --no-ram or a bigger drive.")
if ram and ram > 4 * 1024 ** 3:
    print("   Note: FAT32 drives cannot hold files >4 GB. Use an exFAT/NTFS USB drive for a full RAM image.")
if "--no-ram" in args:   fm._ACQ_TL.answers = {"memory": False, "procs": "", "fuji": False}
elif "--auto" in args:   fm._ACQ_TL.answers = {"memory": True, "procs": "", "fuji": False}
fn = {"windows": fm.run_windows_acquisition, "linux": fm.run_linux_acquisition, "macos": fm.run_macos_acquisition}[osl]
collected = Path(fn(str(out)) or out)

# chain of custody: hashes of everything collected + environment info
print("\n[*] Writing integrity manifest (SHA-256) ...")
rows = []
for p in sorted(collected.rglob("*")):
    if p.is_file() and p.name not in ("MANIFEST_SHA256.txt", "ACQUISITION_INFO.txt"):
        try: rows.append(f"{sha256(p)}  {p.relative_to(collected)}")
        except Exception as e: rows.append(f"ERROR  {p.relative_to(collected)}  {e}")
(collected / "MANIFEST_SHA256.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
info = [f"Host: {host}", f"OS: {platform.platform()}", f"User: {getpass.getuser()}", f"Admin/root: {is_admin()}",
        f"Acquired (local time): {datetime.now():%Y-%m-%d %H:%M:%S}", f"Kit script SHA-256: {sha256(KIT / 'forensics_master.py')}",
        f"Python: {sys.version.split()[0]}", f"Files collected: {len(rows)}"]
(collected / "ACQUISITION_INFO.txt").write_text("\n".join(info) + "\n", encoding="utf-8")
try: fm.acq_fix_permissions(KIT / "output", write_meta=False)    # last step: hand the whole output/ tree (incl. manifest + info) back to the user
except Exception: pass
print(f"\n=== DONE: {collected}  ({len(rows)} files) ===")
print("Safely eject the USB drive, take it to the analysis machine, then in the GUI choose Analysis mode and set the evidence path to this folder.")
'''

KIT_BAT = r'''@echo off
REM Offline acquisition - run on the quarantined Windows system (auto-asks for Administrator)
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
if exist "python\python.exe" ( set "PY=python\python.exe" ) else ( set "PY=python" )
"%PY%" acquire.py %*
echo.
pause
'''

KIT_SH = r'''#!/bin/sh
# Offline acquisition - run on the quarantined Linux / macOS system
cd "$(dirname "$0")" || exit 1
if [ "$(id -u)" -ne 0 ]; then
  echo "Re-running with sudo (needed for full collection / RAM capture)..."
  exec sudo "$0" "$@"
fi
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "python3 not found on this system"; exit 1; }
exec "$PY" acquire.py "$@"
'''


def kit_norm_os(os_type):
    return {"windows": "windows", "win": "windows", "linux": "linux", "kali": "linux", "ubuntu": "linux", "macos": "macos", "mac": "macos", "darwin": "macos"}.get((os_type or "").lower())


def kit_build(os_type, out_dir, with_python=True, log=None):
    """Download every tool needed for acquisition and assemble a self-contained folder for a USB drive."""
    log = log or (lambda lvl, msg: print(f"[{lvl}] {msg}"))
    osl = kit_norm_os(os_type)
    if not osl: raise ValueError("os must be windows, linux or macos")
    kit = Path(out_dir).expanduser() / f"acq_kit_{osl}_{datetime.now():%Y%m%d}"
    tools = kit / "tools"; tools.mkdir(parents=True, exist_ok=True)
    log("HEAD", f"Building offline acquisition kit for {osl.upper()} -> {kit}")
    got = {}
    if osl == "windows":
        url = (epr_mem_github_latest_asset("Velocidex/WinPmem", [".exe"], log) or epr_mem_github_latest_asset("Velocidex/c-aff4", ["winpmem", ".exe"], log))
        got["tools/winpmem.exe (RAM capture)"] = bool(url and epr_mem_download_file(url, tools / "winpmem.exe", log))
        if with_python:
            ok = False
            for u in KIT_PY_URLS:
                try:
                    import zipfile, io
                    log("INFO", f"  downloading embeddable Python: {u.split('/')[-1]}")
                    data = _ur.urlopen(u, timeout=180).read()
                    (kit / "python").mkdir(exist_ok=True)
                    with zipfile.ZipFile(io.BytesIO(data)) as z: z.extractall(kit / "python")
                    ok = True; break
                except Exception as e:
                    log("WARN", f"  {u.split('/')[-1]}: {str(e)[:70]}")
            got["python/ (bundled Python - target needs no install)"] = ok
    elif osl == "linux":
        ok = False
        for u in ("https://github.com/microsoft/avml/releases/latest/download/avml",):
            ok = epr_mem_download_file(u, tools / "avml", log)
            if ok:
                try: (tools / "avml").chmod(0o755)
                except Exception: pass
                break
        got["tools/avml (RAM capture, x86_64 only)"] = bool(ok)
    else:
        url = epr_mem_github_latest_asset("Lazza/Fuji", [".dmg"], log)
        got["tools/Fuji.dmg (Full File System acquisition)"] = bool(url and epr_mem_download_file(url, tools / "Fuji.dmg", log))
        log("INFO", "  macOS: no free RAM-capture tool works on modern macOS; Fuji covers disk-side evidence")
    shutil.copy2(Path(__file__).resolve(), kit / "forensics_master.py")
    (kit / "acquire.py").write_text(KIT_LAUNCHER, encoding="utf-8")
    if osl == "windows": (kit / "RUN_ME.bat").write_text(KIT_BAT.replace("\n", "\r\n"), encoding="utf-8")
    else:
        (kit / "run_me.sh").write_text(KIT_SH, encoding="utf-8")
        try: (kit / "run_me.sh").chmod(0o755)
        except Exception: pass
    run = "Double-click RUN_ME.bat (it asks for Administrator)" if osl == "windows" else "Terminal: sudo ./run_me.sh  (or: sudo python3 acquire.py)"
    (kit / "README.txt").write_text(
        "OFFLINE ACQUISITION KIT\n=======================\n"
        f"Target OS : {osl}\nBuilt     : {datetime.now():%Y-%m-%d %H:%M:%S}\n\n"
        "1. Copy this whole folder to a USB drive (exFAT/NTFS recommended - FAT32 cannot hold a RAM image >4 GB).\n"
        "2. Plug it into the quarantined system (do NOT connect that system to a network).\n"
        f"3. {run}\n"
        "   Options: --no-ram (skip RAM capture)   --auto (capture RAM without asking)\n"
        "4. Evidence is written to  output/<hostname>_<time>/  on the USB drive, with MANIFEST_SHA256.txt and ACQUISITION_INFO.txt.\n"
        "5. Take the USB drive to the analysis machine -> GUI -> Analysis mode -> evidence path = that output folder.\n\n"
        "Notes: run as Administrator/root. Nothing is downloaded on the target (offline mode).\n", encoding="utf-8")
    sums = []
    for p in sorted(kit.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS.txt":
            h = hashlib.sha256(p.read_bytes()).hexdigest() if p.stat().st_size < 400 * 1048576 else "skipped(large)"
            sums.append(f"{h}  {p.relative_to(kit)}")
    (kit / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    for k, v in got.items(): log("OK" if v else "WARN", f"  {k}: {'downloaded' if v else 'NOT downloaded (no network / blocked) - RAM capture will be skipped on the target'}")
    log("OK", f"Kit ready: {kit}")
    return kit


def kit_cli(argv):
    ap = argparse.ArgumentParser(description="Build an offline acquisition kit for a quarantined system")
    ap.add_argument("--build-kit", action="store_true")
    ap.add_argument("--os", choices=["windows", "linux", "kali", "macos"], help="OS of the QUARANTINED system")
    ap.add_argument("--out", default="./acq_kit", help="where to create the kit folder (default ./acq_kit)")
    ap.add_argument("--no-python", action="store_true", help="Windows: do not bundle embeddable Python")
    a = ap.parse_args(argv)
    osx = a.os
    if not osx:
        print("Choose the OS of the quarantined system:\n  [1] Windows\n  [2] Linux / Kali\n  [3] macOS")
        osx = {"1": "windows", "2": "linux", "3": "macos"}.get(input("Choice [1-3]: ").strip(), "windows")
    kit = kit_build(osx, a.out, not a.no_python)
    print(f"\nNext: copy the folder \'{kit}\' to a USB drive and run " + ("RUN_ME.bat" if kit_norm_os(osx) == "windows" else "sudo ./run_me.sh") + " on the quarantined system.\n")


def epr__results_from_csv(path):
    res = {"critical": [], "high": [], "medium": []}
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            res.get(r.get("severity", "").lower(), res["medium"] if r.get("severity") == "LOW" else res["medium"]).append(
                {"severity": r.get("severity"), "source": r.get("source"), "desc": r.get("desc"), "file": r.get("file"), "timestamp": r.get("timestamp"), "data": {}})
    return res


# ===== EPR_BLOCK_END =====

# ===== ADP_BLOCK_BEGIN =====
# ══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE TRIAGE — format/folder-agnostic evidence handling
#   1. recursive inventory of EVERY file (folder names ignored)
#   2. extract archives (nested, password list)
#   3. identify each file: magic bytes -> header/content sniff -> generic text scan (for leftovers)
#   4. install ONLY allow-listed tools needed for the kinds found
#   5. normalise everything to the common event schema used by epr_find_entry_point()
# Only allow-listed tools are ever downloaded.
# ══════════════════════════════════════════════════════════════════════════════
import io
import gzip as adp_gzip, bz2 as adp_bz2, lzma as adp_lzma, zipfile as adp_zip, tarfile as adp_tar
import sqlite3 as adp_sqlite

adp_PASSWORDS = [None, "infected", "malware", "password", "forensics"]  # extra: set ADP_ARCHIVE_PASSWORDS env (comma sep)

# kind -> (what handles it, how it is obtained). Only these can ever be auto-installed.
adp_CATALOG = {
    "evtx":        ("Hayabusa + Chainsaw + python-evtx", "setup_tools()"),
    "reg_hive":    ("python-registry",                   "pip python-registry"),
    "memory":      ("Volatility3",                       "pip volatility3"),
    "pcap":        ("tshark",                            "apt tshark (needs sudo)"),
    "sqlite":      ("sqlite3 (stdlib)",                  "builtin"),
    "csv_events":  ("builtin CSV event parser",          "builtin"),
    "json_events": ("builtin JSON/JSONL parser",         "builtin"),
    "text_log":    ("builtin text-log parser",           "builtin"),
    "xml_events":  ("builtin EVTX-XML parser",           "builtin"),
    "mft":         ("analyzeMFT / MFTECmd",              "detected only — parse manually"),
    "prefetch":    ("PECmd / windowsprefetch",           "detected only — parse manually"),
    "disk_image":  ("sleuthkit + ewf-tools",             "detected only — mount/extract manually"),
    "pst":         ("readpst (pst-utils)",               "detected only"),
    "plist":       ("builtin text scan",                 "builtin"),
    "archive":     ("7z / zipfile / tarfile",            "builtin"),
    "binary_other":("none",                              "ignored (hashed only)"),
}
adp_KINDS = list(adp_CATALOG)

adp_TIME_COLS = ["timecreated", "time created", "date and time", "timestamp", "time", "date", "datetime",
                 "timegenerated", "@timestamp", "_time", "eventtime", "utctime", "created", "systemtime"]
adp_ID_COLS   = ["event id", "eventid", "id", "event_id", "eid"]
adp_PROV_COLS = ["providername", "provider", "source", "provider name", "channel", "logname"]
adp_MSG_COLS  = ["message", "msg", "description", "details", "text", "data"]
adp_HOST_COLS = ["machinename", "computer", "computername", "host", "hostname"]
adp_LEVEL_COLS = ["level", "levelname", "severity"]


# ---------------------------------------------------------------- inventory / sniffing
def adp_read_head(p, n=8192):
    try:
        with open(p, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def adp_decode_text(b):
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", errors="ignore")
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", errors="ignore")
    return b.decode("utf-8", errors="ignore")


def adp_is_texty(b):
    if not b:
        return False
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    bad = sum(1 for c in b[:4096] if c < 9 or (13 < c < 32))
    return bad / max(1, min(len(b), 4096)) < 0.02


def adp_sniff(p):
    """Returns (kind, note). Order: magic bytes -> text content -> size/extension heuristics."""
    p = Path(p)
    try:
        size = p.stat().st_size
    except Exception:
        return "binary_other", "stat failed"
    h = adp_read_head(p)
    ext = p.suffix.lower()
    if h[:8] == b"ElfFile\x00":                       return "evtx", "magic ElfFile"
    if h[:4] == b"regf":                              return "reg_hive", "magic regf"
    if h[:15] == b"SQLite format 3":                  return "sqlite", "magic sqlite"
    if h[:4] in (b"MDMP",) or h[:8] == b"PAGEDU64" or h[:8] == b"PAGEDUMP": return "memory", "dump magic"
    if h[:4] == b"EMiL":                              return "memory", "LiME magic"
    if h[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"): return "pcap", "pcap magic"
    if h[4:8] == b"SCCA" or h[:3] == b"MAM":          return "prefetch", "prefetch magic"
    if h[:4] == b"FILE" and size > 4096 and b"\x00" in h[:64]: return "mft", "MFT record magic"
    if h[:3] == b"EVF" or h[:4] == b"EVF2" or ext in (".e01", ".ex01", ".aff", ".vmdk", ".vhd", ".vhdx", ".dd", ".img"):
        return "disk_image", "disk image"
    if h[:4] == b"!BDN" or ext in (".pst", ".ost"):   return "pst", "outlook store"
    if h[:8] == b"bplist00":                          return "plist", "binary plist"
    if (h[:4] == b"PK\x03\x04" or h[:6] == b"7z\xbc\xaf\x27\x1c" or h[:4] == b"Rar!" or
            h[:2] == b"\x1f\x8b" or h[:3] == b"BZh" or h[:6] == b"\xfd7zXZ\x00" or ext in (".tar", ".tgz")):
        if ext in (".docx", ".xlsx", ".pptx", ".jar", ".apk"):
            return "binary_other", "office/jar zip"
        return "archive", "archive magic"
    if ext in (".raw", ".mem", ".vmem", ".lime", ".dmp", ".bin") and size > 50 * 1024 * 1024:
        return "memory", f"{size//1024//1024} MB memory-like"

    if adp_is_texty(h):
        t = adp_decode_text(h)
        first = t.lstrip().splitlines()[0] if t.strip() else ""
        low = t.lower()
        if "<event xmlns" in low or ("<events>" in low and "<event" in low):
            return "xml_events", "EVTX XML"
        if t.lstrip().startswith("{") and '"' in t:
            return "json_events", "JSON lines"
        if t.lstrip().startswith("[") and "{" in t[:50]:
            return "json_events", "JSON array"
        if "<?xml" in low[:100] and "<plist" in low:
            return "plist", "xml plist"
        for d in (",", "\t", ";", "|"):
            if first.count(d) >= 2:
                cols = [c.strip().strip('"').lower() for c in first.split(d)]
                if any(c in adp_TIME_COLS for c in cols) or any(c in adp_ID_COLS for c in cols):
                    return "csv_events", f"csv header ({d!r})"
        return "text_log", "plain text"
    return "binary_other", "unrecognised binary"


def adp_inventory(base, skip_dirs=()):
    items = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git") and os.path.join(root, d) not in skip_dirs]
        for fn in files:
            fp = Path(root) / fn
            try:
                if fp.is_symlink() and not fp.exists():
                    continue
                sz = fp.stat().st_size
            except Exception:
                continue
            if sz == 0:
                continue
            items.append(fp)
    return items


# ---------------------------------------------------------------- archives
def adp_extract(fp, dest, log):
    dest = Path(dest); dest.mkdir(parents=True, exist_ok=True)
    pw = list(adp_PASSWORDS) + [x for x in os.environ.get("ADP_ARCHIVE_PASSWORDS", "").split(",") if x]
    name = fp.name.lower()
    try:
        if name.endswith(".zip"):
            with adp_zip.ZipFile(fp) as z:
                for pwd in pw:
                    try:
                        z.extractall(dest, pwd=pwd.encode() if pwd else None); return True
                    except RuntimeError:
                        continue
        if name.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
            with adp_tar.open(fp, "r:*") as t:
                t.extractall(dest, filter="data") if hasattr(adp_tar, "data_filter") else t.extractall(dest)
            return True
        if name.endswith(".gz"):
            with adp_gzip.open(fp, "rb") as f, open(dest / fp.stem, "wb") as o: shutil.copyfileobj(f, o)
            return True
        if name.endswith(".bz2"):
            with adp_bz2.open(fp, "rb") as f, open(dest / fp.stem, "wb") as o: shutil.copyfileobj(f, o)
            return True
        if name.endswith(".xz"):
            with adp_lzma.open(fp, "rb") as f, open(dest / fp.stem, "wb") as o: shutil.copyfileobj(f, o)
            return True
        sevenz = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
        if sevenz:
            for pwd in pw:
                r = subprocess.run([sevenz, "x", f"-o{dest}", "-y", f"-p{pwd or ''}", str(fp)], capture_output=True, text=True, timeout=600)
                if r.returncode == 0:
                    return True
        log("WARN", f"  could not extract {fp.name} (wrong password or no 7z) — set ADP_ARCHIVE_PASSWORDS=pw1,pw2")
    except Exception as ex:
        log("WARN", f"  extract {fp.name}: {type(ex).__name__}: {ex}")
    return False


adp_AI_SYSTEM = ("You are a DFIR triage assistant. For each numbered file sample decide what it is. "
                 "Reply with ONLY a JSON object: {\"<index>\": {\"kind\": <one of KINDS>, \"why\": <8 words>, "
                 "\"ts_regex\": <python regex with ONE group capturing the timestamp, or null>, "
                 "\"ts_fmt\": <strptime format for that group, or null>}}. "
                 "KINDS = " + ", ".join(adp_KINDS) + ". Use binary_other if unsure. Never invent kinds.")


def adp_ai_classify(cfg, unknown, log):
    """unknown: list of (path, kind_guess). Returns {path: {kind, ts_regex, ts_fmt}}."""
    out = {}
    if not cfg or not unknown:
        return out
    for i in range(0, len(unknown), 25):
        chunk = unknown[i:i + 25]
        payload = {}
        for j, (p, g) in enumerate(chunk):
            h = adp_read_head(p, 700)
            payload[str(j)] = {"name": Path(p).name, "dir": Path(p).parent.name, "size": Path(p).stat().st_size,
                               "guess": g, "hex": h[:24].hex(),
                               "text": adp_decode_text(h)[:500] if adp_is_texty(h) else ""}
        txt = epr_ai_call(cfg, adp_AI_SYSTEM, json.dumps(payload), log)
        if not txt:
            continue
        m = re.search(r"\{.*\}", txt, re.S)
        try:
            data = json.loads(m.group(0)) if m else {}
        except Exception:
            data = {}
        for j, (p, g) in enumerate(chunk):
            r = data.get(str(j)) or {}
            k = r.get("kind")
            if k in adp_CATALOG:
                out[p] = {"kind": k, "why": r.get("why", ""), "ts_regex": r.get("ts_regex"), "ts_fmt": r.get("ts_fmt")}
    return out


# ---------------------------------------------------------------- tool provisioning (allow-list only)
def adp_ensure_tools(kinds, log, tools_dir, skip_setup=False):
    plan = []
    for k in sorted(kinds):
        tool, how = adp_CATALOG.get(k, ("?", "?"))
        plan.append((k, tool, how))
    log("HEAD", "Tool plan for what was found:")
    for k, tool, how in plan:
        log("INFO", f"  {k:<13} -> {tool}  [{how}]")
    if skip_setup:
        return
    if "reg_hive" in kinds:
        try:
            import Registry.Registry  # noqa
        except ImportError:
            run_cmd("pip3 install python-registry --break-system-packages -q", timeout=120)
    if "memory" in kinds and not shutil.which("vol"):
        log("INFO", "  installing Volatility3 ...")
        run_cmd("pip3 install volatility3 --break-system-packages -q", timeout=300)
    if "pcap" in kinds and not shutil.which("tshark"):
        _, _, rc = run_cmd("sudo -n apt-get install -y tshark -q 2>/dev/null", timeout=300)
        if not shutil.which("tshark"):
            log("WARN", "  tshark missing — run: sudo apt-get install -y tshark   (pcap parsing skipped until then)")
    for k in ("mft", "prefetch", "disk_image", "pst"):
        if k in kinds:
            log("WARN", f"  {k}: detected but not auto-parsed — {adp_CATALOG[k][0]}")


# ---------------------------------------------------------------- timestamp parsing
adp_TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
                  "%d/%m/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%d-%m-%Y %I:%M:%S %p", "%d/%m/%Y %I:%M:%S %p",
                  "%b %d %Y %H:%M:%S", "%Y%m%d%H%M%S", "%Y/%m/%d %H:%M:%S"]


def adp_ts(s, fmt=None, year=None):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    if re.fullmatch(r"\d{13}", s):
        return datetime.utcfromtimestamp(int(s) / 1000)
    if re.fullmatch(r"\d{10}(\.\d+)?", s):
        return datetime.utcfromtimestamp(float(s))
    if fmt:
        try:
            d = datetime.strptime(s, fmt)
            return d.replace(year=year) if (year and d.year == 1900) else d
        except Exception:
            pass
    d = epr_parse_ts(s)
    if d:
        return d
    s2 = re.sub(r"\s+", " ", s)
    for f in adp_TS_FORMATS:
        try:
            return datetime.strptime(s2[:len(datetime.now().strftime(f)) + 3].strip(), f)
        except Exception:
            continue
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)", s)   # syslog (no year)
    if m and year:
        try:
            return datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
        except Exception:
            pass
    return None


def adp_pick(cols, names):
    low = {c.lower().strip(): c for c in cols}
    for n in names:
        if n in low:
            return low[n]
    return None


# ---------------------------------------------------------------- generic classification of a row/line -> event
adp_KV = re.compile(r"^\s*([A-Za-z][A-Za-z _/\-\.]{1,40}):\s+(.*\S)\s*$", re.M)
adp_THREAT = re.compile(r"threat|malware|trojan|ransom|quarantin|blocked|infected|detected|virus|exploit|ioc", re.I)


def adp_msg_kv(msg):
    d = {}
    pairs = adp_KV.findall(msg or "")
    names = [k.strip() for k, _ in pairs]
    for k, v in pairs:
        d.setdefault(k.strip(), v.strip())
    # Windows 4624/4625: two "Account Name" blocks (Subject, then Target) -> take LAST for target
    accts = [v.strip() for k, v in pairs if k.strip() == "Account Name"]
    doms = [v.strip() for k, v in pairs if k.strip() == "Account Domain"]
    if accts:
        d["SubjectUserName"] = accts[0]; d["TargetUserName"] = accts[-1]
    if doms:
        d["TargetDomainName"] = doms[-1]
    for src, dst in (("Source Network Address", "IpAddress"), ("Logon Type", "LogonType"), ("Workstation Name", "Workstation"),
                     ("New Process Name", "NewProcessName"), ("Process Command Line", "CommandLine"),
                     ("Creator Process Name", "ParentProcessName"), ("Service Name", "ServiceName"),
                     ("Service File Name", "ServiceFileName"), ("Task Name", "TaskName"), ("Client Address", "ClientAddress"),
                     ("Image", "Image"), ("ParentImage", "ParentImage"), ("DestinationIp", "DestinationIp")):
        if src in d:
            d[dst] = d[src]
    return d


def adp_role_for(fname, provider):
    n = f"{fname} {provider}".lower()
    if "sysmon" in n: return "sysmon"
    if "security-auditing" in n or re.search(r"(^|[^a-z])security([^a-z]|$)", n) and "endpoint" not in n and "client" not in n: return "security"
    if "defender" in n: return "defender"
    if "remoteconnectionmanager" in n or "localsessionmanager" in n or "terminalservices" in n: return "rdp"
    if "powershell" in n: return "powershell"
    if any(v in n for v in epr_EDR_NAMES) or _is_edr_name(n): return "edr"
    if "service control manager" in n or re.search(r"(^|[^a-z])system([^a-z]|$)", n): return "system"
    return "other"


def adp_classify_event(role, eid, msg, ts, host, logname, fields=None):
    """Return a normalised event dict or None."""
    data = adp_msg_kv(msg)
    if fields:
        data.update({k: v for k, v in fields.items() if v})
    ev = {"ts": ts, "eid": eid, "channel": logname, "computer": host, "data": data}
    try:
        c = epr_classify(role, ev) if eid else None
    except Exception:
        c = None
    if c:
        return {"ts": ts, "eid": eid, "kind": c[0], "text": c[1], "sev": c[2], "log": logname, "host": host, "data": data}
    # EDR / unknown vendors: any threat-ish message in an EDR log, or a malware regex anywhere
    if role == "edr" and adp_THREAT.search(msg or "") and not re.search(r"no threat|0 threat|scan completed|update", msg or "", re.I):
        return {"ts": ts, "eid": eid, "kind": "edr_detect", "text": (msg or "")[:220].replace("\n", " "), "sev": "CRITICAL",
                "log": logname, "host": host, "data": {"Message": msg}}
    for pat, nm in epr_MAL_PATTERNS:
        if pat.search(msg or ""):
            return {"ts": ts, "eid": eid, "kind": "proc_create", "text": f"{nm}: {(msg or '')[:160]}".replace("\n", " "),
                    "sev": "HIGH", "log": logname, "host": host, "data": data}
    return None


# ---------------------------------------------------------------- loaders
adp_MAX_EVENTS = 300000


def adp_load_csv(fp, log, ts_hint=None):
    raw = fp.read_bytes()
    text = adp_decode_text(raw)
    first = text.splitlines()[0] if text else ""
    delim = max([",", "\t", ";", "|"], key=lambda d: first.count(d))
    rdr = csv.DictReader(io.StringIO(text), delimiter=delim)
    cols = rdr.fieldnames or []
    ct, ci, cp, cm = adp_pick(cols, adp_TIME_COLS), adp_pick(cols, adp_ID_COLS), adp_pick(cols, adp_PROV_COLS), adp_pick(cols, adp_MSG_COLS)
    ch, cl = adp_pick(cols, adp_HOST_COLS), adp_pick(cols, adp_LEVEL_COLS)
    year = datetime.fromtimestamp(fp.stat().st_mtime).year
    events, first_t, last_t, n = [], None, None, 0
    # day-first vs month-first guess: if any value has first field >12 it is day-first
    dayfirst = False
    for row in rdr:
        n += 1
        t = adp_ts(row.get(ct) if ct else None, year=year)
        if not t:
            continue
        first_t = t if not first_t or t < first_t else first_t
        last_t = t if not last_t or t > last_t else last_t
        if len(events) >= adp_MAX_EVENTS:
            continue
        try:
            eid = int(re.sub(r"\D", "", str(row.get(ci, "") or "")) or 0) if ci else 0
        except Exception:
            eid = 0
        prov = row.get(cp, "") if cp else ""
        msg = row.get(cm, "") if cm else ""
        if not msg:   # Event-Viewer-style CSV has no message: keep everything useful in one string
            msg = " ".join(str(v) for k, v in row.items() if v and k not in (ct,))
        role = adp_role_for(fp.stem, prov)
        e = adp_classify_event(role, eid, msg, t, row.get(ch, "") if ch else "", fp.name, fields=None)
        if e:
            events.append(e)
    return events, {"role": adp_role_for(fp.stem, ""), "first": first_t, "last": last_t, "records": n,
                    "note": "" if cm else "CSV has no Message column (Event-Viewer export) — IPs/usernames/commandlines are NOT available"}


def adp_load_json(fp, log):
    txt = adp_decode_text(fp.read_bytes()[:200 * 1024 * 1024])
    rows = []
    s = txt.lstrip()
    try:
        if s.startswith("["):
            rows = json.loads(s)
        else:
            for ln in txt.splitlines():
                ln = ln.strip()
                if ln.startswith("{"):
                    try: rows.append(json.loads(ln))
                    except Exception: pass
    except Exception:
        pass
    events, first_t, last_t = [], None, None
    year = datetime.fromtimestamp(fp.stat().st_mtime).year

    def flat(o, pre="", d=None):
        d = d if d is not None else {}
        if isinstance(o, dict):
            for k, v in o.items():
                flat(v, f"{pre}{k}.", d) if isinstance(v, (dict,)) else d.__setitem__((pre + k).lower(), v)
        return d
    for r in rows:
        if not isinstance(r, dict):
            continue
        f = flat(r)
        tk = next((k for k in f if k.split(".")[-1] in ("timestamp", "@timestamp", "time", "timecreated", "_time", "eventtime", "date", "systemtime")), None)
        t = adp_ts(f.get(tk), year=year) if tk else None
        if not t:
            continue
        first_t = t if not first_t or t < first_t else first_t
        last_t = t if not last_t or t > last_t else last_t
        eid = next((int(v) for k, v in f.items() if k.split(".")[-1] in ("eventid", "event_id", "id") and str(v).isdigit()), 0)
        msg = next((str(v) for k, v in f.items() if k.split(".")[-1] in ("message", "msg", "details", "description")), json.dumps(r)[:400])
        e = adp_classify_event(adp_role_for(fp.stem, str(f.get("channel", f.get("provider", "")))), eid, msg, t,
                               str(f.get("computer", f.get("host", ""))), fp.name,
                               fields={"IpAddress": str(f.get("ipaddress", "") or ""), "TargetUserName": str(f.get("targetusername", "") or "")})
        if e and len(events) < adp_MAX_EVENTS:
            events.append(e)
    return events, {"role": adp_role_for(fp.stem, ""), "first": first_t, "last": last_t, "records": len(rows), "note": ""}


adp_AUTH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)")
adp_AUTH_OK   = re.compile(r"Accepted (?:password|publickey|keyboard-interactive\S*) for (\S+) from ([0-9a-fA-F:.]+)")
adp_ISO_TS    = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
adp_SYS_TS    = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)")
adp_USER_RE   = re.compile(r"(?:user|account|username)[=: ]+['\"]?([\w.\-\\@$]+)", re.I)
adp_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def adp_load_text(fp, log, ts_regex=None, ts_fmt=None):
    year = datetime.fromtimestamp(fp.stat().st_mtime).year
    rx = None
    if ts_regex:
        try:
            rx = re.compile(ts_regex)
        except Exception:
            rx = None
    events, first_t, last_t, n = [], None, None, 0
    ok = fail = 0
    with open(fp, "rb") as f:
        for raw in f:
            n += 1
            ln = adp_decode_text(raw).rstrip()
            if not ln:
                continue
            t = None
            if rx:
                m = rx.search(ln)
                t = adp_ts(m.group(1), fmt=ts_fmt, year=year) if m else None
            if not t:
                m = adp_ISO_TS.search(ln) or adp_SYS_TS.search(ln)
                t = adp_ts(m.group(1), year=year) if m else None
            if not t:
                continue
            first_t = t if not first_t or t < first_t else first_t
            last_t = t if not last_t or t > last_t else last_t
            if len(events) >= adp_MAX_EVENTS:
                continue
            mf, mo = adp_AUTH_FAIL.search(ln), adp_AUTH_OK.search(ln)
            if mf:
                events.append({"ts": t, "eid": 0, "kind": "logon_fail", "text": f"{mf.group(1)} type 10 from {mf.group(2)}",
                               "sev": "INFO", "log": fp.name, "host": "", "data": {}}); fail += 1; continue
            if mo:
                events.append({"ts": t, "eid": 0, "kind": "logon_ok", "text": f"{mo.group(1)} type 10 from {mo.group(2)}",
                               "sev": "INFO", "log": fp.name, "host": "", "data": {}}); ok += 1; continue
            for pat, nm in epr_MAL_PATTERNS:
                if pat.search(ln):
                    events.append({"ts": t, "eid": 0, "kind": "proc_create", "text": f"{nm}: {ln[:160]}", "sev": "HIGH",
                                   "log": fp.name, "host": "", "data": {}})
                    break
    return events, {"role": "auth" if (ok or fail) else "text", "first": first_t, "last": last_t, "records": n, "note": ""}


def adp_load_sqlite(fp, results, log):
    found = 0
    try:
        con = adp_sqlite.connect(f"file:{fp}?mode=ro", uri=True)
        for (tname,) in con.execute("select name from sqlite_master where type='table'").fetchall():
            try:
                for row in con.execute(f'select * from "{tname}" limit 20000'):
                    line = " ".join(str(c) for c in row if c is not None)
                    for pat, nm in epr_MAL_PATTERNS:
                        if pat.search(line):
                            win_add(results, "HIGH", "ADAPTIVE_SQLITE", f"{fp.name}:{tname} {nm}", {"line": line[:300]}, fp); found += 1
                            break
                    for ip in win_extract_ips(line):
                        if not win_is_private(ip):
                            results["external_ips"].add(ip)
            except Exception:
                continue
        con.close()
    except Exception as ex:
        log("WARN", f"  sqlite {fp.name}: {ex}")
    return found


def adp_load_pcap(fp, results, log):
    if not shutil.which("tshark"):
        return 0
    out, _, rc = run_cmd(f'tshark -r "{fp}" -q -z conv,ip 2>/dev/null', timeout=300)
    n = 0
    for ip in win_extract_ips(out):
        if not win_is_private(ip):
            results["external_ips"].add(ip); n += 1
    dns, _, _ = run_cmd(f'tshark -r "{fp}" -Y dns.flags.response==0 -T fields -e dns.qry.name 2>/dev/null', timeout=300)
    for dom in set(dns.split()):
        if not _is_whitelisted(dom):
            for pat in SUSP_DOMAIN_RE:
                if pat.search(dom):
                    results["suspicious_domains"].add(dom)
                    win_add(results, "HIGH", "ADAPTIVE_PCAP_DNS", f"Suspicious DNS in pcap: {dom}", {"domain": dom}, fp)
                    break
    return n


# ---------------------------------------------------------------- orchestrator
def adp_run(base, out_dir, results, log, ai_cfg=None, skip_setup=False, tools_dir="./tools"):
    """Returns dict(events, coverage, dirs{evtx,registry,memory}, manifest)."""
    base = Path(base)
    out = Path(out_dir); work = out / "_adaptive"; work.mkdir(parents=True, exist_ok=True)
    log("HEAD", "Adaptive triage: scanning ALL files regardless of folder/format")

    # 1) inventory + nested archive extraction (depth 3)
    seen_arch, files = set(), []
    scan_roots = [base]
    for depth in range(3):
        newroots = []
        for root in scan_roots:
            for fp in adp_inventory(root, skip_dirs=(str(out),)):
                kind, note = adp_sniff(fp)
                if kind == "archive" and str(fp) not in seen_arch:
                    seen_arch.add(str(fp))
                    dest = work / "extracted" / f"{len(seen_arch):03d}_{fp.stem}"
                    log("INFO", f"  extracting {fp.name} -> {dest.name}")
                    if adp_extract(fp, dest, log):
                        newroots.append(dest)
                elif kind != "archive":
                    files.append((fp, kind, note))
        if not newroots:
            break
        scan_roots = newroots
    log("OK", f"Inventory: {len(files)} files")

    # 2) classification of leftovers (text_log / binary_other only)
    leftovers = [(str(fp), k) for fp, k, _ in files if k in ("text_log", "binary_other") and fp.stat().st_size < 2 * 1024 ** 3]
    ai_info = {}
    if ai_cfg and leftovers:
        log("INFO", f"Analyst engine classifying {len(leftovers)} unidentified file(s) ...")
        ai_info = adp_ai_classify(ai_cfg, leftovers[:200], log)
    elif leftovers and not ai_cfg:
        log("INFO", f"{len(leftovers)} unidentified file(s) handled by generic text/IOC scan")
    files = [(fp, ai_info.get(str(fp), {}).get("kind", k), note) for fp, k, note in files]

    by_kind = defaultdict(list)
    for fp, k, note in files:
        by_kind[k].append(fp)
    log("HEAD", "What was found:")
    for k, v in sorted(by_kind.items(), key=lambda x: -len(x[1])):
        log("INFO", f"  {k:<13} {len(v):>5} file(s)  e.g. {v[0].name}")

    # 3) tools
    adp_ensure_tools(set(by_kind), log, tools_dir, skip_setup)

    # 4) stage evtx / hives / memory in clean dirs (proper extensions) so the existing modules work
    dirs = {}
    def stage(kind, sub, suffix):
        if not by_kind.get(kind):
            return None
        d = work / sub; d.mkdir(exist_ok=True)
        for i, fp in enumerate(by_kind[kind]):
            nm = fp.name if fp.name.lower().endswith(suffix) else fp.name + suffix
            dst = d / nm
            if dst.exists():
                dst = d / f"{i}_{nm}"
            try:
                os.symlink(fp.resolve(), dst)
            except Exception:
                shutil.copy2(fp, dst)
        return str(d)
    dirs["evtx"] = stage("evtx", "evtx", ".evtx")
    dirs["registry"] = stage("reg_hive", "registry", ".hiv")
    dirs["memory"] = stage("memory", "memory", "")

    # 5) parse everything else into normalised events
    events, coverage = [], {}
    for k in ("csv_events", "json_events", "text_log", "xml_events"):
        for fp in by_kind.get(k, []):
            try:
                if k == "csv_events":
                    ev, cov = adp_load_csv(fp, log)
                elif k == "json_events":
                    ev, cov = adp_load_json(fp, log)
                else:
                    ai = ai_info.get(str(fp), {})
                    ev, cov = adp_load_text(fp, log, ai.get("ts_regex"), ai.get("ts_fmt"))
                events += ev
                coverage[fp.name] = cov
                log("INFO", f"  {fp.name}: {cov['records']:,} rows, {len(ev):,} relevant, "
                            f"{epr_fmt(cov['first'])} -> {epr_fmt(cov['last'])}" + (f"  [{cov['note']}]" if cov.get("note") else ""))
            except Exception as ex:
                log("WARN", f"  {fp.name}: {type(ex).__name__}: {ex}")
    for fp in by_kind.get("sqlite", []):
        n = adp_load_sqlite(fp, results, log); log("INFO", f"  sqlite {fp.name}: {n} hit(s)")
    for fp in by_kind.get("pcap", []):
        n = adp_load_pcap(fp, results, log); log("INFO", f"  pcap {fp.name}: {n} external IP(s)")
    for k in ("plist", "binary_other"):
        for fp in by_kind.get(k, []):
            if k == "plist" or fp.stat().st_size < 20 * 1024 * 1024:
                try:
                    blob = fp.read_bytes()[:5 * 1024 * 1024].decode("latin-1", errors="ignore")
                    for ip in win_extract_ips(blob):
                        if not win_is_private(ip): results["external_ips"].add(ip)
                except Exception:
                    pass

    # 6) mirror important normalised events into the tool's findings (dashboard)
    for e in events:
        if e["kind"] in ("edr_detect", "av_detect", "log_cleared", "acct_created", "group_add", "svc_install", "task_created",
                         "proc_create", "ps_block", "audit_changed"):
            sev = "CRITICAL" if e["sev"] == "CRITICAL" else "HIGH"
            win_add(results, sev, "ADAPTIVE_" + e["kind"].upper(), f"{epr_KIND_LABEL.get(e['kind'], e['kind'])}: {e['text'][:140]}",
                    {"timestamp": epr_fmt(e["ts"]), "computer": e.get("host", ""), "detail": e["text"][:300]}, e["log"])

    manifest = [{"path": str(fp), "kind": k, "note": n, "size": fp.stat().st_size} for fp, k, n in files]
    (out / "adaptive_manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    log("OK", f"Adaptive triage done: {len(events):,} normalised events, manifest -> adaptive_manifest.json")
    return {"events": events, "coverage": coverage, "dirs": dirs, "manifest": manifest}
# ===== ADP_BLOCK_END =====


def win_main(argv=None):
    win_banner()
    parser = argparse.ArgumentParser(
        description="Windows Forensics Master Analyzer v3.0",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Auto-detect all folders from base path:
  python3 forensics_master.py --base ~/Downloads/"SCDC Forensic Logs/VEEAM-MGMT-SRV_20260901_160713"

  # With API keys:
  python3 forensics_master.py --base /path/to/evidence --vt-key XXXX --abuse-key YYYY

  # Custom paths:
  python3 forensics_master.py --evtx /data/winevt/ --network /data/network/ --memory /data/memory/
""")
    parser.add_argument("--base",      help="Base evidence folder (auto-detects subfolders)")
    parser.add_argument("--evtx",      help="EVTX / winevt folder")
    parser.add_argument("--network",   help="Network folder")
    parser.add_argument("--memory",    help="Memory dumps folder")
    parser.add_argument("--registry",  help="Registry folder")
    parser.add_argument("--artifacts", help="Artifacts folder")
    parser.add_argument("--hashes",    help="hashes.csv path")
    parser.add_argument("--output",    default="./forensics_output", help="Output folder")
    parser.add_argument("--tools-dir", default="./tools", help="Tools directory")
    parser.add_argument("--vt-key",    help="VirusTotal API key")
    parser.add_argument("--abuse-key", help="AbuseIPDB API key")
    parser.add_argument("--skip-setup",action="store_true", help="Skip tool download")
    parser.add_argument("--skip-memory",action="store_true",help="Skip memory analysis (faster)")
    parser.add_argument("--no-report",  action="store_true", help="Skip entry-point analysis + PDF report")
    parser.add_argument("--no-adaptive", action="store_true", help="Disable adaptive (format/folder-agnostic) triage")
    parser.add_argument("--no-review", dest="no_ai", action="store_true", help="Skip the analyst-engine review/report narrative")
    parser.add_argument("--engine", dest="ai_provider", choices=["auto","ollama","anthropic","gemini","meta"], default="auto",
                        help="Analyst backend(s) to use (default: auto - tries Ollama, then Claude, Gemini, Meta, whichever is configured/reachable)")
    parser.add_argument("--ollama-host", help="Ollama server URL (default http://localhost:11434 or env OLLAMA_HOST)")
    parser.add_argument("--ollama-model", help="Ollama model name (default llama3.1 or env OLLAMA_MODEL)")
    parser.add_argument("--engine-key", dest="ai_key", help="Anthropic (Claude) API key (or env ANTHROPIC_API_KEY)")
    parser.add_argument("--engine-model", dest="ai_model", help="Anthropic model name (default claude-sonnet-5-5)")
    parser.add_argument("--gemini-key", help="Google Gemini API key (or env GEMINI_API_KEY / GOOGLE_API_KEY)")
    parser.add_argument("--gemini-model", help="Gemini model name (default gemini-2.5-flash)")
    parser.add_argument("--meta-key",   help="Meta Llama API key (or env META_API_KEY / LLAMA_API_KEY)")
    parser.add_argument("--meta-model", help="Meta Llama API model name (default Llama-4-Scout-17B-16E-Instruct-FP8)")
    parser.add_argument("--non-interactive", action="store_true", help="Never prompt for an engine choice/key during the report step (use flags/env or skip)")
    parser.add_argument("--report-from-csv", help="Only build the PDF from an existing findings.csv (add --edr-csv, --evtx, --base if available)")
    parser.add_argument("--edr-csv",    help="edr_detections.csv path (used with --report-from-csv)")
    args = parser.parse_args(argv)

    if args.report_from_csv:
        _o = Path(args.output); _o.mkdir(parents=True, exist_ok=True)
        _rep = epr_generate(epr__results_from_csv(args.report_from_csv), _o, evtx_dir=args.evtx, base=args.base,
                            memory_dir=args.memory, edr_csv=args.edr_csv, registry_dir=args.registry, use_ai=not args.no_ai,
                            ai_provider=args.ai_provider, ollama_host=args.ollama_host, ollama_model=args.ollama_model,
                            ai_key=args.ai_key, ai_model=args.ai_model, gemini_key=args.gemini_key, gemini_model=args.gemini_model,
                            meta_key=args.meta_key, meta_model=args.meta_model, interactive=not args.non_interactive, log=win_log)
        print(f"  Entry point: {_rep['entry_point']['status']} (see correlation.json; full report is built by a normal analysis run)")
        return

    if not any([args.base, args.evtx, args.network, args.memory,
                args.registry, args.artifacts]):
        parser.print_help()
        sys.exit(0)

    # Auto-detect from base
    if args.base:
        base = Path(args.base)
        base = epr_normalize_evidence_base(base, Path(args.output), win_log)
        print(f"\n{win_C.CYN}[*] Auto-detecting folders in: {base}{win_C.RST}")

        # Map: folder names → arg attribute
        folder_map = [
            (["winevt","evtx","logs/evtx","EventLogs"],     "evtx"),
            (["network","Network","net"],                    "network"),
            (["memory","Memory","mem","dump"],               "memory"),
            (["registry","Registry","reg","hives"],          "registry"),
            (["artifacts","Artifacts","artifact"],           "artifacts"),
        ]
        for candidates, attr in folder_map:
            if not getattr(args, attr):
                for cand in candidates:
                    p = base / cand
                    if p.exists() and p.is_dir():
                        setattr(args, attr, str(p))
                        print(f"  {win_C.GRN}✓{win_C.RST} {attr:<12} → {p}")
                        break
                else:
                    print(f"  {win_C.YEL}✗{win_C.RST} {attr:<12} → not found")

        # Hash files
        for hf in ["hashes.csv","forensics_hashes.csv","hashes.txt"]:
            if not args.hashes and (base/hf).exists():
                args.hashes = str(base/hf)
                print(f"  {win_C.GRN}✓{win_C.RST} hashes      → {base/hf}")
                break
        print()

    # Setup
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    # ── Adaptive triage: works on ANY folder layout / format ──────────────────
    _adp = None
    _ai_cfg = None
    if args.base and not getattr(args, "no_adaptive", False):
        if not getattr(args, "no_ai", False):
            try:
                _picked = None
                if not getattr(args, "non_interactive", False) and getattr(args, "ai_provider", "auto") == "auto":
                    _picked = epr_interactive_ai_setup(win_log, getattr(args, "ollama_model", None), getattr(args, "ai_model", None),
                                                       getattr(args, "gemini_model", None), getattr(args, "meta_model", None),
                                                       getattr(args, "ollama_host", None), getattr(args, "meta_host", None))
                if _picked == "skip":
                    _ai_cfg = None
                elif _picked:
                    _ai_cfg = _picked
                else:
                    _ai_cfg = epr_resolve_ai_cfg(win_log, getattr(args, "ai_provider", "auto"), args.ollama_host, args.ollama_model,
                                                 args.ai_key or os.environ.get("ANTHROPIC_API_KEY"), args.ai_model,
                                                 args.gemini_key or os.environ.get("GEMINI_API_KEY"), args.gemini_model,
                                                 args.meta_key or os.environ.get("META_API_KEY"), args.meta_model, None)
            except Exception as _e:
                win_log("WARN", f"Analyst engine setup failed: {_e}")
        _results_tmp = win_new_results()
        try:
            _adp = adp_run(args.base, out, _results_tmp, win_log, ai_cfg=_ai_cfg, skip_setup=args.skip_setup, tools_dir=args.tools_dir)
            for _k, _a in (("evtx", "evtx"), ("registry", "registry"), ("memory", "memory")):
                if not getattr(args, _a) and _adp["dirs"].get(_k):
                    setattr(args, _a, _adp["dirs"][_k])
                    print(f"  {win_C.GRN}✓{win_C.RST} {_a:<12} → {_adp['dirs'][_k]}  (found by content, not folder name)")
        except Exception as _e:
            import traceback; traceback.print_exc()
            win_log("WARN", f"Adaptive triage failed: {_e}")

    if not args.skip_setup:
        paths = setup_tools(args.tools_dir)
    else:
        td = Path(args.tools_dir)
        paths = {}
        for name, candidates in [
            ("hayabusa", [td/"hayabusa"/"hayabusa"]),
            ("chainsaw",  [td/"chainsaw"/"chainsaw"]),
            ("sigma",     [td/"sigma"]),
            ("chainsaw_mapping", [
                td/"chainsaw"/"mappings"/"sigma-event-logs-all.yml",
                td/"mappings"/"sigma-event-logs-all.yml",
            ])
        ]:
            for c in candidates:
                if c.exists():
                    paths[name] = str(c)
                    break
        out2,_,rc = run_cmd("vol --help 2>/dev/null", timeout=10)
        paths["volatility"] = "vol" if rc==0 else None

    results = win_new_results()
    if _adp:
        for _sev in ("critical", "high", "medium"):
            results[_sev].extend(_results_tmp[_sev])
        results["external_ips"] |= _results_tmp["external_ips"]
        results["suspicious_domains"] |= _results_tmp["suspicious_domains"]
    start   = datetime.now()
    _live = AnalystLive(_ai_cfg, win_log) if _ai_cfg else None
    _marks = {}

    # ── Run all modules ───────────────────────────────────────────────────────
    print(f"\n{win_C.CYN}{win_C.BOLD}{'═'*60}")
    print("  STARTING ANALYSIS")
    print(f"{'═'*60}{win_C.RST}\n")

    if args.evtx:
        # 1. Hayabusa (fastest, best detection)
        run_hayabusa(args.evtx, str(out), paths.get("hayabusa"), results)
        # 2. Chainsaw with Sigma
        run_chainsaw(args.evtx, str(out), paths.get("chainsaw"),
                     paths.get("sigma"), paths.get("chainsaw_mapping"), results)
        # 3. Deep EVTX (python-evtx) — EDR + patterns
        run_evtx_analysis(args.evtx, results)
        win_live_feed(_live, "evtx", results, _marks, out)

    if args.network:
        run_network_analysis(args.network, results)
        win_live_feed(_live, "network", results, _marks, out)

    if args.memory and not args.skip_memory:
        run_volatility(args.memory, str(out), paths.get("volatility"), results)
        win_live_feed(_live, "memory", results, _marks, out)

    if args.registry:
        run_registry_analysis(args.registry, results)
        win_live_feed(_live, "registry", results, _marks, out)

    if args.artifacts:
        run_artifacts_analysis(args.artifacts, results)
        win_live_feed(_live, "artifacts", results, _marks, out)

    # Threat Intel (last — uses all collected IPs/hashes)
    if args.vt_key or args.abuse_key:
        win_run_threat_intel(results, args.hashes, args.vt_key, args.abuse_key)

    # ── Save outputs ──────────────────────────────────────────────────────────
    # JSON
    json_path = out / "results.json"
    with open(json_path, 'w') as f:
        json.dump({
            "generated": datetime.now().isoformat(),
            "duration_seconds": (datetime.now()-start).seconds,
            "summary": {
                "critical": len(results["critical"]),
                "high": len(results["high"]),
                "medium": len(results["medium"]),
                "external_ips": len(results["external_ips"]),
                "c2_indicators": len(results["c2_indicators"]),
                "hayabusa_hits": len(results["hayabusa"]),
                "chainsaw_hits": len(results["chainsaw"]),
                "cisco_hits": len(results["cisco_hits"]),
                "dns_suspicious": len(results["dns_hits"]),
                "threat_intel": len(results["threat_intel"]),
            },
            "critical_findings": results["critical"][:200],
            "high_findings": results["high"][:200],
            "c2_indicators": results["c2_indicators"],
            "cisco_hits": results["cisco_hits"],
            "hayabusa_hits": results["hayabusa"][:200],
            "external_ips": sorted(list(results["external_ips"])),
            "dns_hits": results["dns_hits"],
            "threat_intel": results["threat_intel"],
        }, f, indent=2, default=str)

    # CSV
    csv_path = out / "findings.csv"
    all_f = results["critical"] + results["high"] + results["medium"]
    with open(csv_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=["severity","source","desc","file","timestamp"])
        w.writeheader()
        for item in all_f:
            w.writerow({k: item.get(k,"") for k in ["severity","source","desc","file","timestamp"]})

    # HTML
    uni_dump_results(results, out)
    html_path = win_generate_dashboard(results, out)


    # --- entry-point & correlation analysis (feeds the single report) ---
    if not getattr(args, "no_report", False):
        try:
            _rep = epr_generate(results, out, evtx_dir=args.evtx, base=args.base, memory_dir=args.memory,
                                extra_events=(_adp or {}).get("events"), extra_coverage=(_adp or {}).get("coverage"), ai_cfg=_ai_cfg,
                                registry_dir=args.registry, live_notes=(_live.finish() if _live else None),
                                use_ai=not getattr(args, "no_ai", False), ai_provider=getattr(args, "ai_provider", None),
                                ollama_host=getattr(args, "ollama_host", None), ollama_model=getattr(args, "ollama_model", None),
                                ai_key=getattr(args, "ai_key", None), ai_model=getattr(args, "ai_model", None),
                                gemini_key=getattr(args, "gemini_key", None), gemini_model=getattr(args, "gemini_model", None),
                                meta_key=getattr(args, "meta_key", None), meta_model=getattr(args, "meta_model", None),
                                interactive=not getattr(args, "non_interactive", False), log=win_log)
            try:
                _cs = json.loads((out / "correlation_sections.json").read_text(encoding="utf-8")) if (out / "correlation_sections.json").exists() else []
                _rv = (out / "analyst_review.txt").read_text(encoding="utf-8") if (out / "analyst_review.txt").exists() else None
                uni_inject_html(out / "dashboard.html", _cs, _rv)
            except Exception: pass
            if _rep.get("pdf"):
                print(f"  PDF report : {_rep['pdf']}")
            print(f"  Entry point: {_rep['entry_point']['status']}")
        except Exception as _e:
            win_log("WARN", f"Entry-point/PDF report failed: {_e}")

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = (datetime.now()-start).seconds
    print(f"""
{win_C.BOLD}{win_C.CYN}{'═'*62}
  ANALYSIS COMPLETE  ({elapsed}s)
{'═'*62}{win_C.RST}
  {win_C.RED}🔴 CRITICAL      : {len(results['critical'])}{win_C.RST}
  {win_C.YEL}🟠 HIGH          : {len(results['high'])}{win_C.RST}
  {win_C.BLU}🔵 MEDIUM        : {len(results['medium'])}{win_C.RST}
  {win_C.CYN}🌐 EXTERNAL IPs  : {len(results['external_ips'])}{win_C.RST}
  {win_C.MAG}🎯 C2 INDICATORS : {len(results['c2_indicators'])}{win_C.RST}
  {win_C.MAG}🎯 CISCO HITS    : {len(results['cisco_hits'])}{win_C.RST}
  {win_C.GRN}🔍 HAYABUSA      : {len(results['hayabusa'])}{win_C.RST}
  {win_C.GRN}🔍 CHAINSAW      : {len(results['chainsaw'])}{win_C.RST}
  {win_C.GRN}🔍 DNS SUSPICIOUS: {len(results['dns_hits'])}{win_C.RST}
  {win_C.RED}🧬 THREAT INTEL  : {len(results['threat_intel'])}{win_C.RST}
{win_C.BOLD}{'═'*62}{win_C.RST}
  📊 Dashboard : {html_path}
  📋 JSON      : {json_path}
  📄 CSV       : {csv_path}
{win_C.BOLD}{'═'*62}{win_C.RST}
""")
    if results["critical"]:
        print(f"{win_C.RED}{win_C.BOLD}🚨 TOP CRITICAL:{win_C.RST}")
        for f in results["critical"][:8]:
            print(f"  • [{f['source']}] {f['desc'][:90]}")
    if results["c2_indicators"]:
        print(f"\n{win_C.MAG}{win_C.BOLD}🎯 C2 INDICATORS:{win_C.RST}")
        for c in results["c2_indicators"][:5]:
            print(f"  • {c}")
    if results["cisco_hits"]:
        print(f"\n{win_C.RED}{win_C.BOLD}🦠 CISCO DETECTIONS:{win_C.RST}")
        for c in results["cisco_hits"][:5]:
            print(f"  • [{c.get('severity','')}] {c.get('desc','')}")

    _fin = uni_cli_finish(out, "windows", args.base or args.evtx or args.memory or "", html_path, getattr(args, "vt_key", None), getattr(args, "abuse_key", None))
    print(f"\n{win_C.GRN}Report (PDF + DOCX + HTML):{win_C.RST} {Path(_fin).parent}\n  open: firefox {_fin}\n")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: LINUX FORENSICS MODULE (all top-level names prefixed lin_*)
# Smart auto-discovery — CentOS / RHEL / Ubuntu / Debian / Kali
# ══════════════════════════════════════════════════════════════════════════════


# ── Colors ────────────────────────────────────────────────────────────────────
class lin_C:
    RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"; CYN="\033[96m"
    BOLD="\033[1m"; RST="\033[0m";  BLU="\033[94m"; MAG="\033[95m"

def lin_log(lvl, msg):
    icons={"INFO":f"{lin_C.CYN}[*]","OK":f"{lin_C.GRN}[+]","WARN":f"{lin_C.YEL}[!]",
           "CRIT":f"{lin_C.RED}[!!!]","STEP":f"{lin_C.BLU}[→]","HEAD":f"{lin_C.MAG}[■]"}
    print(f"{icons.get(lvl,'[?]')} {msg}{lin_C.RST}")

def lin_banner():
    print(f"""{lin_C.CYN}{lin_C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║      Linux Forensics Master Analyzer v2.0                            ║
║      Smart Auto-Discovery — CentOS / RHEL / Ubuntu / Debian         ║
║  Auth│Syslog│Audit│Network│Users│SSH│Crontab│Process│Kernel│Memory  ║
╚══════════════════════════════════════════════════════════════════════╝
{lin_C.RST}""")

# ══════════════════════════════════════════════════════════════════════════════
# SMART EVIDENCE DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

# Map: what kind of file → what module handles it
# Kali-specific additional log paths
KALI_EXTRA_SIGNATURES = {
    "KALI_AUTH": {
        "names": ["auth.log","auth.log.*","auth.log-*"],
        "keywords": ["Failed password","session opened","sudo"],
    },
    "KALI_SYSLOG": {
        "names": ["syslog","syslog.*","kern.log","kern.log.*"],
        "keywords": ["kernel:","systemd","segfault"],
    },
    "KALI_DPKG": {
        "names": ["dpkg.log","dpkg.log.*","apt/history.log"],
        "keywords": ["install","remove","upgrade"],
    },
    "KALI_APACHE": {
        "names": ["apache2/access.log","apache2/error.log",
                  "apache2/other_vhosts_access.log"],
        "keywords": ["GET /","POST /","HTTP/"],
    },
    "KALI_MYSQL": {
        "names": ["mysql/error.log","mysql.log"],
        "keywords": ["MySQL","ERROR","Warning"],
    },
}

FILE_SIGNATURES = {
    # Auth logs
    "AUTH_LOG": {
        "names": ["secure","secure-*","auth.log","auth.log.*","auth.log-*"],
        "keywords": ["Failed password","Accepted publickey","session opened","sudo"],
    },
    # System/kernel logs
    "SYSLOG": {
        "names": ["messages","messages-*","syslog","syslog.*","kern.log","kern.log.*",
                  "boot.log","dmesg","dmesg.*","dmesg.txt"],
        "keywords": ["kernel:","systemd","segfault","OOM"],
    },
    # Cron logs
    "CRON_LOG": {
        "names": ["cron","cron-*","cron.log","anacron"],
        "keywords": ["CROND","crontab","CMD","anacron"],
    },
    # Audit logs
    "AUDIT_LOG": {
        "names": ["audit.log","audit.log.*","audit.log-*"],
        "keywords": ["type=SYSCALL","type=EXECVE","type=USER_AUTH","audit("],
    },
    # YUM/DNF package logs
    "PKG_LOG": {
        "names": ["yum.log","yum.log-*","dnf.log","dnf.log-*","yum.history*"],
        "keywords": ["Installed","Updated","Erased","install"],
    },
    # Firewall logs
    "FIREWALL_LOG": {
        "names": ["firewalld","firewalld-*","iptables.log"],
        "keywords": ["REJECT","DROP","ACCEPT","iptables"],
    },
    # Nginx/Apache access logs
    "WEB_LOG": {
        "names": ["access.log","access_log","error.log","error_log",
                  "nginx*.log","apache*.log","httpd*.log"],
        "keywords": ["GET /","POST /","HTTP/1","404","500"],
    },
    # /etc/passwd
    "PASSWD": {
        "names": ["passwd"],
        "keywords": ["root:","bin:","daemon:","nologin","bash"],
    },
    # /etc/shadow
    "SHADOW": {
        "names": ["shadow","gshadow"],
        "keywords": ["$6$","$5$","$1$","!!","*"],
    },
    # /etc/group
    "GROUP": {
        "names": ["group"],
        "keywords": ["root:","wheel:","sudo:"],
    },
    # /etc/sudoers
    "SUDOERS": {
        "names": ["sudoers","sudoers.*"],
        "keywords": ["ALL=(ALL)","NOPASSWD","Defaults"],
    },
    # bash_history
    "BASH_HISTORY": {
        "names": [".bash_history",".sh_history",".zsh_history","bash_history"],
        "keywords": ["wget","curl","ssh","nc ","chmod","sudo"],
    },
    # SSH config
    "SSHD_CONFIG": {
        "names": ["sshd_config"],
        "keywords": ["PermitRootLogin","PasswordAuthentication","Port "],
    },
    # authorized_keys
    "AUTH_KEYS": {
        "names": ["authorized_keys","authorized_keys2"],
        "keywords": ["ssh-rsa","ssh-ed25519","ecdsa-sha2","command="],
    },
    # known_hosts
    "KNOWN_HOSTS": {
        "names": ["known_hosts"],
        "keywords": ["ssh-rsa","ecdsa","ed25519"],
    },
    # crontab files
    "CRONTAB": {
        "names": ["crontab","crontab.*","root","www-data","apache","nginx"],
        "keywords": ["* * * * *","@reboot","@daily","@hourly","MAILTO"],
    },
    # /etc/crontab
    "ETC_CRONTAB": {
        "names": ["crontab"],
        "keywords": ["SHELL=","PATH=","* * * * *","@reboot"],
    },
    # Process list
    "PROCESS_LIST": {
        "names": ["ps.txt","ps_aux*","ps_axo*","ps_ef*","processes*","psaux*","running_processes*"],
        "keywords": ["PID","UID","CMD","COMMAND","root"],
    },
    # Network connections
    "NETSTAT": {
        "names": ["netstat*","ss*.txt","connections*","network_connections*"],
        "keywords": ["ESTABLISHED","LISTEN","tcp","udp"],
    },
    # IP/Interface config
    "IFCONFIG": {
        "names": ["ifconfig*","ip_addr*","ip_a.txt","ipaddr*","interfaces*"],
        "keywords": ["inet ","ether","UP","RUNNING","flags="],
    },
    # Route table
    "ROUTES": {
        "names": ["route*","ip_route*","routes.txt"],
        "keywords": ["default","via","dev","Destination","Gateway"],
    },
    # iptables rules
    "IPTABLES": {
        "names": ["iptables*","iptables-save*","ip6tables*","nftables*","firewall*"],
        "keywords": ["INPUT","OUTPUT","FORWARD","ACCEPT","DROP","REJECT"],
    },
    # resolv.conf
    "RESOLV": {
        "names": ["resolv.conf","resolv*"],
        "keywords": ["nameserver","search","domain"],
    },
    # /etc/hosts
    "HOSTS": {
        "names": ["hosts"],
        "keywords": ["127.0.0.1","localhost","::1"],
    },
    # SUID files list
    "SUID_FILES": {
        "names": ["suid*","sgid*","find_suid*","suid_files*","setuid*"],
        "keywords": ["/usr/bin","/bin","/usr/sbin","rwsr"],
    },
    # World writable
    "WORLD_WRITABLE": {
        "names": ["world_writable*","ww_files*","find_ww*","writable*"],
        "keywords": ["/tmp","/var","777","other"],
    },
    # Recently modified
    "RECENT_FILES": {
        "names": ["recent*","modified*","find_recent*","changed_files*","newer*"],
        "keywords": ["/etc","/bin","/usr","/var","/tmp","/home"],
    },
    # Hidden files
    "HIDDEN_FILES": {
        "names": ["hidden*","find_hidden*","dotfiles*"],
        "keywords": ["/.","/tmp","/."],
    },
    # lsof output
    "LSOF": {
        "names": ["lsof*","open_files*"],
        "keywords": ["COMMAND","PID","FD","TYPE","NAME"],
    },
    # Installed packages
    "PACKAGES": {
        "names": ["rpm*","dpkg*","packages*","installed*","rpm-qa*","rpm_qa*"],
        "keywords": ["rpm","dpkg",".x86_64",".noarch",".el7",".el8"],
    },
    # Kernel modules
    "LSMOD": {
        "names": ["lsmod*","modules*","kernel_modules*","loaded_modules*"],
        "keywords": ["Module","Size","Used by"],
    },
    # dmesg
    "DMESG": {
        "names": ["dmesg*"],
        "keywords": ["kernel:","[","USB","eth","tty","EXT4"],
    },
    # SELinux
    "SELINUX": {
        "names": ["sestatus*","selinux*"],
        "keywords": ["SELinux","enforcing","permissive","disabled"],
    },
    # systemd services
    "SYSTEMD": {
        "names": ["systemctl*","services*","units*","service_list*"],
        "keywords": ["active","inactive","enabled","disabled","running","dead"],
    },
    # Memory dumps
    "MEMORY_DUMP": {
        "names": ["*.lime","*.mem","*.raw","*.dmp","memory*","mem.*","dump.*"],
        "keywords": [],  # binary — no keyword check
        "min_size_mb": 10,  # must be >10MB
    },
    # /proc/net files
    "PROC_NET": {
        "names": ["proc_net*","proc_tcp*","proc_udp*"],
        "keywords": ["sl","local_address","rem_address"],
    },
    # Last/lastlog/wtmp
    "LAST_LOG": {
        "names": ["last*","lastlog*","wtmp*","btmp*","utmp*"],
        "keywords": ["pts","tty","reboot","shutdown"],
    },
    # /etc/rc.local / init scripts
    "INIT_SCRIPTS": {
        "names": ["rc.local","rc*","init.d*"],
        "keywords": ["#!/bin","exit 0","start","stop"],
    },
    # Root-level forensics files (hostname, uname, last, etc.)
    "HOST_INFO": {
        "names": ["hostname.txt","hostname","uname.txt","uptime.txt",
                  "os_release.txt","os-release.txt","issue.txt"],
        "keywords": ["Linux","kernel","hostname","Ubuntu","CentOS","Red Hat"],
    },
    "HASHES": {
        "names": ["*hashes*.csv","*hashes*.txt","forensics_hashes*","md5sum*","sha256sum*"],
        "keywords": ["MD5","SHA","hash","checksum"],
    },
    "FORENSICS_LOG": {
        "names": ["forensics_run.log","forensics*.log","collection*.log","run.log"],
        "keywords": ["Collecting","Starting","Done","Error"],
    },
    # Compressed log rotations (CentOS rotates with .gz)
    "AUTH_LOG_GZ": {
        "names": ["secure-*.gz","secure.*.gz","auth.log.*.gz","auth.log-*.gz"],
        "keywords": [],
    },
    "SYSLOG_GZ": {
        "names": ["messages-*.gz","messages.*.gz","syslog.*.gz","kern.log.*.gz"],
        "keywords": [],
    },
    "AUDIT_LOG_GZ": {
        "names": ["audit.log.*.gz","audit.log-*.gz"],
        "keywords": [],
    },
    "CRON_LOG_GZ": {
        "names": ["cron-*.gz","cron.*.gz"],
        "keywords": [],
    },
    # ZIP/7z/RAR archives (password protected)
    "ARCHIVE_ZIP": {
        "names": ["*.zip"],
        "keywords": [],
        "is_archive": True,
    },
    "ARCHIVE_7Z": {
        "names": ["*.7z"],
        "keywords": [],
        "is_archive": True,
    },
    "ARCHIVE_RAR": {
        "names": ["*.rar"],
        "keywords": [],
        "is_archive": True,
    },
}

def discover_evidence(base):
    base = Path(base)
    discovered = defaultdict(list)
    total_files = 0
    total_size  = 0

    lin_log("HEAD", f"Auto-discovering evidence in: {base}")
    lin_log("INFO", "Scanning all files recursively...")

    all_files = []
    try:
        for root, dirs, files in os.walk(base):
            # Skip these directories
            dirs[:] = [d for d in dirs if d not in [
                '__pycache__','.git','node_modules',
                'linux_forensics_output','pipeline_output',
            ]]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    fsize = fpath.stat().st_size
                    all_files.append((fpath, fsize))
                    total_size += fsize
                except:
                    pass
    except Exception as e:
        lin_log("WARN", f"Walk error: {e}")

    total_files = len(all_files)
    lin_log("INFO", f"  Found {total_files} files ({total_size//1024//1024} MB total)")

    # Categorize each file
    uncategorized = []
    for fpath, fsize in all_files:
        fname_lower = fpath.name.lower()
        fname_full  = str(fpath).lower()
        categorized = False

        for ftype, sig in FILE_SIGNATURES.items():
            # Memory dump — size-based detection
            if ftype == "MEMORY_DUMP":
                min_mb = sig.get("min_size_mb", 10)
                if fsize > min_mb * 1024 * 1024:
                    ext = fpath.suffix.lower()
                    if ext in ['.lime','.mem','.raw','.dmp'] or                        any(n.replace('*','') in fname_lower for n in sig["names"] if '*' not in n):
                        discovered[ftype].append(str(fpath))
                        categorized = True
                        break
                continue

            # Archive files — match by extension only (no keyword check needed)
            if sig.get("is_archive"):
                for pattern in sig["names"]:
                    ext = pattern.replace('*','')
                    if fname_lower.endswith(ext):
                        discovered[ftype].append(str(fpath))
                        categorized = True
                        break
                if categorized: break
                continue

            # Compressed log files (.gz, .bz2) — match by name pattern
            if ftype in ("AUTH_LOG_GZ","SYSLOG_GZ","AUDIT_LOG_GZ","CRON_LOG_GZ"):
                for pattern in sig["names"]:
                    prefix = pattern.split('*')[0].lower()
                    if fname_lower.startswith(prefix) and fname_lower.endswith('.gz'):
                        discovered[ftype].append(str(fpath))
                        categorized = True
                        break
                if categorized: break
                continue

            # Name-based matching
            name_match = False
            for pattern in sig["names"]:
                if '*' in pattern:
                    # Glob-style: check prefix + suffix
                    parts  = pattern.lower().split('*')
                    prefix = parts[0]
                    suffix = parts[-1] if len(parts) > 1 else ''
                    if fname_lower.startswith(prefix) and                        (not suffix or fname_lower.endswith(suffix)):
                        name_match = True
                        break
                else:
                    if fname_lower == pattern.lower():
                        name_match = True
                        break

            if name_match:
                keywords = sig.get("keywords", [])
                # No keywords = always accept
                if not keywords:
                    discovered[ftype].append(str(fpath))
                    categorized = True
                    break
                # With keywords = verify by reading sample
                elif fsize > 0 and fsize < 50 * 1024 * 1024:
                    try:
                        sample = fpath.read_bytes()[:4096].decode('utf-8', errors='ignore')
                        if any(kw in sample for kw in keywords):
                            discovered[ftype].append(str(fpath))
                            categorized = True
                            break
                        # Compressed — just accept on name match
                    except:
                        pass
                    if not categorized:
                        # Accept anyway if name matches well
                        discovered[ftype].append(str(fpath))
                        categorized = True
                        break

        if not categorized and fsize > 0:
            uncategorized.append(str(fpath))

    # Uncategorized files — add to EXTRA bucket for reporting
    if uncategorized:
        discovered["UNCATEGORIZED"] = uncategorized

    # Print discovery summary
    print(f"\n{lin_C.BOLD}{'─'*55}{lin_C.RST}")
    print(f"{lin_C.BOLD}  EVIDENCE DISCOVERY RESULTS{lin_C.RST}")
    print(f"{'─'*55}")
    found_types = {k: v for k, v in discovered.items() if v}
    for ftype, files in sorted(found_types.items()):
        total_sz = sum(Path(f).stat().st_size for f in files if Path(f).exists())
        print(f"  {lin_C.GRN}✓{lin_C.RST} {ftype:<25} {len(files):>3} file(s)  "
              f"({total_sz//1024:,} KB)")

    missing = [k for k in FILE_SIGNATURES if k not in found_types]
    if missing:
        print(f"\n  {lin_C.YEL}Not found:{lin_C.RST} {', '.join(missing[:8])}")
        if len(missing) > 8:
            print(f"             ... and {len(missing)-8} more")
    print(f"{'─'*55}\n")

    return discovered

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def lin_is_private(ip):
    try:
        o = ipaddress.ip_address(ip.strip())
        return o.is_private or o.is_loopback or o.is_link_local
    except: return True

def lin_extract_ips(text):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

ARCHIVE_PASSWORDS = [pw for pw in adp_PASSWORDS if pw] + [x for x in os.environ.get("ADP_ARCHIVE_PASSWORDS", "").split(",") if x]


def _arc_extract(kind, path, tmp, timeout=60):
    """Extract a 7z/rar archive: no password first, then common malware-sample passwords. Never prompts."""
    for pw in [None] + ARCHIVE_PASSWORDS:
        if kind == "7z": cmd = ["7z", "x", f"-o{tmp}", str(path), "-y"] + ([f"-p{pw}"] if pw else [])
        else: cmd = ["unrar", "x", "-y"] + ([f"-p{pw}"] if pw else ["-p-"]) + [str(path), tmp]
        try: r = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        except Exception: return False
        if r.returncode == 0: return True
    return False


def _sudo_read(path):
    """Read a root-protected file via passwordless / already-cached sudo. Never prompts and no password is stored in this tool."""
    try:
        r = subprocess.run(['sudo', '-n', 'cat', str(path)], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        if r.returncode == 0: return r.stdout
    except Exception:
        pass
    return None

def read_file(path, max_bytes=10*1024*1024):
    """Smart reader: plain text, .gz, .bz2, .xz, .zip, .7z, .rar, .tar.gz
       Also handles root-protected files using sudo"""
    path = str(path)
    ext  = path.lower()
    try:
        # First try normal read
        # If permission denied → try sudo
        try:
            open(path, 'rb').close()
        except PermissionError:
            lin_log("INFO", f"  Permission denied - trying passwordless sudo: {Path(path).name}")
            sudo_content = _sudo_read(path)
            if sudo_content:
                return sudo_content[:max_bytes]
            else:
                lin_log("WARN", f"  Could not read (permission denied, no passwordless sudo): {Path(path).name}"); UNI_CTX.setdefault("denied", []).append(str(path))
                return ""
        # GZIP
        if ext.endswith('.gz') and not ext.endswith('.tar.gz'):
            import gzip
            with gzip.open(path, 'rb') as f:
                return f.read(max_bytes).decode('utf-8', errors='ignore')
        # BZIP2
        elif ext.endswith('.bz2') and not ext.endswith('.tar.bz2'):
            import bz2
            with bz2.open(path, 'rb') as f:
                return f.read(max_bytes).decode('utf-8', errors='ignore')
        # XZ
        elif ext.endswith('.xz'):
            import lzma
            with lzma.open(path, 'rb') as f:
                return f.read(max_bytes).decode('utf-8', errors='ignore')
        # TAR.GZ / TGZ / TAR.BZ2
        elif any(ext.endswith(e) for e in ['.tar.gz','.tgz','.tar.bz2','.tar.xz','.tar']):
            import tarfile
            result = []
            with tarfile.open(path, 'r:*') as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.size < max_bytes:
                        try:
                            f = tar.extractfile(member)
                            if f:
                                result.append(f.read().decode('utf-8', errors='ignore'))
                        except: pass
            return "\n".join(result)
        # ZIP (try password first, then without)
        elif ext.endswith('.zip'):
            import zipfile
            result = []
            with zipfile.ZipFile(path, 'r') as zf:
                for name in zf.namelist():
                    for pwd in [pw.encode() for pw in ARCHIVE_PASSWORDS] + [None]:
                        try:
                            data = zf.read(name, pwd=pwd) if pwd else zf.read(name)
                            result.append(data.decode('utf-8', errors='ignore'))
                            break
                        except: pass
            return "\n".join(result)
        # 7Z (password protected)
        elif ext.endswith('.7z'):
            import subprocess, tempfile, shutil
            if shutil.which('7z'):
                tmp = tempfile.mkdtemp()
                try:
                    _arc_extract("7z", path, tmp, 60)
                    result = []
                    for root, _, files in os.walk(tmp):
                        for fname in files:
                            try:
                                with open(os.path.join(root,fname),'rb') as f:
                                    result.append(f.read(max_bytes).decode('utf-8',errors='ignore'))
                            except: pass
                    return "\n".join(result)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
        # RAR (password protected)
        elif ext.endswith('.rar'):
            import subprocess, tempfile, shutil
            if shutil.which('unrar'):
                tmp = tempfile.mkdtemp()
                try:
                    _arc_extract("rar", path, tmp, 60)
                    result = []
                    for root, _, files in os.walk(tmp):
                        for fname in files:
                            try:
                                with open(os.path.join(root,fname),'rb') as f:
                                    result.append(f.read(max_bytes).decode('utf-8',errors='ignore'))
                            except: pass
                    return "\n".join(result)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
        # Plain text / binary (default)
        else:
            with open(path, 'rb') as f:
                return f.read(max_bytes).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def lin_new_results():
    return {
        "critical":[], "high":[], "medium":[],
        "external_ips":set(), "suspicious_processes":[],
        "crontab_hits":[], "ssh_hits":[], "kernel_hits":[],
        "timeline":[], "threat_intel":[],
        "discovery":{},
    }

def lin_add(results, sev, src, desc, data=None, file=""):
    e = {"severity":sev,"source":src,"desc":desc,
         "data":data or {},"file":str(file),
         "timestamp":datetime.now().isoformat()}
    if   sev=="CRITICAL": results["critical"].append(e)
    elif sev=="HIGH":     results["high"].append(e)
    else:                 results["medium"].append(e)

def add_tl(results, ts, sev, src, desc, detail=""):
    results["timeline"].append({
        "ts":ts,"sev":sev,"src":src,
        "desc":desc,"detail":str(detail)[:300]
    })

# ── IOC Lists ─────────────────────────────────────────────────────────────────
SUSP_CMDS = [
    (re.compile(r'nc\s+.*-[el]|ncat\s+.*-[el]|netcat',re.I),            "Netcat reverse shell"),
    (re.compile(r'bash\s+-i\s+>&|/dev/tcp/\d',re.I),                    "Bash reverse shell"),
    (re.compile(r'python.*-c.*socket|perl.*socket',re.I),               "Script reverse shell"),
    (re.compile(r'wget\s+\S+\s*\|\s*ba?sh|curl\s+\S+\s*\|\s*ba?sh',re.I),"curl/wget|bash RCE"),
    (re.compile(r'chmod\s+[+]?[47]?777|chmod\s+a\+[srwx]+',re.I),      "Dangerous chmod"),
    (re.compile(r'base64\s+-d|base64\s+--decode',re.I),                 "Base64 decode"),
    (re.compile(r'eval\s*\$\(|eval\s*`',re.I),                          "Eval execution"),
    (re.compile(r'dd\s+if=.*of=/dev/|shred\s+-',re.I),                  "Disk wipe"),
    (re.compile(r'iptables\s+-F|iptables\s+--flush',re.I),              "Firewall flush"),
    (re.compile(r'useradd|adduser|usermod.*sudo|usermod.*wheel',re.I),   "User manipulation"),
    (re.compile(r'visudo|echo.*sudoers|tee.*sudoers',re.I),              "Sudoers edit"),
    (re.compile(r'crontab\s+-[ei]|echo.*crontab|>\s*/etc/cron',re.I),   "Crontab edit"),
    (re.compile(r'nmap|masscan|zmap|arp-scan',re.I),                     "Network scan"),
    (re.compile(r'hydra|medusa|john|hashcat',re.I),                      "Password crack"),
    (re.compile(r'tcpdump|tshark|wireshark',re.I),                       "Packet capture"),
    (re.compile(r'history\s+-c|>\s*~/\.bash_history|unset\s+HIST',re.I),"History clear"),
    (re.compile(r'pkill.*log|kill.*rsyslog|systemctl.*stop.*log',re.I), "Log kill"),
    (re.compile(r'rm\s+-rf\s+/var/log|>\s+/var/log',re.I),              "Log delete"),
    (re.compile(r'insmod|modprobe\s+(?!--)',re.I),                       "Kernel module load"),
    (re.compile(r'socat|cryptcat',re.I),                                  "Tunnel tool"),
    (re.compile(r'linpeas|linenum|linux-exploit',re.I),                  "PrivEsc tool"),
    (re.compile(r'mimipenguin|pypykatz',re.I),                           "Credential dump"),
    (re.compile(r'passwd\s+root|echo.*:.*passwd',re.I),                  "Root password change"),
    (re.compile(r'ssh.*-o.*StrictHost.*no.*-i\s+/tmp',re.I),            "Suspicious SSH"),
    (re.compile(r'mount\s+.*--bind|mount\s+.*tmpfs',re.I),              "Suspicious mount"),
]

SUSP_PROCS = [
    'nc','ncat','netcat','socat','cryptcat',
    'nmap','masscan','zmap','arp-scan',
    'hydra','medusa','john','hashcat',
    'mimipenguin','pypykatz',
    'linpeas','linenum',
    'msfconsole','meterpreter',
    'tcpdump','tshark',
]

lin_SUSP_PORTS = {4444,31337,1234,8888,9999,6666,5555,9001,9050,1337}
SUSP_DIRS  = ['/tmp','/var/tmp','/dev/shm','/run/shm']

WHITELIST_IPS = {
    '8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1',
    '127.0.0.1','0.0.0.0','255.255.255.255',
}

ROOTKIT_MODS = [
    'diamorphine','reptile','azazel','beurk','suterusu',
    'adore','knark','rexob','enyelkm','modhide','kbeast',
]

# ══════════════════════════════════════════════════════════════════════════════
# ANALYZERS — each takes list of file paths
# ══════════════════════════════════════════════════════════════════════════════

def analyze_auth_logs(files, results):
    if not files: return
    lin_log("STEP", f"Auth logs ({len(files)} files)...")
    failed = defaultdict(int)

    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            ts_m = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            ts   = ts_m.group(1) if ts_m else ""
            ll   = line.lower()

            # Failed login
            if 'failed password' in ll or 'authentication failure' in ll:
                ip_m = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_m:
                    ip = ip_m.group(1)
                    failed[ip] += 1
                    if not lin_is_private(ip): results["external_ips"].add(ip)

            # Successful login
            elif 'accepted password' in ll or 'accepted publickey' in ll:
                ip_m   = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                usr_m  = re.search(r'for\s+(?:invalid user\s+)?(\S+)', line)
                ip     = ip_m.group(1)  if ip_m  else "?"
                user   = usr_m.group(1) if usr_m else "?"
                add_tl(results, ts, "HIGH", "AUTH", f"Login: {user} from {ip}", line[:150])
                if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                    results["external_ips"].add(ip)
                    lin_add(results,"HIGH","AUTH_EXT_LOGIN",
                        f"External IP login: {user}@{ip}",{"user":user,"ip":ip,"ts":ts},fpath)

            # Root login
            if 'root' in ll and ('accepted' in ll or 'session opened' in ll):
                lin_add(results,"CRITICAL","AUTH_ROOT",
                    f"Root login: {line.strip()[:120]}",{"ts":ts},fpath)
                add_tl(results, ts, "CRITICAL", "AUTH_ROOT", "Root login", line[:120])

            # New user
            if 'new user' in ll or 'useradd' in ll:
                lin_add(results,"HIGH","AUTH_NEW_USER",
                    f"New user created: {line.strip()[:120]}",{"ts":ts},fpath)
                add_tl(results, ts, "HIGH", "AUTH", "New user created", line[:120])

            # Sudo
            if 'sudo' in ll and 'command' in ll:
                for pat, pname in SUSP_CMDS:
                    if pat.search(line):
                        lin_add(results,"CRITICAL","SUDO_MALICIOUS",
                            f"Malicious sudo: {pname}",{"ts":ts,"line":line[:300]},fpath)
                        add_tl(results,ts,"CRITICAL","SUDO",pname,line[:200])
                        break

    # Brute force
    for ip, cnt in failed.items():
        if cnt >= 10:
            sev = "CRITICAL" if cnt >= 50 else "HIGH"
            lin_add(results,sev,"BRUTE_FORCE",
                f"Brute force {ip}: {cnt} failed attempts",{"ip":ip,"count":cnt},"auth")
    lin_log("OK", f"  Auth: {sum(failed.values())} failed attempts, {len(failed)} source IPs")

def analyze_syslogs(files, results):
    if not files: return
    lin_log("STEP", f"System logs ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            ts_m = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            ts   = ts_m.group(1) if ts_m else ""
            ll   = line.lower()
            if 'segfault' in ll:
                lin_add(results,"MEDIUM","KERNEL_SEGFAULT",f"Segfault: {line[:120]}",{"ts":ts},fpath)
            if 'module loaded' in ll or 'insmod' in ll:
                lin_add(results,"HIGH","KERNEL_MODULE",f"Module loaded: {line[:120]}",{"ts":ts},fpath)
                add_tl(results,ts,"HIGH","KERNEL","Module loaded",line[:120])
            if 'usb' in ll and ('new' in ll or 'connect' in ll):
                lin_add(results,"MEDIUM","USB",f"USB device: {line[:120]}",{"ts":ts},fpath)
            for rk in ROOTKIT_MODS:
                if rk in ll:
                    lin_add(results,"CRITICAL","ROOTKIT_SYSLOG",
                        f"Rootkit in syslog: {rk}",{"ts":ts},fpath)
            for pat, pname in SUSP_CMDS:
                if pat.search(line):
                    lin_add(results,"HIGH","SYSLOG_MALICIOUS",
                        f"Malicious: {pname}",{"ts":ts,"line":line[:200]},fpath)
                    add_tl(results,ts,"HIGH","SYSLOG",pname,line[:150])
                    break

def analyze_cron_logs(files, results):
    if not files: return
    lin_log("STEP", f"Cron logs ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            ts_m = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
            ts   = ts_m.group(1) if ts_m else ""
            for pat, pname in SUSP_CMDS:
                if pat.search(line):
                    lin_add(results,"CRITICAL","CRON_LOG_MALICIOUS",
                        f"Malicious cron execution: {pname}",
                        {"ts":ts,"line":line[:300]},fpath)
                    add_tl(results,ts,"CRITICAL","CRON_LOG",pname,line[:200])
                    break
            # Unusual cron times (every minute)
            if re.search(r'CROND.*CMD',line) and re.search(r':00:\d\d',line):
                pass  # normal

def analyze_audit_logs(files, results):
    if not files: return
    lin_log("STEP", f"Audit logs ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            ts_m = re.search(r'msg=audit\((\d+\.\d+)', line)
            ts   = ""
            if ts_m:
                try: ts = datetime.fromtimestamp(float(ts_m.group(1))).strftime('%Y-%m-%d %H:%M:%S')
                except: pass

            atype_m = re.search(r'type=(\w+)', line)
            atype   = atype_m.group(1) if atype_m else ""

            if atype == "EXECVE":
                parts = re.findall(r'a\d+="([^"]*)"', line)
                cmd   = " ".join(parts)
                if cmd:
                    for pat, pname in SUSP_CMDS:
                        if pat.search(cmd):
                            lin_add(results,"CRITICAL","AUDIT_EXEC",
                                f"Malicious command: {pname}",
                                {"ts":ts,"cmd":cmd[:300]},fpath)
                            add_tl(results,ts,"CRITICAL","AUDIT",pname,cmd[:200])
                            break

            if atype in ("ADD_USER","DEL_USER","ADD_GROUP","CHUSER_ID"):
                lin_add(results,"HIGH","AUDIT_USER",
                    f"User/group change: {atype}",{"ts":ts},fpath)
                add_tl(results,ts,"HIGH","AUDIT",f"User change: {atype}")

            if atype == "PATH":
                p_m = re.search(r'name="([^"]*)"', line)
                if p_m:
                    p = p_m.group(1)
                    if any(sf in p for sf in ['/etc/passwd','/etc/shadow','/etc/sudoers',
                                               '/root/.ssh','/etc/cron']):
                        lin_add(results,"HIGH","AUDIT_SENSITIVE",
                            f"Sensitive file accessed: {p}",{"ts":ts,"path":p},fpath)

def analyze_web_logs(files, results):
    if not files: return
    lin_log("STEP", f"Web logs ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            # Web shell indicators
            if re.search(r'(cmd|exec|shell|passthru|system)\s*=', line, re.I):
                lin_add(results,"CRITICAL","WEB_SHELL",
                    f"Web shell parameter: {line[:200]}",{"line":line[:200]},fpath)
            # SQL injection
            if re.search(r'(union\s+select|1=1|or\s+1=1|drop\s+table)', line, re.I):
                lin_add(results,"HIGH","SQLI",
                    f"SQL injection attempt: {line[:200]}",{"line":line[:200]},fpath)
            # Directory traversal
            if re.search(r'\.\.\/|\.\.\\|%2e%2e', line, re.I):
                lin_add(results,"HIGH","DIR_TRAVERSAL",
                    f"Directory traversal: {line[:200]}",{"line":line[:200]},fpath)
            # Scanner signatures
            if re.search(r'nikto|sqlmap|nmap|masscan|zgrab|nuclei', line, re.I):
                lin_add(results,"HIGH","WEB_SCANNER",
                    f"Scanner detected: {line[:200]}",{"line":line[:200]},fpath)

def analyze_pkg_logs(files, results):
    if not files: return
    lin_log("STEP", f"Package logs ({len(files)} files)...")
    hacking_tools = [
        'nmap','masscan','nikto','sqlmap','hydra','medusa',
        'john','hashcat','aircrack','metasploit','netcat',
        'ncat','socat','proxychains','tcpdump','wireshark',
        'hping','scapy','dsniff','ettercap','arpspoof',
    ]
    for fpath in files:
        content = read_file(fpath)
        for tool in hacking_tools:
            if re.search(rf'\b{tool}\b', content, re.I):
                # Find context
                for line in content.splitlines():
                    if re.search(rf'\b{tool}\b', line, re.I) and \
                       ('install' in line.lower() or 'install' in line.lower()):
                        lin_add(results,"HIGH","HACKING_TOOL",
                            f"Hacking tool installed: {tool}",
                            {"tool":tool,"line":line[:200]},fpath)
                        break

def analyze_passwd(files, results):
    if not files: return
    lin_log("STEP", f"passwd/shadow/group ({len(files)} files)...")
    for fpath in files:
        content  = read_file(fpath)
        fname    = Path(fpath).name

        if fname == "passwd":
            for line in content.splitlines():
                if not line.strip() or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts) < 7: continue
                user,_,uid,_,_,home,shell = parts[:7]
                uid = int(uid) if uid.isdigit() else -1
                if uid == 0 and user != 'root':
                    lin_add(results,"CRITICAL","UID0",
                        f"Non-root UID 0: {user}",{"user":user},fpath)
                if uid > 0 and uid < 1000 and \
                   shell not in ['/bin/false','/usr/sbin/nologin','/sbin/nologin','']:
                    if user not in ['nobody','daemon','bin','sys']:
                        lin_add(results,"HIGH","SYS_USER_SHELL",
                            f"System account with shell: {user} ({shell})",
                            {"user":user,"shell":shell},fpath)
                if home and any(sd in home for sd in SUSP_DIRS):
                    lin_add(results,"CRITICAL","SUSP_HOME",
                        f"User home in temp dir: {user} → {home}",
                        {"user":user,"home":home},fpath)

        elif fname == "shadow":
            for line in content.splitlines():
                if not line.strip() or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts) < 2: continue
                user,h = parts[0],parts[1]
                if h == '':
                    lin_add(results,"CRITICAL","EMPTY_PASS",
                        f"Empty password: {user}",{"user":user},fpath)

        elif fname in ["sudoers","sudoers.d"]:
            for line in content.splitlines():
                if line.startswith('#') or not line.strip(): continue
                if 'NOPASSWD' in line and 'ALL' in line:
                    lin_add(results,"CRITICAL","SUDOERS_NOPASSWD",
                        f"NOPASSWD ALL: {line.strip()}",{"line":line.strip()},fpath)

        elif fname == "group":
            for line in content.splitlines():
                if not line.strip() or line.startswith('#'): continue
                parts = line.split(':')
                if len(parts) < 4: continue
                grp,_,gid,members = parts[0],parts[1],parts[2],parts[3]
                if grp in ['wheel','sudo','root'] and members.strip():
                    lin_add(results,"HIGH","PRIV_GROUP",
                        f"Members in privileged group {grp}: {members}",
                        {"group":grp,"members":members},fpath)

def analyze_bash_history(files, results):
    if not files: return
    lin_log("STEP", f"Bash history ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath, max_bytes=2*1024*1024)
        for i, line in enumerate(content.splitlines()):
            for pat, pname in SUSP_CMDS:
                if pat.search(line):
                    lin_add(results,"CRITICAL","BASH_HIST",
                        f"Malicious cmd in history: {pname}",
                        {"cmd":line.strip()[:300],"file":str(fpath)},fpath)
                    add_tl(results,"","CRITICAL","BASH_HIST",pname,line.strip()[:200])
                    break

def analyze_ssh_files(files, results):
    if not files: return
    lin_log("STEP", f"SSH files ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        fname   = Path(fpath).name.lower()

        if fname == "sshd_config":
            checks = {
                r'PermitRootLogin\s+yes':       ("CRITICAL","Root SSH login allowed"),
                r'PermitEmptyPasswords\s+yes':  ("CRITICAL","Empty passwords via SSH"),
                r'PasswordAuthentication\s+yes':("HIGH",    "Password auth enabled"),
                r'Protocol\s+1':               ("HIGH",    "SSH Protocol 1 (insecure)"),
                r'GatewayPorts\s+yes':          ("HIGH",    "Gateway ports enabled"),
                r'X11Forwarding\s+yes':         ("MEDIUM",  "X11 forwarding on"),
            }
            for pattern,(sev,desc) in checks.items():
                if re.search(pattern,content,re.I):
                    lin_add(results,sev,"SSHD_CONFIG",desc,{"pattern":pattern},fpath)

        elif fname in ["authorized_keys","authorized_keys2"]:
            lines = [l for l in content.splitlines() if l.strip() and not l.startswith('#')]
            if lines:
                lin_add(results,"HIGH","AUTH_KEYS",
                    f"{len(lines)} SSH authorized key(s) found",
                    {"count":len(lines),"keys":[l[:80] for l in lines[:3]]},fpath)
                results["ssh_hits"].append({"file":str(fpath),"keys":len(lines),
                                            "sample":[l[:80] for l in lines[:3]]})
            for line in lines:
                if line.startswith('command='):
                    lin_add(results,"CRITICAL","SSH_CMD_KEY",
                        f"SSH key with forced command (backdoor?): {line[:150]}",
                        {"key":line[:200]},fpath)

        elif fname == "known_hosts":
            for line in content.splitlines():
                for ip in lin_extract_ips(line):
                    if not lin_is_private(ip): results["external_ips"].add(ip)

def analyze_crontabs(files, results):
    if not files: return
    lin_log("STEP", f"Crontab files ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            if line.startswith('#') or not line.strip(): continue
            for pat, pname in SUSP_CMDS:
                if pat.search(line):
                    lin_add(results,"CRITICAL","CRONTAB_MALICIOUS",
                        f"Malicious crontab entry: {pname}",
                        {"line":line.strip()[:300],"file":str(fpath)},fpath)
                    results["crontab_hits"].append({"file":str(fpath),
                                                    "line":line.strip(),"pattern":pname})
                    add_tl(results,"","CRITICAL","CRONTAB",pname,line.strip()[:200])
                    break
            if re.search(r'wget|curl',line,re.I) and re.search(r'http',line,re.I):
                lin_add(results,"CRITICAL","CRONTAB_DOWNLOAD",
                    f"Crontab downloads from internet: {line.strip()[:200]}",
                    {"line":line.strip()},fpath)
            if any(sd in line for sd in SUSP_DIRS):
                lin_add(results,"HIGH","CRONTAB_TEMP",
                    f"Crontab runs from temp dir: {line.strip()[:200]}",
                    {"line":line.strip()},fpath)

def analyze_network_files(files_by_type, results):
    lin_log("STEP", "Network data...")
    all_net_files = (files_by_type.get("NETSTAT",[]) +
                     files_by_type.get("IFCONFIG",[]) +
                     files_by_type.get("ROUTES",[]) +
                     files_by_type.get("PROC_NET",[]) +
                     files_by_type.get("LSOF",[]))

    for fpath in all_net_files:
        content = read_file(fpath)
        for ip in lin_extract_ips(content):
            if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                results["external_ips"].add(ip)
        ports = re.findall(r':(\d{4,5})\b', content)
        for p in ports:
            try:
                if int(p) in lin_SUSP_PORTS:
                    ctx = next((l for l in content.splitlines() if f':{p}' in l),"")
                    lin_add(results,"CRITICAL","NET_SUSP_PORT",
                        f"Suspicious port {p} in network data",
                        {"port":p,"context":ctx[:200]},fpath)
            except: pass
        if 'ESTABLISHED' in content:
            for line in content.splitlines():
                if 'ESTABLISHED' in line:
                    ips = [i for i in lin_extract_ips(line)
                           if not lin_is_private(i) and i not in WHITELIST_IPS]
                    for ip in ips:
                        lin_add(results,"HIGH","NET_EXTERNAL",
                            f"External ESTABLISHED connection: {ip}",
                            {"ip":ip,"line":line[:200]},fpath)

    # iptables
    for fpath in files_by_type.get("IPTABLES",[]):
        content = read_file(fpath)
        if content.count("ACCEPT") > 10 and "DROP" not in content and "REJECT" not in content:
            lin_add(results,"HIGH","FIREWALL_OPEN",
                "Firewall appears fully open (all ACCEPT, no DROP/REJECT)",
                {"file":str(fpath)},fpath)

    # resolv.conf
    for fpath in files_by_type.get("RESOLV",[]):
        content = read_file(fpath)
        for line in content.splitlines():
            if line.startswith('nameserver'):
                ns_m = re.search(r'nameserver\s+(\S+)', line)
                if ns_m:
                    ns = ns_m.group(1)
                    if not lin_is_private(ns) and ns not in {'8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1'}:
                        lin_add(results,"HIGH","SUSP_DNS",
                            f"Suspicious nameserver: {ns}",{"ns":ns},fpath)

    # /etc/hosts
    for fpath in files_by_type.get("HOSTS",[]):
        content = read_file(fpath)
        for line in content.splitlines():
            if line.startswith('#') or not line.strip(): continue
            if re.search(r'(google|microsoft|antivirus|update)\.com', line, re.I):
                lin_add(results,"CRITICAL","HOSTS_HIJACK",
                    f"Hosts file hijack: {line.strip()}",{"line":line.strip()},fpath)

def analyze_processes(files, results):
    if not files: return
    lin_log("STEP", f"Process lists ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            for sp in SUSP_PROCS:
                if re.search(rf'\b{re.escape(sp)}\b', line, re.I):
                    lin_add(results,"CRITICAL","PROC_SUSP",
                        f"Suspicious process: {sp}",
                        {"process":sp,"line":line.strip()[:200]},fpath)
                    results["suspicious_processes"].append({"name":sp,"line":line.strip()[:150]})
                    break
            if any(sd in line for sd in SUSP_DIRS) and re.search(r'\d+\s+\w+', line):
                lin_add(results,"HIGH","PROC_TEMP",
                    f"Process from temp dir: {line.strip()[:150]}",
                    {"line":line.strip()[:150]},fpath)
            if '(deleted)' in line.lower():
                lin_add(results,"HIGH","PROC_DELETED",
                    f"Process running deleted exe: {line.strip()[:150]}",
                    {"line":line.strip()[:150]},fpath)
            for pat, pname in SUSP_CMDS[:10]:
                if pat.search(line):
                    lin_add(results,"CRITICAL","PROC_MALICIOUS_CMD",
                        f"Malicious process cmdline: {pname}",
                        {"pattern":pname,"line":line.strip()[:200]},fpath)
                    break

def analyze_filesystem_artifacts(files_by_type, results):
    lin_log("STEP", "Filesystem artifacts...")

    for fpath in files_by_type.get("SUID_FILES",[]):
        content = read_file(fpath)
        standard = {'/usr/bin/sudo','/usr/bin/passwd','/usr/bin/su',
                    '/usr/bin/newgrp','/usr/bin/gpasswd','/bin/ping',
                    '/usr/bin/chfn','/usr/bin/chsh','/usr/bin/pkexec'}
        for line in content.splitlines():
            line = line.strip()
            if line and not any(s == line for s in standard):
                lin_add(results,"HIGH","SUID_UNUSUAL",
                    f"Unusual SUID binary: {line}",{"path":line},fpath)

    for fpath in files_by_type.get("WORLD_WRITABLE",[]):
        content = read_file(fpath)
        for line in content.splitlines():
            line = line.strip()
            if line and not any(ok in line for ok in ['/tmp','/var/tmp','/dev/shm','/proc']):
                lin_add(results,"HIGH","WORLD_WRITABLE",
                    f"World-writable outside tmp: {line}",{"path":line},fpath)

    for fpath in files_by_type.get("RECENT_FILES",[]):
        content = read_file(fpath)
        for line in content.splitlines():
            line = line.strip()
            if not line: continue
            if any(sd in line for sd in SUSP_DIRS):
                lin_add(results,"HIGH","RECENT_TEMP",
                    f"Recent file in temp: {line}",{"path":line},fpath)
            if re.search(r'\.(sh|py|pl|rb|php|elf)\s*$', line) and \
               any(sd in line for sd in ['/etc','/bin','/usr/bin']):
                lin_add(results,"HIGH","RECENT_SYSTEM_SCRIPT",
                    f"Script modified in system dir: {line}",{"path":line},fpath)

    for fpath in files_by_type.get("PACKAGES",[]):
        content = read_file(fpath)
        hacking = ['nmap','masscan','nikto','sqlmap','hydra','medusa',
                   'john','hashcat','aircrack','netcat','ncat','socat',
                   'proxychains','tcpdump','wireshark','hping','scapy']
        for tool in hacking:
            if re.search(rf'\b{tool}\b', content, re.I):
                lin_add(results,"HIGH","HACKING_TOOL",
                    f"Hacking tool in packages: {tool}",{"tool":tool},fpath)

def analyze_kernel_modules(files_by_type, results):
    lin_log("STEP", "Kernel modules/dmesg...")

    for fpath in files_by_type.get("LSMOD",[]) + files_by_type.get("DMESG",[]):
        content = read_file(fpath)
        for mod in ROOTKIT_MODS:
            if re.search(rf'\b{mod}\b', content, re.I):
                lin_add(results,"CRITICAL","ROOTKIT_MODULE",
                    f"Rootkit kernel module: {mod}",{"module":mod},fpath)
                results["kernel_hits"].append({"module":mod,"type":"ROOTKIT"})
        if re.search(r'kernel panic|BUG:|general protection fault', content, re.I):
            lin_add(results,"HIGH","KERNEL_CRASH",
                "Kernel crash/panic — possible exploitation",{"file":str(fpath)},fpath)

    for fpath in files_by_type.get("SELINUX",[]):
        content = read_file(fpath)
        if re.search(r'SELINUX\s*=\s*(disabled|permissive)', content, re.I):
            m = re.search(r'SELINUX\s*=\s*(\w+)', content, re.I)
            mode = m.group(1) if m else "disabled"
            lin_add(results,"HIGH","SELINUX_DISABLED",
                f"SELinux is {mode}",{"mode":mode},fpath)

def analyze_systemd(files, results):
    if not files: return
    lin_log("STEP", f"Systemd/services ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        # Unusual ExecStart paths
        exec_m = re.findall(r'ExecStart=(.+)', content)
        for ep in exec_m:
            if any(sd in ep for sd in SUSP_DIRS):
                lin_add(results,"CRITICAL","SYSTEMD_TEMP",
                    f"Systemd ExecStart from temp: {ep}",{"exec":ep},fpath)
            for pat, pname in SUSP_CMDS:
                if pat.search(ep):
                    lin_add(results,"CRITICAL","SYSTEMD_MALICIOUS",
                        f"Malicious systemd service: {pname}",
                        {"exec":ep,"pattern":pname},fpath)
                    break

def analyze_last_log(files, results):
    if not files: return
    lin_log("STEP", f"Last/login logs ({len(files)} files)...")
    for fpath in files:
        try:
            content = read_file(fpath)
            for line in content.splitlines():
                for ip in lin_extract_ips(line):
                    if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                        results["external_ips"].add(ip)
                        add_tl(results,"","HIGH","LAST_LOG",
                               f"Login from external IP: {ip}",line[:150])
        except: pass

def analyze_archives(files, results):
    """Extract and analyze password-protected ZIP/7z/RAR archives"""
    if not files: return
    lin_log("STEP", f"Archives ({len(files)} files) - trying no password, then common sample passwords")
    import tempfile, shutil, zipfile, subprocess

    for fpath in files:
        fname = Path(fpath).name.lower()
        extracted_content = []

        try:
            if fname.endswith('.zip'):
                with zipfile.ZipFile(fpath, 'r') as zf:
                    for name in zf.namelist():
                        for pwd in [pw.encode() for pw in ARCHIVE_PASSWORDS] + [None]:
                            try:
                                data = zf.read(name, pwd=pwd) if pwd else zf.read(name)
                                text = data.decode('utf-8', errors='ignore')
                                extracted_content.append((name, text))
                                break
                            except: pass

            elif fname.endswith('.7z'):
                tmp = tempfile.mkdtemp()
                try:
                    _arc_extract("7z", fpath, tmp, 120)
                    for root, _, fs in os.walk(tmp):
                        for fn in fs:
                            fp2 = os.path.join(root, fn)
                            try:
                                with open(fp2, 'rb') as f2:
                                    text = f2.read(5*1024*1024).decode('utf-8', errors='ignore')
                                    extracted_content.append((fn, text))
                            except: pass
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)

            elif fname.endswith('.rar'):
                tmp = tempfile.mkdtemp()
                try:
                    _arc_extract("rar", fpath, tmp, 120)
                    for root, _, fs in os.walk(tmp):
                        for fn in fs:
                            fp2 = os.path.join(root, fn)
                            try:
                                with open(fp2, 'rb') as f2:
                                    text = f2.read(5*1024*1024).decode('utf-8', errors='ignore')
                                    extracted_content.append((fn, text))
                            except: pass
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)

        except Exception as e:
            lin_log("WARN", f"  Archive error {Path(fpath).name}: {e}")
            continue

        lin_log("OK", f"  {Path(fpath).name}: {len(extracted_content)} files extracted")

        # Analyze each extracted file
        for inner_name, text in extracted_content:
            inner_lower = inner_name.lower()
            # Run all pattern checks
            for line in text.splitlines():
                ts_m = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                ts   = ts_m.group(1) if ts_m else ""
                for pat, pname in SUSP_CMDS:
                    if pat.search(line):
                        lin_add(results, "CRITICAL", "ARCHIVE_CONTENT",
                            f"Malicious pattern in archive {Path(fpath).name}/{inner_name}: {pname}",
                            {"cmd":line.strip()[:300],"archive":str(fpath),"file":inner_name}, fpath)
                        add_tl(results, ts, "CRITICAL", "ARCHIVE", pname, line.strip()[:200])
                        break
            # Extract IPs
            for ip in lin_extract_ips(text):
                if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                    results["external_ips"].add(ip)


def analyze_hashes_csv(files, results, vt_key=None):
    """Analyze forensics_hashes.csv — check against VirusTotal"""
    if not files: return
    lin_log("STEP", f"Hashes CSV ({len(files)} files)...")

    all_hashes = []
    for fpath in files:
        content = read_file(fpath)
        try:
            import io
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                h = (row.get('SHA256') or row.get('sha256') or
                     row.get('MD5') or row.get('md5') or
                     row.get('Hash') or row.get('hash') or
                     row.get('Checksum') or '').strip()
                fname_col = (row.get('File') or row.get('file') or
                             row.get('Name') or row.get('name') or
                             row.get('Path') or row.get('path') or '').strip()
                if h and len(h) >= 32:
                    all_hashes.append({"hash": h, "file": fname_col})
        except Exception as e:
            # Try line by line if CSV parse fails
            for line in content.splitlines():
                h_m = re.search(r'([a-fA-F0-9]{32,64})', line)
                if h_m:
                    all_hashes.append({"hash": h_m.group(1), "file": line.strip()[:100]})

    lin_log("OK", f"  {len(all_hashes)} hashes found")
    results["total_hashes"] = len(all_hashes)

    if not vt_key:
        lin_log("WARN", "  No VT key — hash reputation check skipped (add --vt-key)")
        return

    try:
        import requests, time
    except ImportError:
        return

    lin_log("INFO", f"  Checking first 40 hashes against VirusTotal...")
    for item in all_hashes[:40]:
        h = item["hash"]
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": vt_key}, timeout=10)
            if r.status_code == 200:
                attrs = r.json().get("data",{}).get("attributes",{})
                stats = attrs.get("last_analysis_stats",{})
                mal   = stats.get("malicious", 0)
                name  = attrs.get("meaningful_name", item["file"] or h[:16])
                if mal > 0:
                    lin_add(results,"CRITICAL","HASH_VT",
                        f"Malicious file detected: {name} ({mal} VT detections)",
                        {"hash":h,"detections":mal,"name":name,"file":item["file"]}, "hashes.csv")
                    results["threat_intel"].append({
                        "hash":h,"name":name,"detections":mal,"source":"VirusTotal"})
            time.sleep(16)  # Free tier: 4/min
        except Exception as e:
            lin_log("WARN", f"  VT error: {e}")


def analyze_memory(files, results):
    if not files: return
    lin_log("STEP", f"Memory dump analysis ({len(files)} dump(s))...")

    chk = subprocess.run("vol --help 2>/dev/null", shell=True, capture_output=True)
    if chk.returncode != 0:
        lin_log("WARN", "  Volatility3 not found — install: pip3 install volatility3")
        return

    for dump in files:
        size_mb = Path(dump).stat().st_size // 1024 // 1024
        lin_log("INFO", f"  {Path(dump).name} ({size_mb} MB)")

        vol_plugins = {
            "linux.pslist":        lin__vol_pslist,
            "linux.pstree":        lin__vol_pstree,
            "linux.netstat":       _vol_netstat,
            "linux.malfind":       lin__vol_malfind,
            "linux.bash":          _vol_bash,
            "linux.lsmod":         _vol_lsmod,
            "linux.check_syscall": _vol_syscall,
        }
        for plugin, handler in vol_plugins.items():
            lin_log("INFO", f"    vol {plugin}...")
            try:
                out = subprocess.run(
                    f'vol -q -f "{dump}" {plugin} 2>/dev/null',
                    shell=True,capture_output=True,text=True,timeout=int(os.environ.get("VOL_TIMEOUT", 0)) or 7200)
                if out.stdout.strip():
                    handler(out.stdout, results, dump)
                    if UNI_CTX.get("vol_dir"):
                        Path(UNI_CTX["vol_dir"]).mkdir(parents=True, exist_ok=True)
                        (Path(UNI_CTX["vol_dir"]) / f"{Path(dump).stem}_{plugin.replace('.', '_')}.txt").write_text(out.stdout, encoding="utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                lin_log("WARN", f"    {plugin}: timeout")

def lin__vol_pslist(out,results,dump):
    for line in out.splitlines()[2:]:
        for sp in SUSP_PROCS:
            if sp.lower() in line.lower():
                lin_add(results,"CRITICAL","MEM_PROC",f"Suspicious process in memory: {sp}",
                    {"line":line.strip()[:200]},dump)

def lin__vol_pstree(out,results,dump):
    for line in out.splitlines():
        for p in ['nginx','apache','httpd','php','python','node']:
            if p in line.lower() and any(s in line.lower() for s in ['bash','sh ','dash']):
                lin_add(results,"CRITICAL","MEM_SHELL",
                    f"Shell spawned from service: {line.strip()[:150]}",
                    {"line":line.strip()},dump)

def _vol_netstat(out,results,dump):
    for line in out.splitlines()[2:]:
        for ip in lin_extract_ips(line):
            if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                results["external_ips"].add(ip)
                lin_add(results,"HIGH","MEM_NET",f"Memory: external connection {ip}",
                    {"line":line.strip()[:200]},dump)
        for p in re.findall(r':(\d{4,5})\b',line):
            try:
                if int(p) in lin_SUSP_PORTS:
                    lin_add(results,"CRITICAL","MEM_SUSP_PORT",
                        f"C2 port {p} in memory",{"port":p,"line":line[:150]},dump)
            except: pass

def lin__vol_malfind(out,results,dump):
    if any(x in out for x in ['rwx','EXECUTE']):
        lin_add(results,"CRITICAL","MEM_INJECT",
            "Code injection detected (malfind)",{"output":out[:2000]},dump)

def _vol_bash(out,results,dump):
    for line in out.splitlines()[2:]:
        for pat,pname in SUSP_CMDS[:15]:
            if pat.search(line):
                lin_add(results,"CRITICAL","MEM_BASH",
                    f"Malicious cmd in memory bash history: {pname}",
                    {"line":line.strip()[:300]},dump)
                add_tl(results,"","CRITICAL","MEM_BASH",pname,line.strip()[:200])
                break

def _vol_lsmod(out,results,dump):
    for line in out.splitlines():
        for mod in ROOTKIT_MODS:
            if mod.lower() in line.lower():
                lin_add(results,"CRITICAL","MEM_ROOTKIT",
                    f"Rootkit module in memory: {mod}",{"module":mod},dump)
                results["kernel_hits"].append({"module":mod,"type":"MEMORY_ROOTKIT"})

def _vol_syscall(out,results,dump):
    if 'hook' in out.lower() or 'modified' in out.lower():
        lin_add(results,"CRITICAL","MEM_SYSCALL_HOOK",
            "Syscall table hooks — rootkit present!",{"output":out[:1000]},dump)
        add_tl(results,"","CRITICAL","ROOTKIT","Syscall hooked",out[:200])

def lin_run_threat_intel(results, vt_key=None, abuse_key=None):
    if not vt_key and not abuse_key: return
    ips = [ip for ip in results["external_ips"] if not lin_is_private(ip)]
    if not ips: return
    lin_log("STEP", f"Threat Intel: {min(len(ips),30)} IPs...")
    try:
        import requests, time
    except: return
    for ip in list(ips)[:30]:
        if vt_key:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey":vt_key}, timeout=8)
                if r.status_code == 200:
                    attrs = r.json().get("data",{}).get("attributes",{})
                    mal   = attrs.get("last_analysis_stats",{}).get("malicious",0)
                    if mal > 0:
                        lin_add(results,"CRITICAL","THREAT_INTEL",
                            f"Malicious IP (VT {mal}): {ip}",
                            {"ip":ip,"malicious":mal,
                             "country":attrs.get("country",""),
                             "owner":attrs.get("as_owner","")},"")
                        results["threat_intel"].append({
                            "ip":ip,"malicious":mal,
                            "country":attrs.get("country",""),
                            "owner":attrs.get("as_owner",""),
                            "source":"VirusTotal"})
                time.sleep(16)
            except: pass

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def lin_generate_dashboard(results, discovered, output_dir):
    lin_log("HEAD", "Generating dashboard...")
    crit = len(results["critical"])
    high = len(results["high"])
    med  = len(results["medium"])
    ips  = len(results["external_ips"])
    ti   = len(results["threat_intel"])
    tl   = sorted(results["timeline"], key=lambda x: x.get("ts",""))
    tl_start = tl[0]["ts"]  if tl else "N/A"
    tl_end   = tl[-1]["ts"] if tl else "N/A"

    dates = sorted(set(e["ts"][:10] for e in tl if len(e.get("ts",""))>=10))
    chart_labels = str(dates).replace("'",'"')
    chart_crit   = str([sum(1 for e in tl if e.get("ts","")[:10]==d and e.get("sev")=="CRITICAL") for d in dates])
    chart_high   = str([sum(1 for e in tl if e.get("ts","")[:10]==d and e.get("sev")=="HIGH") for d in dates])

    all_f = results["critical"]+results["high"]+results["medium"][:100]
    rows = "".join(f"""<tr data-sev="{f['severity']}" data-src="{f.get('source','')}">
      <td><span class="badge" style="background:{'#ff4444' if f['severity']=='CRITICAL' else '#f97316' if f['severity']=='HIGH' else '#eab308'}">{f['severity']}</span></td>
      <td class="src">{f.get('source','')}</td>
      <td>{f.get('desc','')}</td>
      <td class="mono">{str(f.get('data',{}).get('cmd') or f.get('data',{}).get('line') or f.get('data',{}).get('ip') or f.get('data',{}).get('path') or '')[:180]}</td>
      <td class="mono dim">{str(f.get('data',{}).get('ts',''))[:19]}</td>
    </tr>""" for f in all_f[:600])

    tl_rows = ""
    prev_date = ""
    for e in tl[:800]:
        date = e.get("ts","")[:10]
        if date != prev_date and date:
            tl_rows += f'<tr class="ds"><td colspan="5"><span class="dl">📅 {date}</span></td></tr>'
            prev_date = date
        sev = e.get("sev","")
        col = {"CRITICAL":"#ff4444","HIGH":"#f97316","MEDIUM":"#eab308"}.get(sev,"#64748b")
        tl_rows += f"""<tr><td class="mono dim">{e.get('ts','')[11:19]}</td>
          <td><span class="badge" style="background:{col}">{sev}</span></td>
          <td class="src">{e.get('src','')}</td>
          <td>{e.get('desc','')}</td>
          <td class="mono">{e.get('detail','')[:150]}</td></tr>"""

    disc_rows = "".join(f"""<tr>
      <td style="color:var(--cyan);font-family:monospace;font-size:11px">{ft}</td>
      <td>{len(fps)}</td>
      <td class="mono" style="font-size:10px;color:var(--dim)">{', '.join(Path(f).name for f in fps[:3])}</td>
    </tr>""" for ft,fps in sorted(discovered.items()) if fps)

    ip_tags = "".join(f'<span class="ip-tag">{ip}</span>' for ip in sorted(results["external_ips"])[:200])
    ti_rows = "".join(f"""<tr>
      <td class="mono">{t.get('ip','')}</td>
      <td><span class="badge" style="background:#ff4444">{t.get('malicious','')}</span></td>
      <td>{t.get('source','')}</td><td>{t.get('country','')}</td><td>{t.get('owner','')}</td>
    </tr>""" for t in results["threat_intel"])

    import json as _json
    exp = _json.dumps({
        "generated":datetime.now().isoformat(),
        "summary":{"critical":crit,"high":high,"medium":med,"external_ips":ips,
                   "timeline_start":tl_start,"timeline_end":tl_end},
        "timeline":tl[:1000],
        "critical_findings":results["critical"][:200],
        "external_ips":sorted(list(results["external_ips"])),
        "threat_intel":results["threat_intel"],
        "crontab_hits":results["crontab_hits"],
        "ssh_hits":results["ssh_hits"],
        "kernel_hits":results["kernel_hits"],
        "suspicious_processes":results["suspicious_processes"],
    }, default=str, ensure_ascii=False)

    alert = f'<div class="alert">🚨 {crit} CRITICAL findings — Immediate investigation required!</div>' if crit else ""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Linux Forensics — {datetime.now().strftime('%Y-%m-%d')}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');
:root{{--bg:#080d1a;--surf:#0f1629;--surf2:#1a2035;--border:#1e2d45;
  --text:#e2e8f0;--dim:#64748b;--red:#ff4444;--orange:#f97316;
  --yellow:#eab308;--green:#22c55e;--blue:#3b82f6;--cyan:#06b6d4;--purple:#a855f7}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;line-height:1.6}}
header{{background:linear-gradient(135deg,#080d1a,#0d1832);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center}}
.logo{{font-size:18px;font-weight:700;color:var(--cyan)}}
.logo-sub{{color:var(--dim);font-size:11px;margin-top:2px}}
.ts{{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim);background:var(--surf2);padding:4px 10px;border-radius:6px;border:1px solid var(--border)}}
.toolbar{{display:flex;gap:8px;padding:10px 28px;background:var(--surf);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}}
.eb{{padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:none}}
.eb.pdf{{background:#dc2626;color:#fff}}.eb.csv{{background:#16a34a;color:#fff}}
.eb.json{{background:#2563eb;color:#fff}}.eb.rpt{{background:#7c3aed;color:#fff}}
.wrap{{max-width:1700px;margin:0 auto;padding:20px 28px}}
.alert{{background:rgba(255,68,68,.1);border:1px solid var(--red);border-radius:8px;padding:12px 18px;margin-bottom:16px;color:var(--red);font-weight:600}}
.tls{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}}
.tlc{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center}}
.tlc .v{{font-size:15px;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--cyan)}}
.tlc .l{{color:var(--dim);font-size:10px;margin-top:2px}}
.stats{{display:grid;grid-template-columns:repeat(8,1fr);gap:8px;margin-bottom:16px}}
.sc{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:10px 6px;text-align:center;position:relative;overflow:hidden}}
.sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
.sc.r::before{{background:var(--red)}}.sc.o::before{{background:var(--orange)}}
.sc.y::before{{background:var(--yellow)}}.sc.b::before{{background:var(--blue)}}
.sc.p::before{{background:var(--purple)}}.sc.c::before{{background:var(--cyan)}}.sc.g::before{{background:var(--green)}}
.sn{{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.sc.r .sn{{color:var(--red)}}.sc.o .sn{{color:var(--orange)}}.sc.y .sn{{color:var(--yellow)}}
.sc.b .sn{{color:var(--blue)}}.sc.p .sn{{color:var(--purple)}}.sc.c .sn{{color:var(--cyan)}}.sc.g .sn{{color:var(--green)}}
.sl{{color:var(--dim);font-size:10px;margin-top:2px;text-transform:uppercase;letter-spacing:.3px}}
.chart-wrap{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:14px}}
.cc{{position:relative;height:150px}}
.tabs{{display:flex;gap:2px;border-bottom:1px solid var(--border);flex-wrap:wrap}}
.tab{{padding:8px 13px;font-size:12px;cursor:pointer;color:var(--dim);border-radius:6px 6px 0 0;border:1px solid transparent;border-bottom:none;margin-bottom:-1px;transition:.15s}}
.tab:hover{{color:var(--text);background:var(--surf2)}}
.tab.active{{color:var(--cyan);background:var(--surf);border-color:var(--border);border-bottom-color:var(--surf)}}
.tp{{display:none;background:var(--surf);border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;padding:12px}}
.tp.active{{display:block}}
.fb-bar{{display:flex;gap:5px;margin-bottom:8px;flex-wrap:wrap;align-items:center}}
.fb{{background:var(--surf2);border:1px solid var(--border);color:var(--dim);padding:3px 10px;border-radius:14px;font-size:11px;cursor:pointer;transition:.15s}}
.fb:hover,.fb.active{{background:var(--blue);border-color:var(--blue);color:#fff}}
.sb{{margin-left:auto;background:var(--surf2);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font-size:12px;width:200px}}
.tw{{overflow-x:auto;max-height:500px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--surf2);color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1}}
td{{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:rgba(59,130,246,.04)}}
.badge{{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;color:#fff}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all}}
.dim{{color:var(--dim)}}.src{{font-size:11px;color:var(--cyan);font-family:'JetBrains Mono',monospace}}
.ds td{{background:var(--surf2);padding:5px 10px;border-top:2px solid var(--border)}}
.dl{{font-weight:700;font-size:12px;color:var(--yellow)}}
.ip-cloud{{line-height:2.5}}
.ip-tag{{display:inline-block;background:var(--surf2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;margin:2px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim)}}
.empty{{color:var(--dim);font-size:12px;padding:24px;text-align:center}}
footer{{border-top:1px solid var(--border);padding:12px 28px;color:var(--dim);font-size:11px;text-align:center;margin-top:28px}}
</style></head><body>
<header>
  <div><div class="logo">🐧 Linux Forensics Master Analyzer v2.0</div>
  <div class="logo-sub">CentOS/RHEL/Ubuntu — Smart Auto-Discovery</div></div>
  <div class="ts">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</header>
<div class="toolbar">
  <button class="eb pdf" onclick="window.print()">📄 PDF</button>
  <button class="eb csv" onclick="exportCSV()">📊 CSV</button>
  <button class="eb json" onclick="exportJSON()">🗂 JSON</button>
  <button class="eb rpt" onclick="exportReport()">📋 Investigation Report</button>
</div>
<div class="wrap">
{alert}
<div class="tls">
  <div class="tlc"><div class="v">{tl_start}</div><div class="l">🕐 First Event</div></div>
  <div class="tlc"><div class="v">{tl_end}</div><div class="l">🕐 Last Event</div></div>
  <div class="tlc"><div class="v" style="color:var(--red)">{len(tl)}</div><div class="l">📍 Events</div></div>
  <div class="tlc"><div class="v" style="color:var(--orange)">{len(dates)}</div><div class="l">📅 Active Days</div></div>
</div>
<div class="chart-wrap">
  <div style="font-size:13px;font-weight:600;margin-bottom:8px">📈 Activity Timeline</div>
  <div class="cc"><canvas id="chart"></canvas></div>
</div>
<div class="stats">
  <div class="sc r"><div class="sn">{crit}</div><div class="sl">Critical</div></div>
  <div class="sc o"><div class="sn">{high}</div><div class="sl">High</div></div>
  <div class="sc y"><div class="sn">{med}</div><div class="sl">Medium</div></div>
  <div class="sc b"><div class="sn">{ips}</div><div class="sl">Ext IPs</div></div>
  <div class="sc p"><div class="sn">{len(results['crontab_hits'])}</div><div class="sl">Crontab</div></div>
  <div class="sc c"><div class="sn">{len(results['ssh_hits'])}</div><div class="sl">SSH Keys</div></div>
  <div class="sc g"><div class="sn">{len(results['suspicious_processes'])}</div><div class="sl">Susp Proc</div></div>
  <div class="sc r"><div class="sn">{ti}</div><div class="sl">TI Hits</div></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="sw('tl',this)">⏱ Timeline ({len(tl)})</div>
  <div class="tab" onclick="sw('all',this)">All ({len(all_f)})</div>
  <div class="tab" onclick="sw('disc',this)">📁 Discovery</div>
  <div class="tab" onclick="sw('auth',this)">🔐 Auth</div>
  <div class="tab" onclick="sw('net',this)">🌐 Network</div>
  <div class="tab" onclick="sw('proc',this)">⚙️ Process</div>
  <div class="tab" onclick="sw('ssh',this)">🔑 SSH</div>
  <div class="tab" onclick="sw('cron',this)">⏰ Crontab</div>
  <div class="tab" onclick="sw('ips',this)">🌍 IPs ({ips})</div>
  <div class="tab" onclick="sw('ti',this)">🎯 TI ({ti})</div>
</div>

<div id="tab-tl" class="tp active">
  <div class="fb-bar">
    <button class="fb active" onclick="ftl('ALL',this)">All</button>
    <button class="fb" onclick="ftl('CRITICAL',this)">Critical</button>
    <button class="fb" onclick="ftl('HIGH',this)">High</button>
    <input class="sb" placeholder="🔍 Search..." oninput="stl(this.value)">
  </div>
  <div class="tw"><table id="tlt">
    <thead><tr><th>Time</th><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>{tl_rows or '<tr><td colspan="5" class="empty">No timestamped events</td></tr>'}</tbody>
  </table></div>
</div>

<div id="tab-all" class="tp">
  <div class="fb-bar">
    <button class="fb active" onclick="fa('ALL',this)">All</button>
    <button class="fb" onclick="fa('CRITICAL',this)">Critical</button>
    <button class="fb" onclick="fa('HIGH',this)">High</button>
    <button class="fb" onclick="fa('AUTH',this)">Auth</button>
    <button class="fb" onclick="fa('BRUTE',this)">Brute</button>
    <button class="fb" onclick="fa('NET',this)">Network</button>
    <button class="fb" onclick="fa('PROC',this)">Process</button>
    <button class="fb" onclick="fa('CRONTAB',this)">Crontab</button>
    <button class="fb" onclick="fa('SSH',this)">SSH</button>
    <button class="fb" onclick="fa('KERNEL',this)">Kernel</button>
    <button class="fb" onclick="fa('MEM',this)">Memory</button>
    <input class="sb" placeholder="🔍 Search..." oninput="saa(this.value)">
  </div>
  <div class="tw"><table id="fat">
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th><th>Timestamp</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</div>

<div id="tab-disc" class="tp">
  <div style="margin-bottom:12px;font-size:12px;color:var(--dim)">Files auto-discovered and analyzed from evidence folder:</div>
  <div class="tw"><table>
    <thead><tr><th>File Type</th><th>Count</th><th>Files Found</th></tr></thead>
    <tbody>{disc_rows}</tbody>
  </table></div>
</div>

<div id="tab-auth" class="tp">
  <div class="tw"><table>
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>{"".join(f'<tr><td><span class="badge" style="background:{"#ff4444" if f["severity"]=="CRITICAL" else "#f97316"}">{f["severity"]}</span></td><td class="src">{f["source"]}</td><td>{f["desc"]}</td><td class="mono">{str(f.get("data",{}).get("line","") or f.get("data",{}).get("ip",""))[:150]}</td></tr>' for f in all_f if any(x in f.get("source","") for x in ["AUTH","BRUTE","SUDO","USER"]))}</tbody>
  </table></div>
</div>

<div id="tab-net" class="tp">
  <div class="tw"><table>
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>{"".join(f'<tr><td><span class="badge" style="background:{"#ff4444" if f["severity"]=="CRITICAL" else "#f97316"}">{f["severity"]}</span></td><td class="src">{f["source"]}</td><td>{f["desc"]}</td><td class="mono">{str(f.get("data",{}).get("line","") or f.get("data",{}).get("ip",""))[:150]}</td></tr>' for f in all_f if any(x in f.get("source","") for x in ["NET","FIRE","DNS","HOST","SUSP_DNS"]))}</tbody>
  </table></div>
</div>

<div id="tab-proc" class="tp">
  <div class="tw"><table>
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th></tr></thead>
    <tbody>{"".join(f'<tr><td><span class="badge" style="background:{"#ff4444" if f["severity"]=="CRITICAL" else "#f97316"}">{f["severity"]}</span></td><td class="src">{f["source"]}</td><td>{f["desc"]}</td><td class="mono">{str(f.get("data",{}).get("line","") or f.get("data",{}).get("cmd",""))[:150]}</td></tr>' for f in all_f if any(x in f.get("source","") for x in ["PROC","AUDIT","BASH","MEM"]))}</tbody>
  </table></div>
</div>

<div id="tab-ssh" class="tp">
  {'<div class="empty">No SSH findings</div>' if not results["ssh_hits"] else
   "".join(f'<div style="background:var(--surf2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:8px"><div style="font-family:JetBrains Mono,monospace;font-size:11px;color:var(--cyan)">{h["file"]}</div><div style="color:var(--dim);font-size:11px;margin-top:4px">{h["keys"]} key(s)</div><div style="font-family:JetBrains Mono,monospace;font-size:10px;margin-top:6px">{"<br>".join(h["sample"])}</div></div>' for h in results["ssh_hits"])}
</div>

<div id="tab-cron" class="tp">
  {'<div class="empty">No malicious crontab entries</div>' if not results["crontab_hits"] else
   "".join(f'<div style="background:rgba(255,68,68,.08);border:1px solid #ff4444;border-radius:6px;padding:12px;margin-bottom:8px"><div style="color:#ff4444;font-weight:600">🚨 {h["pattern"]}</div><div style="font-family:JetBrains Mono,monospace;font-size:11px;margin-top:6px">{h["line"][:300]}</div><div style="color:var(--dim);font-size:10px;margin-top:4px">{h["file"]}</div></div>' for h in results["crontab_hits"])}
</div>

<div id="tab-ips" class="tp">
  <div style="margin-bottom:8px;font-size:12px;color:var(--dim)">{ips} external IPs</div>
  <div class="ip-cloud">{ip_tags or '<span class="dim">None</span>'}</div>
</div>

<div id="tab-ti" class="tp">
  {'<div class="empty">No TI hits — add --vt-key</div>' if not results["threat_intel"] else
   f'<div class="tw"><table><thead><tr><th>IP</th><th>Score</th><th>Source</th><th>Country</th><th>Owner</th></tr></thead><tbody>{ti_rows}</tbody></table></div>'}
</div>

</div>
<footer>Linux Forensics Master Analyzer v2.0 — CentOS/RHEL — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
<script id="exp" type="application/json">{exp}</script>
<script>
const ctx=document.getElementById('chart').getContext('2d');
new Chart(ctx,{{type:'bar',data:{{labels:{chart_labels},datasets:[
  {{label:'Critical',data:{chart_crit},backgroundColor:'rgba(255,68,68,0.8)',borderColor:'#ff4444',borderWidth:1}},
  {{label:'High',data:{chart_high},backgroundColor:'rgba(249,115,22,0.7)',borderColor:'#f97316',borderWidth:1}}
]}},options:{{responsive:true,maintainAspectRatio:false,
  plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}}}},
  scales:{{x:{{ticks:{{color:'#64748b',font:{{size:10}},maxRotation:45}},grid:{{color:'#1e2d45'}}}},
    y:{{ticks:{{color:'#64748b'}},grid:{{color:'#1e2d45'}},beginAtZero:true}}}}
}}}});
function sw(id,el){{document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');document.getElementById('tab-'+id).classList.add('active');}}
function fa(f,btn){{document.querySelectorAll('#tab-all .fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#fat tbody tr').forEach(r=>{{
    r.style.display=(f==='ALL'||r.dataset.sev===f||r.dataset.src?.includes(f))?'':'none';}});}}
function saa(q){{q=q.toLowerCase();document.querySelectorAll('#fat tbody tr').forEach(r=>{{
  r.style.display=(!q||r.textContent.toLowerCase().includes(q))?'':'none';}});}}
function ftl(f,btn){{document.querySelectorAll('#tab-tl .fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');document.querySelectorAll('#tlt tbody tr').forEach(r=>{{
    if(r.classList.contains('ds')){{r.style.display='';return;}}
    const sev=r.children[1]?.textContent||'';
    r.style.display=(f==='ALL'||sev.includes(f))?'':'none';}});}}
function stl(q){{q=q.toLowerCase();document.querySelectorAll('#tlt tbody tr').forEach(r=>{{
  if(r.classList.contains('ds'))return;
  r.style.display=(!q||r.textContent.toLowerCase().includes(q))?'':'none';}});}}
function dl(c,n,t){{const b=new Blob([c],{{type:t}});const a=document.createElement('a');
  a.href=URL.createObjectURL(b);a.download=n;a.click();}}
function getData(){{return JSON.parse(document.getElementById('exp').textContent);}}
function exportCSV(){{let c='Severity,Source,Description,Detail\\n';
  document.querySelectorAll('#fat tbody tr').forEach(r=>{{if(r.style.display==='none')return;
    const x=r.querySelectorAll('td');if(x.length<4)return;
    c+=[x[0].textContent.trim(),x[1].textContent.trim(),
      '"'+x[2].textContent.trim().replace(/"/g,'""')+'"',
      '"'+x[3].textContent.trim().replace(/"/g,'""')+'"'].join(',')+'\\n';}});
  dl(c,'linux_forensics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv','text/csv');}}
function exportJSON(){{dl(JSON.stringify(getData(),null,2),
  'linux_forensics_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json','application/json');}}
function exportReport(){{const d=getData();const s=d.summary;
  const html=`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Linux Forensics Report</title>
<style>body{{font-family:Segoe UI,sans-serif;font-size:13px;color:#1e293b;margin:0}}
.cover{{background:linear-gradient(135deg,#1e3a5f,#0f2444);color:#fff;padding:50px}}
h1{{font-size:24px}}h2{{color:#1e3a5f;border-bottom:2px solid #1e3a5f;padding-bottom:6px;margin:20px 0 10px}}
section{{padding:18px 40px;border-bottom:1px solid #e2e8f0}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#1e3a5f;color:#fff;padding:7px 10px;text-align:left;font-size:11px}}
td{{padding:7px 10px;border-bottom:1px solid #e2e8f0}}
tr:nth-child(even) td{{background:#f8fafc}}
.red{{color:#dc2626;font-weight:700}}.mono{{font-family:monospace;font-size:11px}}
</style></head><body>
<div class="cover"><h1>🐧 Linux Forensics Investigation Report</h1>
<div style="color:#94a3b8;margin:8px 0 16px">Generated: ${{d.generated?.substring(0,19)||''}}</div>
<div style="background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:6px;padding:10px 16px;display:inline-block">
🚨 ${{s.critical}} CRITICAL | ${{s.high}} HIGH findings</div></div>
<section><h2>1. Summary</h2>
<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>
<tr><td>Timeline Start</td><td>${{s.timeline_start}}</td></tr>
<tr><td>Timeline End</td><td>${{s.timeline_end}}</td></tr>
<tr><td class="red">Critical Findings</td><td class="red">${{s.critical}}</td></tr>
<tr><td>High Findings</td><td>${{s.high}}</td></tr>
<tr><td>External IPs</td><td>${{s.external_ips}}</td></tr>
</tbody></table></section>
<section><h2>2. Critical Findings</h2>
<table><thead><tr><th>Source</th><th>Description</th><th>Detail</th></tr></thead><tbody>
${{(d.critical_findings||[]).slice(0,50).map(f=>`<tr><td class="mono">${{f.source}}</td><td>${{f.desc}}</td><td class="mono">${{(f.data?.cmd||f.data?.line||f.data?.ip||'').substring(0,200)}}</td></tr>`).join('')}}
</tbody></table></section>
<section><h2>3. Attack Timeline</h2>
<table><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Description</th></tr></thead><tbody>
${{(d.timeline||[]).slice(0,300).map(e=>`<tr><td class="mono">${{e.ts}}</td><td style="color:${{e.sev==='CRITICAL'?'#dc2626':'#ea580c'}};font-weight:700">${{e.sev}}</td><td class="mono">${{e.src}}</td><td>${{e.desc}}</td></tr>`).join('')}}
</tbody></table></section>
<section><h2>4. External IPs</h2>
<p style="font-family:monospace;font-size:11px;line-height:2.2">${{(d.external_ips||[]).join(' | ')}}</p></section>
<section style="background:#f8fafc"><p style="color:#64748b;font-size:12px">
Linux Forensics Master Analyzer v2.0 | ${{d.generated}}<br>
<strong>For authorized security analysis only.</strong></p></section>
</body></html>`;
  dl(html,'linux_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html','text/html');}}
</script></body></html>"""

    out = Path(output_dir)/"dashboard.html"
    out.write_text(html, encoding='utf-8')
    lin_log("OK", f"Dashboard: {out}")
    return out

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def lin_main(argv=None):
    lin_banner()
    parser = argparse.ArgumentParser(
        description="Linux Forensics Master Analyzer v2.0 — Smart Auto-Discovery",
        epilog="""
Example:
  python3 linux_forensics.py --base /path/to/centos/evidence/
  python3 linux_forensics.py --base /evidence/ --vt-key XXXX --abuse-key YYYY
""")
    parser.add_argument("--base",      required=True,
                        help="Evidence base folder — tool auto-discovers everything inside")
    parser.add_argument("--output",    default="./linux_forensics_output")
    parser.add_argument("--vt-key",    help="VirusTotal API key")
    parser.add_argument("--abuse-key", help="AbuseIPDB API key")
    parser.add_argument("--tools-dir", default="./tools", help="Tools directory")
    parser.add_argument("--skip-setup",action="store_true", help="Skip requirement check/install")
    uni_add_engine_args(parser)
    args = parser.parse_args(argv)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    if not args.skip_setup:
        setup_common_tools(args.tools_dir)

    UNI_CTX["vol_dir"] = str(out / "volatility")
    _cfg = uni_engine_cfg(args, lin_log)
    _live = AnalystLive(_cfg, lin_log) if _cfg else None
    _marks = {}
    results  = lin_new_results()
    start    = datetime.now()

    # ── STEP 1: Auto-discover all evidence files ───────────────────────────────
    discovered = discover_evidence(args.base)
    results["discovery"] = {k: len(v) for k, v in discovered.items() if v}

    print(f"{lin_C.CYN}{lin_C.BOLD}{'═'*60}")
    print("  STARTING ANALYSIS")
    print(f"{'═'*60}{lin_C.RST}\n")

    # ── STEP 2: Run each module with discovered files ──────────────────────────
    # Auth logs — plain + compressed (.gz rotated)
    analyze_auth_logs(
        discovered.get("AUTH_LOG",[]) +
        discovered.get("AUTH_LOG_GZ",[]), results)

    # Syslogs — plain + compressed
    analyze_syslogs(
        discovered.get("SYSLOG",[]) +
        discovered.get("SYSLOG_GZ",[]) +
        discovered.get("DMESG",[]), results)

    # Cron logs — plain + compressed
    analyze_cron_logs(
        discovered.get("CRON_LOG",[]) +
        discovered.get("CRON_LOG_GZ",[]), results)

    # Audit logs — plain + compressed
    analyze_audit_logs(
        discovered.get("AUDIT_LOG",[]) +
        discovered.get("AUDIT_LOG_GZ",[]), results)

    analyze_web_logs(
        discovered.get("WEB_LOG",[]), results)
    uni_live_feed(_live, "system logs", results, _marks, discovered.get("AUTH_LOG",[]) + discovered.get("AUDIT_LOG",[]) + discovered.get("SYSLOG",[]) + discovered.get("CRON_LOG",[]))

    analyze_pkg_logs(
        discovered.get("PKG_LOG",[]), results)

    analyze_passwd(
        discovered.get("PASSWD",[]) +
        discovered.get("SHADOW",[]) +
        discovered.get("SUDOERS",[]) +
        discovered.get("GROUP",[]), results)

    analyze_bash_history(
        discovered.get("BASH_HISTORY",[]), results)

    analyze_ssh_files(
        discovered.get("SSHD_CONFIG",[]) +
        discovered.get("AUTH_KEYS",[]) +
        discovered.get("KNOWN_HOSTS",[]), results)

    analyze_crontabs(
        discovered.get("CRONTAB",[]) +
        discovered.get("ETC_CRONTAB",[]) +
        discovered.get("INIT_SCRIPTS",[]), results)
    uni_live_feed(_live, "accounts & persistence", results, _marks, discovered.get("BASH_HISTORY",[]) + discovered.get("AUTH_KEYS",[]) + discovered.get("CRONTAB",[]) + discovered.get("SYSTEMD",[]))

    analyze_network_files(discovered, results)

    analyze_processes(
        discovered.get("PROCESS_LIST",[]) +
        discovered.get("LSOF",[]), results)

    analyze_filesystem_artifacts(discovered, results)

    analyze_kernel_modules(discovered, results)

    analyze_systemd(
        discovered.get("SYSTEMD",[]), results)
    uni_live_feed(_live, "runtime state", results, _marks, discovered.get("PROCESS_LIST",[]) + discovered.get("LSOF",[]) + discovered.get("LAST_LOG",[]))

    analyze_last_log(
        discovered.get("LAST_LOG",[]) +
        discovered.get("HOST_INFO",[]), results)

    # Archives — extract and analyze contents
    analyze_archives(
        discovered.get("ARCHIVE_ZIP",[]) +
        discovered.get("ARCHIVE_7Z",[]) +
        discovered.get("ARCHIVE_RAR",[]), results)

    # Hashes CSV
    analyze_hashes_csv(
        discovered.get("HASHES",[]), results, args.vt_key)

    analyze_memory(
        discovered.get("MEMORY_DUMP",[]), results)
    uni_live_feed(_live, "memory", results, _marks, vol_dir=UNI_CTX["vol_dir"])
    xt_run_all("linux", args.base, out, results, lin_log, args.tools_dir, discovered.get("MEMORY_DUMP", []), install=not args.skip_setup)
    uni_live_feed(_live, "external tools (yara / clamav / auditd / logins)", results, _marks)

    if args.vt_key or args.abuse_key:
        lin_run_threat_intel(results, args.vt_key, args.abuse_key)

    # ── STEP 3: Save outputs ──────────────────────────────────────────────────
    json_path = out/"results.json"
    with open(json_path,'w') as f:
        json.dump({
            "generated":    datetime.now().isoformat(),
            "duration_sec": (datetime.now()-start).seconds,
            "discovery":    results["discovery"],
            "summary":{"critical":len(results["critical"]),"high":len(results["high"]),
                       "medium":len(results["medium"]),"external_ips":len(results["external_ips"])},
            "critical":  results["critical"][:300],
            "high":      results["high"][:300],
            "timeline":  results["timeline"],
            "external_ips": sorted(list(results["external_ips"])),
            "threat_intel": results["threat_intel"],
            "crontab_hits": results["crontab_hits"],
            "ssh_hits":     results["ssh_hits"],
            "kernel_hits":  results["kernel_hits"],
            "suspicious_processes": results["suspicious_processes"],
        }, f, indent=2, default=str)

    csv_path = out/"findings.csv"
    with open(csv_path,'w',newline='') as f:
        w = csv.DictWriter(f, fieldnames=["severity","source","desc","file"])
        w.writeheader()
        for item in results["critical"]+results["high"]+results["medium"]:
            w.writerow({k:item.get(k,"") for k in ["severity","source","desc","file"]})

    uni_dump_results(results, out)
    html_path = lin_generate_dashboard(results, discovered, out)
    uni_finalize("linux", out, args.base, results, _cfg, _live, lin_log, html_path=html_path)

    elapsed = (datetime.now()-start).seconds
    print(f"""
{lin_C.BOLD}{lin_C.CYN}{'═'*60}
  ANALYSIS COMPLETE ({elapsed}s)
{'═'*60}{lin_C.RST}
  {lin_C.RED}🔴 CRITICAL    : {len(results['critical'])}{lin_C.RST}
  {lin_C.YEL}🟠 HIGH        : {len(results['high'])}{lin_C.RST}
  {lin_C.BLU}🔵 MEDIUM      : {len(results['medium'])}{lin_C.RST}
  {lin_C.CYN}🌐 EXT IPs     : {len(results['external_ips'])}{lin_C.RST}
  {lin_C.MAG}⏰ CRONTAB     : {len(results['crontab_hits'])}{lin_C.RST}
  {lin_C.GRN}🔑 SSH KEYS    : {len(results['ssh_hits'])}{lin_C.RST}
  {lin_C.RED}🧬 THREAT INTEL: {len(results['threat_intel'])}{lin_C.RST}
{lin_C.BOLD}{'═'*60}{lin_C.RST}
  📊 Dashboard : {html_path}
  📋 JSON      : {json_path}
  📄 CSV       : {csv_path}
{'═'*60}
""")
    if results["critical"]:
        print(f"{lin_C.RED}{lin_C.BOLD}🚨 TOP CRITICAL:{lin_C.RST}")
        for f in results["critical"][:8]:
            print(f"  • [{f['source']}] {f['desc'][:90]}")
    _fin = uni_cli_finish(out, "linux", args.base, html_path, getattr(args, "vt_key", None), getattr(args, "abuse_key", None))
    print(f"\n{lin_C.GRN}Report (PDF + DOCX + HTML): {Path(_fin).parent}{lin_C.RST}\n  open: firefox {_fin}\n")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: macOS FORENSICS MODULE (all top-level names prefixed mac_*)
# Persistence (LaunchAgents/Daemons) · Quarantine · Unified Logs · TCC · Kexts
# Reuses generic helpers already defined in the Linux section above:
#   read_file(), add_tl(), lin_is_private(), lin_extract_ips(),
#   SUSP_CMDS, SUSP_PROCS, WHITELIST_IPS, lin_SUSP_PORTS, ROOTKIT_MODS
# ══════════════════════════════════════════════════════════════════════════════

class mac_C:
    RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"; CYN="\033[96m"
    BOLD="\033[1m"; RST="\033[0m";  BLU="\033[94m"; MAG="\033[95m"

def mac_log(lvl, msg):
    icons={"INFO":f"{mac_C.CYN}[*]","OK":f"{mac_C.GRN}[+]","WARN":f"{mac_C.YEL}[!]",
           "CRIT":f"{mac_C.RED}[!!!]","STEP":f"{mac_C.BLU}[→]","HEAD":f"{mac_C.MAG}[■]"}
    print(f"{icons.get(lvl,'[?]')} {msg}{mac_C.RST}")

def mac_banner():
    print(f"""{mac_C.CYN}{mac_C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║      macOS Forensics Master Analyzer v1.0                            ║
║      Persistence · Quarantine · Unified Logs · TCC · Kexts           ║
║  LaunchItems│Bash/Zsh│SSH│Crontab│Network│Quarantine│Safari│Kexts   ║
╚══════════════════════════════════════════════════════════════════════╝
{mac_C.RST}""")

# ══════════════════════════════════════════════════════════════════════════════
# EVIDENCE DISCOVERY — macOS-specific artifact signatures
# ══════════════════════════════════════════════════════════════════════════════

MAC_FILE_SIGNATURES = {
    # Persistence — LaunchAgents/LaunchDaemons plists (equivalent of Registry Run
    # keys on Windows / systemd+crontab on Linux). Most important macOS artifact.
    "LAUNCH_AGENTS": {
        "names": ["*.plist"],
        "path_hints": ["launchagents", "launchdaemons"],
    },
    # Downloaded-file provenance (quarantine attribute database)
    "QUARANTINE_DB": {
        "names": ["com.apple.launchservices.quarantineeventsv2",
                  "quarantineeventsv2", "quarantineevents"],
        "path_hints": [],
    },
    # Unified logs exported as text, and the legacy system.log
    "UNIFIED_LOG": {
        "names": ["system.log", "system.log.*", "unified_log*.txt",
                  "logarchive*.txt", "log_show*.txt", "asl.log*"],
        "keywords": ["com.apple", "kernel", "launchd"],
    },
    # Shell history
    "BASH_HISTORY": {
        "names": [".bash_history", ".zsh_history", ".sh_history", "bash_history", "zsh_history"],
        "keywords": ["wget", "curl", "ssh", "sudo", "chmod"],
    },
    # TCC — privacy permissions database (camera/mic/screen-recording/full-disk access)
    "TCC_DB": {
        "names": ["tcc.db"],
        "path_hints": [],
    },
    # SSH
    "SSHD_CONFIG": {"names": ["sshd_config"], "keywords": ["PermitRootLogin","PasswordAuthentication"]},
    "AUTH_KEYS":   {"names": ["authorized_keys","authorized_keys2"], "keywords": ["ssh-rsa","ssh-ed25519"]},
    "KNOWN_HOSTS": {"names": ["known_hosts"], "keywords": ["ssh-rsa","ecdsa","ed25519"]},
    # Crontab (legacy — modern macOS mostly uses launchd, but still checked)
    "CRONTAB": {"names": ["crontab","crontab.*"], "keywords": ["* * * * *","@reboot","@daily"]},
    # Users / privilege files
    "PASSWD":   {"names": ["passwd"],  "keywords": ["root:","daemon:","nologin"]},
    "SUDOERS":  {"names": ["sudoers","sudoers.*"], "keywords": ["ALL=(ALL)","NOPASSWD"]},
    "HOSTS":    {"names": ["hosts"],   "keywords": ["127.0.0.1","localhost"]},
    # Network snapshots (same text formats as Linux: netstat/lsof/ifconfig output)
    "NETSTAT":  {"names": ["netstat*","lsof*","connections*","network_connections*"],
                 "keywords": ["ESTABLISHED","LISTEN","tcp","udp"]},
    "IFCONFIG": {"names": ["ifconfig*","interfaces*"], "keywords": ["inet ","ether","UP","RUNNING"]},
    # Process snapshot
    "PROCESS_LIST": {"names": ["ps.txt","ps_aux*","processes*","running_processes*"],
                      "keywords": ["PID","CMD","COMMAND"]},
    # Installed apps / package history
    "INSTALL_HISTORY": {"names": ["installhistory.plist","install_history*"], "path_hints": []},
    # Kernel extensions (legacy kexts — still relevant on older macOS / forensics images)
    "KEXTS": {"names": ["kextstat*","kext_list*","systemextensions*"], "keywords": ["com.apple","kext"]},
    # Login items / startup apps
    "LOGIN_ITEMS": {"names": ["loginitems*","backgrounditems.btm","com.apple.loginitems*"], "path_hints": []},
    # Browser history (SQLite — flagged for separate offline analysis, not parsed inline)
    "SAFARI_HISTORY": {"names": ["history.db"], "path_hints": ["safari"]},
    # Spotlight / FSEvents (file-activity artifacts — flagged, not deep-parsed)
    "FSEVENTS": {"names": ["fseventsd*","*.fsevents"], "path_hints": ["fsevents"]},
    "HASHES": {"names": ["*hashes*.csv","*hashes*.txt","md5sum*","sha256sum*"],
               "keywords": ["MD5","SHA","hash","checksum"]},
}

def discover_evidence_mac(base):
    """Walk a macOS evidence folder tree and categorize every file."""
    base = Path(base)
    discovered = defaultdict(list)
    mac_log("HEAD", f"Auto-discovering macOS evidence in: {base}")
    mac_log("INFO", "Scanning all files recursively...")

    all_files = []
    try:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ['__pycache__','.git','node_modules']]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    all_files.append((fpath, fpath.stat().st_size))
                except Exception:
                    pass
    except Exception as e:
        mac_log("WARN", f"Walk error: {e}")

    mac_log("INFO", f"  Found {len(all_files)} files")

    uncategorized = []
    for fpath, fsize in all_files:
        fname_lower = fpath.name.lower()
        full_lower  = str(fpath).lower()
        categorized = False

        for ftype, sig in MAC_FILE_SIGNATURES.items():
            path_hints = sig.get("path_hints", [])
            if path_hints and not any(h in full_lower for h in path_hints):
                # Needs a path hint match (e.g. must be inside a LaunchAgents dir)
                if ftype in ("LAUNCH_AGENTS","SAFARI_HISTORY","FSEVENTS"):
                    continue

            name_match = False
            for pattern in sig["names"]:
                if '*' in pattern:
                    parts  = pattern.lower().split('*')
                    prefix, suffix = parts[0], (parts[-1] if len(parts) > 1 else '')
                    if fname_lower.startswith(prefix) and (not suffix or fname_lower.endswith(suffix)):
                        name_match = True
                        break
                elif fname_lower == pattern.lower():
                    name_match = True
                    break

            if name_match:
                keywords = sig.get("keywords", [])
                if not keywords:
                    discovered[ftype].append(str(fpath))
                    categorized = True
                    break
                elif 0 < fsize < 50*1024*1024:
                    try:
                        sample = fpath.read_bytes()[:4096].decode('utf-8', errors='ignore')
                        if any(kw in sample for kw in keywords):
                            discovered[ftype].append(str(fpath))
                            categorized = True
                            break
                    except Exception:
                        pass
                    if not categorized:
                        discovered[ftype].append(str(fpath))
                        categorized = True
                        break

        if not categorized and fsize > 0:
            uncategorized.append(str(fpath))

    if uncategorized:
        discovered["UNCATEGORIZED"] = uncategorized

    print(f"\n{mac_C.BOLD}{'─'*55}{mac_C.RST}")
    print(f"{mac_C.BOLD}  macOS EVIDENCE DISCOVERY RESULTS{mac_C.RST}")
    print(f"{'─'*55}")
    found = {k: v for k, v in discovered.items() if v}
    for ftype, files in sorted(found.items()):
        print(f"  {mac_C.GRN}✓{mac_C.RST} {ftype:<20} {len(files):>3} file(s)")
    missing = [k for k in MAC_FILE_SIGNATURES if k not in found]
    if missing:
        print(f"\n  {mac_C.YEL}Not found:{mac_C.RST} {', '.join(missing[:8])}")
    print(f"{'─'*55}\n")
    return discovered

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS / HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def mac_new_results():
    return {
        "critical":[], "high":[], "medium":[],
        "external_ips":set(), "suspicious_processes":[],
        "launch_items":[], "quarantine_hits":[], "kext_hits":[],
        "ssh_hits":[], "timeline":[], "threat_intel":[],
        "discovery":{},
    }

def mac_add(results, sev, src, desc, data=None, file=""):
    e = {"severity":sev,"source":src,"desc":desc,
         "data":data or {},"file":str(file),
         "timestamp":datetime.now().isoformat()}
    if   sev=="CRITICAL": results["critical"].append(e)
    elif sev=="HIGH":     results["high"].append(e)
    else:                 results["medium"].append(e)

# Known-standard Apple LaunchAgent/Daemon identifiers — anything NOT matching
# "com.apple.*" or a handful of known vendor prefixes gets extra scrutiny.
MAC_KNOWN_VENDOR_PREFIXES = (
    "com.apple.", "com.microsoft.", "com.google.", "com.adobe.",
    "com.docker.", "com.jetbrains.", "com.valvesoftware.",
)

# ══════════════════════════════════════════════════════════════════════════════
# ANALYZERS
# ══════════════════════════════════════════════════════════════════════════════

def mac_analyze_launch_items(files, results):
    """Parse LaunchAgent/LaunchDaemon .plist files — the #1 macOS persistence
    mechanism (equivalent of Windows Registry Run keys / Linux systemd units)."""
    if not files: return
    mac_log("STEP", f"Launch items ({len(files)} plist files)...")
    for fpath in files:
        content = read_file(fpath)
        fname = Path(fpath).name
        label = ""
        m = re.search(r'<key>Label</key>\s*<string>([^<]+)</string>', content)
        if m: label = m.group(1)

        prog_args = re.findall(r'<string>([^<]+)</string>', content)
        full_cmd  = " ".join(prog_args)

        is_user_agent = "/users/" in str(fpath).lower() and "launchagents" in str(fpath).lower()
        is_known_vendor = label.lower().startswith(MAC_KNOWN_VENDOR_PREFIXES) if label else False

        entry = {"file": str(fpath), "label": label or fname, "cmd": full_cmd[:300],
                 "location": "User" if is_user_agent else "System"}
        results["launch_items"].append(entry)

        # Check the program/arguments for malicious patterns
        for pat, pname in SUSP_CMDS:
            if pat.search(full_cmd):
                mac_add(results,"CRITICAL","LAUNCH_ITEM_MALICIOUS",
                    f"Malicious launch item [{label or fname}]: {pname}",
                    {"label":label,"cmd":full_cmd[:300],"pattern":pname}, fpath)
                break

        # Runs from a temp/suspicious directory
        if any(sd in full_cmd for sd in ['/tmp','/var/tmp','/private/tmp']):
            mac_add(results,"CRITICAL","LAUNCH_ITEM_TEMP",
                f"Launch item runs from temp dir: {label or fname}",
                {"label":label,"cmd":full_cmd[:300]}, fpath)

        # Unknown vendor launching at system level (LaunchDaemons = root persistence)
        if "launchdaemons" in str(fpath).lower() and label and not is_known_vendor:
            mac_add(results,"HIGH","LAUNCH_DAEMON_UNKNOWN",
                f"Non-Apple LaunchDaemon (runs as root): {label}",
                {"label":label,"cmd":full_cmd[:300]}, fpath)

        # RunAtLoad + KeepAlive together = persistent background execution
        if "<key>RunAtLoad</key>" in content and "<key>KeepAlive</key>" in content and not is_known_vendor:
            mac_add(results,"MEDIUM","LAUNCH_ITEM_PERSISTENT",
                f"Persistent (RunAtLoad+KeepAlive) item: {label or fname}",
                {"label":label}, fpath)

    mac_log("OK", f"  Launch items: {len(results['launch_items'])} parsed")

def mac_analyze_quarantine(files, results):
    """Downloaded-file provenance — where a file came from (browser/app) and when."""
    if not files: return
    mac_log("STEP", f"Quarantine events ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        # Text/plist export of QuarantineEventsV2 — look for URLs and executable downloads
        urls = re.findall(r'https?://[^\s<>"\']+', content)
        exe_urls = [u for u in urls if re.search(r'\.(exe|sh|command|dmg|pkg|scpt)(\?|$)', u, re.I)]
        for u in exe_urls[:20]:
            mac_add(results,"MEDIUM","QUARANTINE_DOWNLOAD",
                f"Downloaded executable/installer: {u[:150]}",
                {"url":u[:300]}, fpath)
        results["quarantine_hits"].append({"file":str(fpath),"url_count":len(urls),
                                            "exe_count":len(exe_urls)})
    mac_log("OK", f"  Quarantine: {len(results['quarantine_hits'])} source(s) reviewed")

def mac_analyze_unified_log(files, results):
    if not files: return
    mac_log("STEP", f"Unified/system logs ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            ll = line.lower()
            ts_m = re.match(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line)
            ts = ts_m.group(1) if ts_m else ""
            for pat, pname in SUSP_CMDS:
                if pat.search(line):
                    mac_add(results,"HIGH","UNIFIED_LOG_MALICIOUS",
                        f"Malicious command in log: {pname}",
                        {"ts":ts,"line":line[:250]}, fpath)
                    add_tl(results, ts, "HIGH", "UNIFIED_LOG", pname, line[:200])
                    break
            if 'sudo' in ll and ('incorrect password' in ll or 'authentication failure' in ll):
                mac_add(results,"MEDIUM","SUDO_FAILED",
                    f"Failed sudo attempt: {line[:150]}", {"ts":ts}, fpath)
            if 'sshd' in ll and 'accepted' in ll:
                add_tl(results, ts, "HIGH", "SSH", "SSH login accepted", line[:150])
            for ip in lin_extract_ips(line):
                if not lin_is_private(ip) and ip not in WHITELIST_IPS:
                    results["external_ips"].add(ip)

def mac_analyze_tcc(files, results):
    if not files: return
    mac_log("STEP", f"TCC privacy database ({len(files)} files)...")
    for fpath in files:
        mac_add(results,"MEDIUM","TCC_DB_PRESENT",
            f"TCC.db found — review manually for unexpected camera/mic/screen-recording grants",
            {"file":str(fpath)}, fpath)

def mac_analyze_kexts(files, results):
    if not files: return
    mac_log("STEP", f"Kernel extensions ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for line in content.splitlines():
            if 'com.apple' in line.lower():
                continue
            if re.search(r'\d+\s+\d+\s+\S+', line) and line.strip():
                mac_add(results,"MEDIUM","KEXT_THIRD_PARTY",
                    f"Non-Apple kernel extension loaded: {line.strip()[:150]}",
                    {"line":line.strip()[:150]}, fpath)

def mac_analyze_login_items(files, results):
    if not files: return
    mac_log("STEP", f"Login items ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        for pat, pname in SUSP_CMDS:
            if pat.search(content):
                mac_add(results,"HIGH","LOGIN_ITEM_MALICIOUS",
                    f"Malicious login item: {pname}", {"pattern":pname}, fpath)

def mac_analyze_install_history(files, results):
    if not files: return
    mac_log("STEP", f"Install history ({len(files)} files)...")
    for fpath in files:
        content = read_file(fpath)
        pkgs = re.findall(r'<string>([^<]+\.(?:pkg|app))</string>', content, re.I)
        if pkgs:
            results.setdefault("installed_packages", []).extend(pkgs[:200])

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD (reuses the Linux-style dark dashboard layout, retitled for macOS)
# ══════════════════════════════════════════════════════════════════════════════

def mac_generate_dashboard(results, discovered, output_dir):
    mac_log("HEAD", "Generating dashboard...")
    crit = len(results["critical"]); high = len(results["high"]); med = len(results["medium"])
    ips  = len(results["external_ips"]); ti = len(results["threat_intel"])
    tl   = sorted(results["timeline"], key=lambda x: x.get("ts",""))
    tl_start = tl[0]["ts"] if tl else "N/A"
    tl_end   = tl[-1]["ts"] if tl else "N/A"

    all_f = results["critical"] + results["high"] + results["medium"][:100]
    rows = "".join(f"""<tr data-sev="{f['severity']}" data-src="{f.get('source','')}">
      <td><span class="badge" style="background:{'#ff4444' if f['severity']=='CRITICAL' else '#f97316' if f['severity']=='HIGH' else '#eab308'}">{f['severity']}</span></td>
      <td class="src">{f.get('source','')}</td>
      <td>{f.get('desc','')}</td>
      <td class="mono">{str(f.get('data',{}).get('cmd') or f.get('data',{}).get('line') or f.get('data',{}).get('label') or '')[:180]}</td>
      <td class="mono dim">{str(f.get('data',{}).get('ts',''))[:19]}</td>
    </tr>""" for f in all_f[:600])

    li_rows = "".join(f"""<tr>
      <td class="mono" style="color:var(--cyan)">{li.get('location','')}</td>
      <td class="mono">{li.get('label','')}</td>
      <td class="mono" style="font-size:11px">{li.get('cmd','')[:200]}</td>
    </tr>""" for li in results["launch_items"][:300])

    ip_tags = "".join(f'<span class="ip-tag">{ip}</span>' for ip in sorted(results["external_ips"])[:200])

    import json as _json
    exp = _json.dumps({
        "generated": datetime.now().isoformat(),
        "summary": {"critical":crit,"high":high,"medium":med,"external_ips":ips},
        "timeline": tl[:1000],
        "critical_findings": results["critical"][:200],
        "external_ips": sorted(list(results["external_ips"])),
        "launch_items": results["launch_items"][:300],
        "threat_intel": results["threat_intel"],
    }, default=str, ensure_ascii=False)

    alert = f'<div class="alert">🚨 {crit} CRITICAL findings — Immediate investigation required!</div>' if crit else ""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>macOS Forensics — {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');
:root{{--bg:#080d1a;--surf:#0f1629;--surf2:#1a2035;--border:#1e2d45;--text:#e2e8f0;--dim:#64748b;
  --red:#ff4444;--orange:#f97316;--yellow:#eab308;--green:#22c55e;--blue:#3b82f6;--cyan:#06b6d4;--purple:#a855f7}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;line-height:1.6}}
header{{background:linear-gradient(135deg,#080d1a,#0d1832);border-bottom:1px solid var(--border);padding:16px 28px;display:flex;align-items:center}}
.logo{{font-size:18px;font-weight:700;color:var(--cyan)}}
.logo-sub{{color:var(--dim);font-size:11px;margin-top:2px}}
.ts{{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim);background:var(--surf2);padding:4px 10px;border-radius:6px;border:1px solid var(--border)}}
.wrap{{max-width:1700px;margin:0 auto;padding:20px 28px}}
.alert{{background:rgba(255,68,68,.1);border:1px solid var(--red);border-radius:8px;padding:12px 18px;margin-bottom:16px;color:var(--red);font-weight:600}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:16px}}
.sc{{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:10px 6px;text-align:center;position:relative;overflow:hidden}}
.sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
.sc.r::before{{background:var(--red)}}.sc.o::before{{background:var(--orange)}}.sc.y::before{{background:var(--yellow)}}
.sc.b::before{{background:var(--blue)}}.sc.p::before{{background:var(--purple)}}.sc.c::before{{background:var(--cyan)}}
.sn{{font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.sc.r .sn{{color:var(--red)}}.sc.o .sn{{color:var(--orange)}}.sc.y .sn{{color:var(--yellow)}}
.sc.b .sn{{color:var(--blue)}}.sc.p .sn{{color:var(--purple)}}.sc.c .sn{{color:var(--cyan)}}
.sl{{color:var(--dim);font-size:10px;margin-top:2px;text-transform:uppercase}}
.tabs{{display:flex;gap:2px;border-bottom:1px solid var(--border);flex-wrap:wrap}}
.tab{{padding:8px 13px;font-size:12px;cursor:pointer;color:var(--dim);border-radius:6px 6px 0 0;border:1px solid transparent;border-bottom:none;margin-bottom:-1px}}
.tab.active{{color:var(--cyan);background:var(--surf);border-color:var(--border);border-bottom-color:var(--surf)}}
.tp{{display:none;background:var(--surf);border:1px solid var(--border);border-top:none;border-radius:0 0 8px 8px;padding:12px}}
.tp.active{{display:block}}
.tw{{overflow-x:auto;max-height:500px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--surf2);color:var(--dim);font-size:10px;text-transform:uppercase;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0}}
td{{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
.badge{{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;color:#fff}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all}}
.dim{{color:var(--dim)}}.src{{font-size:11px;color:var(--cyan);font-family:'JetBrains Mono',monospace}}
.ip-cloud{{line-height:2.5}}
.ip-tag{{display:inline-block;background:var(--surf2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;margin:2px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--dim)}}
.empty{{color:var(--dim);font-size:12px;padding:24px;text-align:center}}
footer{{border-top:1px solid var(--border);padding:12px 28px;color:var(--dim);font-size:11px;text-align:center;margin-top:28px}}
</style></head><body>
<header>
  <div><div class="logo">🍎 macOS Forensics Master Analyzer v1.0</div>
  <div class="logo-sub">Persistence · Quarantine · Unified Logs · TCC · Kexts</div></div>
  <div class="ts">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</header>
<div class="wrap">
{alert}
<div class="stats">
  <div class="sc r"><div class="sn">{crit}</div><div class="sl">Critical</div></div>
  <div class="sc o"><div class="sn">{high}</div><div class="sl">High</div></div>
  <div class="sc y"><div class="sn">{med}</div><div class="sl">Medium</div></div>
  <div class="sc b"><div class="sn">{ips}</div><div class="sl">Ext IPs</div></div>
  <div class="sc p"><div class="sn">{len(results['launch_items'])}</div><div class="sl">Launch Items</div></div>
  <div class="sc r"><div class="sn">{ti}</div><div class="sl">TI Hits</div></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="sw('all',this)">All Findings ({len(all_f)})</div>
  <div class="tab" onclick="sw('li',this)">🚀 Launch Items ({len(results['launch_items'])})</div>
  <div class="tab" onclick="sw('ips',this)">🌍 IPs ({ips})</div>
</div>
<div id="tab-all" class="tp active">
  <div class="tw"><table id="fat">
    <thead><tr><th>Sev</th><th>Source</th><th>Description</th><th>Detail</th><th>Timestamp</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="5" class="empty">No findings</td></tr>'}</tbody>
  </table></div>
</div>
<div id="tab-li" class="tp">
  <div style="margin-bottom:10px;font-size:12px;color:var(--dim)">LaunchAgents (user, run at login) and LaunchDaemons (root, run at boot) — the primary macOS persistence mechanism.</div>
  <div class="tw"><table>
    <thead><tr><th>Scope</th><th>Label</th><th>Program / Arguments</th></tr></thead>
    <tbody>{li_rows or '<tr><td colspan="3" class="empty">No launch items parsed</td></tr>'}</tbody>
  </table></div>
</div>
<div id="tab-ips" class="tp">
  <div style="margin-bottom:8px;font-size:12px;color:var(--dim)">{ips} external IPs</div>
  <div class="ip-cloud">{ip_tags or '<span class="dim">None</span>'}</div>
</div>
</div>
<footer>macOS Forensics Master Analyzer v1.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
<script id="exp" type="application/json">{exp}</script>
<script>
function sw(id,el){{document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');document.getElementById('tab-'+id).classList.add('active');}}
</script>
</body></html>"""

    out = Path(output_dir)/"dashboard.html"
    out.write_text(html, encoding='utf-8')
    mac_log("OK", f"Dashboard: {out}")
    return out

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def mac_main(argv=None):
    mac_banner()
    parser = argparse.ArgumentParser(
        description="macOS Forensics Master Analyzer v1.0 — Smart Auto-Discovery",
        epilog="""
Example:
  python3 forensics_unified.py --base /path/to/macos/evidence/   (via launcher)
""")
    parser.add_argument("--base", required=True, help="Evidence base folder")
    parser.add_argument("--output", default="./macos_forensics_output")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--abuse-key", help="AbuseIPDB API key")
    parser.add_argument("--tools-dir", default="./tools", help="Tools directory")
    parser.add_argument("--skip-setup", action="store_true", help="Skip requirement check/install")
    uni_add_engine_args(parser)
    args = parser.parse_args(argv)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    if not args.skip_setup:
        setup_common_tools(args.tools_dir)

    UNI_CTX["vol_dir"] = str(out / "volatility")
    _cfg = uni_engine_cfg(args, mac_log)
    _live = AnalystLive(_cfg, mac_log) if _cfg else None
    _marks = {}
    results = mac_new_results()
    start   = datetime.now()

    discovered = discover_evidence_mac(args.base)
    results["discovery"] = {k: len(v) for k, v in discovered.items() if v}

    print(f"{mac_C.CYN}{mac_C.BOLD}{'═'*60}")
    print("  STARTING ANALYSIS")
    print(f"{'═'*60}{mac_C.RST}\n")

    mac_analyze_launch_items(discovered.get("LAUNCH_AGENTS",[]), results)
    mac_analyze_quarantine(discovered.get("QUARANTINE_DB",[]), results)
    mac_analyze_unified_log(discovered.get("UNIFIED_LOG",[]), results)
    analyze_bash_history(discovered.get("BASH_HISTORY",[]), results)  # reused from Linux module
    mac_analyze_tcc(discovered.get("TCC_DB",[]), results)
    mac_analyze_kexts(discovered.get("KEXTS",[]), results)
    mac_analyze_login_items(discovered.get("LOGIN_ITEMS",[]), results)
    mac_analyze_install_history(discovered.get("INSTALL_HISTORY",[]), results)
    uni_live_feed(_live, "launch items & history", results, _marks, discovered.get("LAUNCH_AGENTS",[]) + discovered.get("BASH_HISTORY",[]) + discovered.get("UNIFIED_LOG",[]) + discovered.get("INSTALL_HISTORY",[]))
    _dumps = uni_memory_dumps(args.base)
    if _dumps:
        mac_log("STEP", f"Memory dump analysis ({len(_dumps)} dump(s))...")
        uni_memory_analysis("macos", _dumps, UNI_CTX["vol_dir"], mac_log)
        uni_live_feed(_live, "memory", results, _marks, vol_dir=UNI_CTX["vol_dir"])
    xt_run_all("macos", args.base, out, results, mac_log, args.tools_dir, _dumps, install=not args.skip_setup)
    uni_live_feed(_live, "external tools (yara / clamav / logins)", results, _marks)
    analyze_ssh_files(
        discovered.get("SSHD_CONFIG",[]) + discovered.get("AUTH_KEYS",[]) +
        discovered.get("KNOWN_HOSTS",[]), results)                     # reused from Linux module
    analyze_crontabs(discovered.get("CRONTAB",[]), results)            # reused
    analyze_passwd(
        discovered.get("PASSWD",[]) + discovered.get("SUDOERS",[]), results)  # reused
    analyze_network_files(discovered, results)                        # reused
    analyze_processes(discovered.get("PROCESS_LIST",[]), results)     # reused
    analyze_hashes_csv(discovered.get("HASHES",[]), results, args.vt_key)  # reused

    if args.vt_key or args.abuse_key:
        lin_run_threat_intel(results, args.vt_key, args.abuse_key)    # reused

    json_path = out/"results.json"
    with open(json_path,'w') as f:
        json.dump({
            "generated": datetime.now().isoformat(),
            "duration_sec": (datetime.now()-start).seconds,
            "discovery": results["discovery"],
            "summary": {"critical":len(results["critical"]),"high":len(results["high"]),
                        "medium":len(results["medium"]),"external_ips":len(results["external_ips"])},
            "critical": results["critical"][:300],
            "high":     results["high"][:300],
            "timeline": results["timeline"],
            "external_ips": sorted(list(results["external_ips"])),
            "launch_items": results["launch_items"],
            "threat_intel": results["threat_intel"],
        }, f, indent=2, default=str)

    csv_path = out/"findings.csv"
    with open(csv_path,'w',newline='') as f:
        w = csv.DictWriter(f, fieldnames=["severity","source","desc","file"])
        w.writeheader()
        for item in results["critical"]+results["high"]+results["medium"]:
            w.writerow({k:item.get(k,"") for k in ["severity","source","desc","file"]})

    uni_dump_results(results, out)
    html_path = mac_generate_dashboard(results, discovered, out)
    uni_finalize("macos", out, args.base, results, _cfg, _live, mac_log, html_path=html_path)

    elapsed = (datetime.now()-start).seconds
    print(f"""
{mac_C.BOLD}{mac_C.CYN}{'═'*60}
  ANALYSIS COMPLETE ({elapsed}s)
{'═'*60}{mac_C.RST}
  {mac_C.RED}🔴 CRITICAL     : {len(results['critical'])}{mac_C.RST}
  {mac_C.YEL}🟠 HIGH         : {len(results['high'])}{mac_C.RST}
  {mac_C.BLU}🔵 MEDIUM       : {len(results['medium'])}{mac_C.RST}
  {mac_C.CYN}🌐 EXT IPs      : {len(results['external_ips'])}{mac_C.RST}
  {mac_C.MAG}🚀 LAUNCH ITEMS : {len(results['launch_items'])}{mac_C.RST}
  {mac_C.RED}🧬 THREAT INTEL : {len(results['threat_intel'])}{mac_C.RST}
{mac_C.BOLD}{'═'*60}{mac_C.RST}
  📊 Dashboard : {html_path}
  📋 JSON      : {json_path}
  📄 CSV       : {csv_path}
{'═'*60}
""")
    if results["critical"]:
        print(f"{mac_C.RED}{mac_C.BOLD}🚨 TOP CRITICAL:{mac_C.RST}")
        for f in results["critical"][:8]:
            print(f"  • [{f['source']}] {f['desc'][:90]}")
    _fin = uni_cli_finish(out, "macos", args.base, html_path, getattr(args, "vt_key", None), getattr(args, "abuse_key", None))
    print(f"\n{mac_C.GRN}Report (PDF + DOCX + HTML): {Path(_fin).parent}{mac_C.RST}\n  open: firefox {_fin}\n")



# ══════════════════════════════════════════════════════════════════════════════
# PART B — WEB GUI  (forensics_master.py — embedded)
# ══════════════════════════════════════════════════════════════════════════════


import os, sys, re, json, struct, csv, io, uuid, shutil
import threading, time, subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════════
# STEP 0 — AUTO INSTALL DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════

def _install(pkg):
    subprocess.run([sys.executable, "-m", "pip", "install", pkg,
                    "--quiet", "--break-system-packages"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _ensure_deps():
    missing = []
    for mod, pip_name in [("flask","flask"), ("docx","python-docx"),
                           ("reportlab","reportlab")]:
        try: __import__(mod)
        except ImportError: missing.append(pip_name)
    if missing:
        print(f"[*] Installing: {', '.join(missing)} ...")
        for p in missing:
            _install(p)
        print("[+] Done.\n")

if not os.environ.get("FM_OFFLINE"):          # offline kit: never try to pip-install anything
    _ensure_deps()

try:
    from flask import Flask, render_template_string, request, jsonify, send_file
except ImportError:                            # offline acquisition kit does not need the GUI
    class Flask:
        def __init__(self, *a, **k): pass
        def route(self, *a, **k): return lambda f: f
        def run(self, *a, **k): raise SystemExit("Flask is not installed - the GUI is unavailable on this machine")
    render_template_string = request = jsonify = send_file = None


# ══════════════════════════════════════════════════════════════════════
# STEP 2 — REGISTRY HIVE PARSER (pure Python, no library needed)
# ══════════════════════════════════════════════════════════════════════

REGF_MAGIC = b'regf'
NK_MAGIC   = b'nk'
VK_MAGIC   = b'vk'

VALUE_TYPES = {
    0:'REG_NONE', 1:'REG_SZ', 2:'REG_EXPAND_SZ', 3:'REG_BINARY',
    4:'REG_DWORD', 5:'REG_DWORD_BIG_ENDIAN', 6:'REG_LINK',
    7:'REG_MULTI_SZ', 8:'REG_RESOURCE_LIST', 11:'REG_QWORD',
}

REG_PERSIST_KEYS = {
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run":                "CRITICAL",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce":            "CRITICAL",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx":          "CRITICAL",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon":        "HIGH",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options": "HIGH",
    r"SOFTWARE\Classes\exefile\shell\open\command":                  "CRITICAL",
    r"SYSTEM\CurrentControlSet\Services":                            "HIGH",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute": "CRITICAL",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run": "CRITICAL",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows":         "HIGH",
    r"SYSTEM\CurrentControlSet\Control\SafeBoot":                    "HIGH",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run":    "CRITICAL",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache": "HIGH",
    r"SYSTEM\CurrentControlSet\Control\Lsa":                        "HIGH",
    r"SOFTWARE\Policies\Microsoft\Windows\PowerShell":              "HIGH",
}

REG_SUSPICIOUS = [
    (re.compile(r'powershell.*-enc',   re.I), "PowerShell Encoded Command"),
    (re.compile(r'powershell.*bypass', re.I), "PowerShell Bypass"),
    (re.compile(r'mshta\.exe',         re.I), "MSHTA Execution"),
    (re.compile(r'wscript|cscript',    re.I), "Script Host"),
    (re.compile(r'regsvr32.*scrobj',   re.I), "Regsvr32 COM Scriptlet"),
    (re.compile(r'certutil.*-decode',  re.I), "Certutil Decode (Dropper)"),
    (re.compile(r'bitsadmin.*transfer',re.I), "BITSAdmin Transfer"),
    (re.compile(r'\\temp\\.*\.(exe|bat|vbs|ps1)',    re.I), "Exec from TEMP"),
    (re.compile(r'\\appdata\\.*\.(exe|bat|vbs|ps1)', re.I), "Exec from AppData"),
    (re.compile(r'mimikatz|sekurlsa|lsadump',        re.I), "Credential Dumping"),
    (re.compile(r'net user.*\/add',    re.I), "User Creation"),
    (re.compile(r'procdump.*lsass',    re.I), "LSASS Dump"),
]

IP_RE      = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
PRIV_RE    = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)')


def _ft_to_str(ft):
    try:
        ts = (ft - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return ''


def _decode_reg_val(vtype, data):
    try:
        if vtype in (1, 2): return data.decode('utf-16-le', errors='replace').rstrip('\x00')
        if vtype == 4:  return str(struct.unpack_from('<I', data)[0]) if len(data) >= 4 else ''
        if vtype == 11: return str(struct.unpack_from('<Q', data)[0]) if len(data) >= 8 else ''
        if vtype == 7:  return ' | '.join(data.decode('utf-16-le', errors='replace').rstrip('\x00').split('\x00'))
        return data.hex()[:80]
    except: return ''


class _RegfParser:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        self.base = 0x1000

    def _cell(self, off):
        a = self.base + off
        if a + 4 > len(self.data): return 0, b''
        sz = struct.unpack_from('<i', self.data, a)[0]
        sz = -sz if sz < 0 else sz
        return sz, self.data[a+4:a+sz]

    def walk(self):
        if len(self.data) < 0x1020 or self.data[:4] != REGF_MAGIC: return
        root = struct.unpack_from('<I', self.data, 0x24)[0]
        yield from self._nk(root, '')

    def _nk(self, off, path):
        sz, cell = self._cell(off)
        if len(cell) < 72 or cell[:2] != NK_MAGIC: return
        flags    = struct.unpack_from('<H', cell, 2)[0]
        lw       = _ft_to_str(struct.unpack_from('<Q', cell, 4)[0])
        nval     = struct.unpack_from('<I', cell, 36)[0]
        vlist    = struct.unpack_from('<i', cell, 40)[0]
        nsub     = struct.unpack_from('<I', cell, 16)[0]
        subs     = struct.unpack_from('<i', cell, 20)[0]
        nlen     = struct.unpack_from('<H', cell, 72)[0]
        noff     = self.base + off + 4 + 76
        raw      = self.data[noff:noff+nlen]
        kname    = raw.decode('ascii','replace') if flags & 0x20 else raw.decode('utf-16-le','replace')
        kpath    = (path + '\\' + kname).lstrip('\\')

        if nval > 0 and vlist > 0:
            try:
                _, vc = self._cell(vlist)
                for i in range(min(nval, 500)):
                    if i*4+4 > len(vc): break
                    vk = struct.unpack_from('<i', vc, i*4)[0]
                    if vk <= 0: continue
                    _, v = self._cell(vk)
                    if len(v) < 16 or v[:2] != VK_MAGIC: continue
                    vnl  = struct.unpack_from('<H', v, 2)[0]
                    dlen = struct.unpack_from('<I', v, 4)[0]
                    doff = struct.unpack_from('<i', v, 8)[0]
                    vt   = struct.unpack_from('<I', v, 12)[0]
                    vfl  = struct.unpack_from('<H', v, 16)[0]
                    vnr  = self.data[self.base+vk+4+20:self.base+vk+4+20+vnl]
                    vn   = (vnr.decode('ascii','replace') if vfl & 1 else vnr.decode('utf-16-le','replace')) or '(Default)'
                    if dlen & 0x80000000:
                        rd = struct.pack('<I', doff)[:dlen & 0x7FFFFFFF]
                    else:
                        _, dc = self._cell(doff); rd = dc[:dlen]
                    yield kpath, vn, VALUE_TYPES.get(vt, str(vt)), _decode_reg_val(vt, rd), lw
            except: pass

        if nsub > 0 and subs > 0:
            try:
                _, sc = self._cell(subs)
                if len(sc) < 2: return
                sig = sc[:2]
                if sig in (b'lf', b'lh'):
                    cnt = struct.unpack_from('<H', sc, 2)[0]
                    for i in range(min(cnt, 1000)):
                        if 4+i*8+4 > len(sc): break
                        so = struct.unpack_from('<i', sc, 4+i*8)[0]
                        if so > 0: yield from self._nk(so, kpath)
                elif sig == b'ri':
                    cnt = struct.unpack_from('<H', sc, 2)[0]
                    for i in range(min(cnt, 500)):
                        if 4+i*4+4 > len(sc): break
                        so = struct.unpack_from('<i', sc, 4+i*4)[0]
                        if so > 0:
                            _, sc2 = self._cell(so)
                            if sc2[:2] in (b'lf', b'lh'):
                                cnt2 = struct.unpack_from('<H', sc2, 2)[0]
                                for j in range(min(cnt2, 1000)):
                                    if 4+j*8+4 > len(sc2): break
                                    so2 = struct.unpack_from('<i', sc2, 4+j*8)[0]
                                    if so2 > 0: yield from self._nk(so2, kpath)
            except: pass


def _analyze_hive(hive_path):
    hive_path = Path(hive_path)
    findings, stats = [], {
        'hive': hive_path.name, 'size_kb': hive_path.stat().st_size // 1024,
        'total_values': 0, 'critical': 0, 'high': 0, 'medium': 0, 'external_ips': [],
    }
    try:
        for kpath, vname, vtype, vdata, lw in _RegfParser(hive_path).walk():
            stats['total_values'] += 1
            sev, pat = None, None
            for pk, ps in REG_PERSIST_KEYS.items():
                if re.search(pk, kpath, re.I): sev = ps; break
            for rx, pn in REG_SUSPICIOUS:
                if rx.search(vdata): pat = pn; sev = 'CRITICAL'; break
            if sev:
                stats[sev.lower()] = stats.get(sev.lower(), 0) + 1
                findings.append({'severity': sev, 'hive': hive_path.stem.upper(),
                    'key': kpath, 'name': vname, 'type': vtype,
                    'data': vdata[:400], 'last_written': lw, 'pattern': pat})
            for ip in IP_RE.findall(vdata):
                if not PRIV_RE.match(ip) and ip not in stats['external_ips']:
                    stats['external_ips'].append(ip)
    except Exception as e:
        findings.append({'severity':'INFO','hive':hive_path.name,'key':'PARSE_ERROR',
                         'name':'','type':'','data':str(e),'last_written':'','pattern':None})
    return {'findings': findings, 'stats': stats, 'hive_path': str(hive_path)}


def _analyze_reg_folder(folder):
    folder = Path(folder)
    HIVE_NAMES = {'NTUSER.DAT','SAM','SYSTEM','SOFTWARE','SECURITY','DEFAULT','USRCLASS.DAT','BCD'}
    found = []
    for f in folder.rglob('*'):
        if not f.is_file(): continue
        if f.name.upper() in HIVE_NAMES: found.append(f); continue
        if f.suffix.lower() in ('.hiv','.hive','') and f.stat().st_size > 4096:
            try:
                with open(f,'rb') as fh:
                    if fh.read(4) == REGF_MAGIC: found.append(f)
            except: pass
    return [_analyze_hive(h) for h in found]


# ══════════════════════════════════════════════════════════════════════
# STEP 3 — REPORT GENERATION (DOCX + PDF)
# ══════════════════════════════════════════════════════════════════════

def _make_docx(results, summary, out_dir, os_type, evidence, mem=None, extra=None):
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    doc = Document()
    for s in doc.sections:
        s.top_margin = s.bottom_margin = Inches(1)
        s.left_margin = s.right_margin = Inches(1.2)

    def h(txt, lvl=1):
        hd = doc.add_heading(txt, level=lvl)
        if lvl == 1 and hd.runs:
            hd.runs[0].font.color.rgb = RGBColor(0x1e, 0x3a, 0x5f)
        return hd

    def tbl(headers, rows, maxr=200):
        if not rows: doc.add_paragraph("No entries."); return
        t = doc.add_table(rows=1, cols=len(headers)); t.style = 'Table Grid'
        hr = t.rows[0]
        for i, hd in enumerate(headers):
            c = hr.cells[i]; c.text = hd
            for r in c.paragraphs[0].runs:
                r.bold = True; r.font.size = Pt(9)
                r.font.color.rgb = RGBColor(0xFF,0xFF,0xFF)
            tc = c._tc; p = tc.get_or_add_tcPr()
            sh = OxmlElement('w:shd')
            sh.set(qn('w:fill'),'1e3a5f'); sh.set(qn('w:val'),'clear')
            p.append(sh)
        for row in rows[:maxr]:
            tr = t.add_row()
            for i, v in enumerate(row):
                tr.cells[i].text = str(v)[:300]
                for r in tr.cells[i].paragraphs[0].runs:
                    r.font.size = Pt(8)

    doc.add_heading("🛡 Forensics Investigation Report", 0)
    doc.add_paragraph(f"OS: {os_type.upper()}  |  Evidence: {evidence}  |  Generated: {datetime.now():%Y-%m-%d %H:%M:%S}")
    doc.add_page_break()

    h("1. Executive Summary")
    c,hi,m = summary.get('critical',0), summary.get('high',0), summary.get('medium',0)
    lvl = "CRITICAL" if c else "HIGH" if hi else "MEDIUM" if m else "LOW"
    p = doc.add_paragraph(); p.add_run("Risk Level: ").bold = True
    run = p.add_run(lvl); run.bold = True
    run.font.color.rgb = {"CRITICAL":RGBColor(0xf8,0x51,0x49),"HIGH":RGBColor(0xf9,0x73,0x16),
                          "MEDIUM":RGBColor(0xe3,0xb3,0x41),"LOW":RGBColor(0x3f,0xb9,0x50)}[lvl]
    tbl(["Metric","Value"], mem['summary_rows'] if mem else [
        ["Critical",str(c)],["High",str(hi)],["Medium",str(m)],
        ["Timeline Events",str(summary.get('total_events',0))],
        ["External IPs",str(summary.get('external_ips',0))],
        ["EDR Hits",str(summary.get('cisco_hits',0))],
        ["Hayabusa Hits",str(summary.get('hayabusa_hits',0))],
        ["Analysis Time",summary.get('analysis_time','N/A')],
    ])

    if mem:
        for _i, (_t, _hd, _rw) in enumerate(mem['sections']):
            if _i == 0: doc.add_page_break()
            h(f"{_i+2}. {_t}")
            if len(_rw) > 300: doc.add_paragraph(f"Showing first 300 of {len(_rw)} rows (full output in the volatility/ folder).")
            tbl(_hd, _rw, maxr=300)
    else:
        doc.add_page_break(); h("2. Critical Findings")
        tbl(["Timestamp","Source","Description","Data"],
            [(f.get('timestamp','')[:19],f.get('source',''),f.get('desc',''),str(f.get('data',''))[:200])
             for f in results.get('critical',[])])

        doc.add_page_break(); h("3. Attack Timeline")
        tbl(["Time","Severity","Source","Description","Detail"],
            [(e.get('ts','')[:19],e.get('sev',''),e.get('src',''),e.get('desc',''),e.get('det','')[:150])
             for e in results.get('timeline',[])])

        doc.add_page_break(); h("4. Network & C2 Indicators")
        h("External IPs",2)
        tbl(["IP"],[[ip] for ip in sorted(results.get('external_ips',[]))[:200]])
        h("C2 Indicators",2)
        tbl(["Type","IP/Domain","Port","Detail"],
            [(c.get('type',''),c.get('ip',''),str(c.get('port','')),c.get('detail','')[:150])
             for c in results.get('c2_indicators',[])])

        if results.get('registry_hits'):
            doc.add_page_break(); h("5. Registry Persistence")
            tbl(["Severity","Hive","Key","Value Name","Value Data"],
                [(r.get('severity',''),r.get('hive',''),r.get('key','')[:80],
                  r.get('name',''),r.get('data','')[:120])
                 for r in results['registry_hits']])

        if results.get('hayabusa'):
            doc.add_page_break(); h("6. Hayabusa EVTX Analysis")
            tbl(["Severity","Rule","Timestamp","Detail"],
                [(x.get('severity',''),x.get('rule',''),x.get('timestamp','')[:19],str(x.get('detail',''))[:200])
                 for x in results['hayabusa']])

    if extra:
        doc.add_page_break()
        for _t, _hd, _rw in extra:
            h(_t)
            tbl(_hd, _rw, maxr=300)
    doc.add_page_break(); h("Report Info")
    doc.add_paragraph(f"Generated by: Forensics Master Analyzer\nDate: {datetime.now():%Y-%m-%d %H:%M:%S}\nEvidence: {evidence}")

    out = Path(out_dir) / "forensics_report.docx"
    doc.save(str(out))
    return str(out)


def _make_pdf(results, summary, out_dir, os_type, evidence, mem=None, extra=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, PageBreak)

    out = str(Path(out_dir) / "forensics_report.pdf")
    doc = SimpleDocTemplate(out, pagesize=A4,
                             leftMargin=2.5*cm, rightMargin=2.5*cm,
                             topMargin=2.5*cm, bottomMargin=2.5*cm)
    S  = getSampleStyleSheet()
    T  = ParagraphStyle('T', parent=S['Title'],  fontSize=22, textColor=colors.HexColor('#1e3a5f'))
    H1 = ParagraphStyle('H1',parent=S['Heading1'],fontSize=15,textColor=colors.HexColor('#1e3a5f'),spaceBefore=16)
    H2 = ParagraphStyle('H2',parent=S['Heading2'],fontSize=12,textColor=colors.HexColor('#334155'),spaceBefore=12)
    B  = ParagraphStyle('B', parent=S['Normal'], fontSize=9, leading=14)
    HDR = colors.HexColor('#1e3a5f')

    def mtbl(headers, rows, cw=None, mx=200):
        if not rows: return Paragraph("No entries.", B)
        from xml.sax.saxutils import escape as _esc
        _cs = ParagraphStyle('cell', parent=B, fontSize=7, leading=8.5)
        data = [headers] + [[Paragraph(_esc(str(c)[:200]), _cs) for c in r] for r in rows[:mx]]
        if not cw: cw = [16.5*cm/len(headers)]*len(headers)
        t = Table(data, colWidths=cw, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),HDR),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),8),
            ('FONTSIZE',(0,1),(-1,-1),7.5),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f8fafc')]),
            ('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#e2e8f0')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ]))
        return t

    c,hi = summary.get('critical',0), summary.get('high',0)
    lvl = "🔴 CRITICAL" if c else "🟠 HIGH" if hi else "🟡 MEDIUM" if summary.get('medium',0) else "🟢 LOW"
    story = [
        Spacer(1,2*cm), Paragraph("🛡 Forensics Investigation Report",T),
        Paragraph(f"<b>OS:</b> {os_type.upper()}  |  <b>Evidence:</b> {evidence}",B),
        Paragraph(f"<b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M:%S}",B),
        Paragraph(f"<b>Risk Level: {lvl}</b>",ParagraphStyle('RL',parent=B,fontSize=12)),
        PageBreak(),
    ]
    story += [
        Paragraph("1. Executive Summary",H1),
        mtbl(["Metric","Value"], mem['summary_rows'] if mem else [
            ["Critical",str(c)],["High",str(hi)],
            ["Medium",str(summary.get('medium',0))],
            ["Timeline Events",str(summary.get('total_events',0))],
            ["External IPs",str(summary.get('external_ips',0))],
            ["EDR Hits",str(summary.get('cisco_hits',0))],
            ["Analysis Time",summary.get('analysis_time','N/A')],
        ],cw=[9*cm,7.5*cm]),
        Spacer(1,0.3*cm),
    ]
    if mem:
        for _i, (_t, _hd, _rw) in enumerate(mem['sections']):
            story += [PageBreak() if _i == 0 else Spacer(1,0.4*cm), Paragraph(f"{_i+2}. {_t}", H1)]
            if len(_rw) > 300: story.append(Paragraph(f"Showing first 300 of {len(_rw)} rows (full output in the volatility/ folder).", B))
            story.append(mtbl(_hd, _rw, mx=300))
    else:
        story += [PageBreak(),
        Paragraph("2. Critical Findings",H1),
        mtbl(["Timestamp","Source","Description","Data"],
            [(f.get('timestamp','')[:19],f.get('source',''),f.get('desc',''),str(f.get('data',''))[:150])
             for f in results.get('critical',[])],
            cw=[3.5*cm,2.5*cm,5.5*cm,5*cm]),
        PageBreak(),
        Paragraph("3. Attack Timeline",H1),
        mtbl(["Time","Sev","Source","Description","Detail"],
            [(e.get('ts','')[:19],e.get('sev',''),e.get('src',''),e.get('desc',''),e.get('det','')[:120])
             for e in results.get('timeline',[])],
            cw=[3.2*cm,1.8*cm,2.5*cm,4.5*cm,4.5*cm]),
        PageBreak(),
        Paragraph("4. Network Indicators",H1),
        Paragraph("External IPs",H2),
        mtbl(["IP"],[[ip] for ip in sorted(results.get('external_ips',[]))[:200]],cw=[16.5*cm]),
        ]

    if results.get('registry_hits') and not mem:
        story += [PageBreak(), Paragraph("5. Registry Persistence",H1),
            mtbl(["Severity","Hive","Key","Value","Data"],
                [(r.get('severity',''),r.get('hive',''),r.get('key','')[:60],
                  r.get('name',''),r.get('data','')[:100]) for r in results['registry_hits']],
                cw=[2.2*cm,2.5*cm,5*cm,3*cm,3.8*cm])]

    if results.get('hayabusa') and not mem:
        story += [PageBreak(), Paragraph("6. Hayabusa Detections",H1),
            mtbl(["Severity","Rule","Timestamp","Detail"],
                [(x.get('severity',''),x.get('rule',''),x.get('timestamp','')[:19],str(x.get('detail',''))[:200])
                 for x in results['hayabusa']],
                cw=[2.2*cm,5*cm,3.5*cm,5.8*cm])]

    if extra:
        story.append(PageBreak())
        for _t, _hd, _rw in extra:
            story += [Paragraph(_t, H1), mtbl(_hd, _rw, mx=300), Spacer(1, 0.4*cm)]
    story += [PageBreak(), Paragraph("Report Information",H1),
        Paragraph(f"Forensics Master Analyzer | {datetime.now():%Y-%m-%d %H:%M:%S} | {evidence}",B)]
    doc.build(story)
    return out


# ══════════════════════════════════════════════════════════════════════
# STEP 4 — JOB RUNNER
# ══════════════════════════════════════════════════════════════════════

OUTPUT_BASE = Path.home() / "forensics_output"
OUTPUT_BASE.mkdir(parents=True, exist_ok=True)


def _safe_case(name):
    n = re.sub(r"[^\w.\- ]+", "_", (name or "").strip()).strip(" ._")
    return re.sub(r"\s+", "_", n)[:80]


def _unique_dir(path):
    """Use the folder as-is if it is new/empty, else add _2, _3 ... so earlier cases are never overwritten."""
    path = Path(path)
    if not path.exists() or not any(path.iterdir()): return path
    i = 2
    while Path(f"{path}_{i}").exists() and any(Path(f"{path}_{i}").iterdir()): i += 1
    return Path(f"{path}_{i}")
JOBS = {}


class JobStopped(BaseException):
    """Raised inside a job thread when user presses Stop (BaseException so
    broad `except Exception` blocks in analyzers cannot swallow it)."""


def _kill_children(job):
    """Kill the job's tracked process group + any child processes of this server."""
    import signal
    for proc in list(job.get('procs') or []) + ([job['proc']] if job.get('proc') else []):
        if proc and proc.poll() is None:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try: proc.kill()
                except Exception: pass
    try:
        import psutil
        for ch in psutil.Process(os.getpid()).children(recursive=True):
            try: ch.kill()
            except Exception: pass
    except ImportError:
        try: subprocess.run(['pkill', '-KILL', '-P', str(os.getpid())],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except Exception: pass


def _stop_job(job):
    import ctypes
    job['cancel'] = True
    job['log'].append("[!] ⛔ Stop requested by user — terminating…")
    _kill_children(job)
    th = job.get('thread')
    if th and th.is_alive():
        ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_ulong(th.ident), ctypes.py_object(JobStopped))
    job['status'] = 'stopped'


def _ai_args(cfg):
    """CLI flags for the Windows analysis (provider + key)."""
    prov, key = cfg.get('ai_provider', 'none'), (cfg.get('ai_key') or '').strip()
    if prov in (None, '', 'none'): return ["--no-review"]
    a = ["--engine", 'anthropic' if (prov == 'auto' and key.startswith('sk-ant')) else prov, "--non-interactive"]
    if prov == 'anthropic' or (prov == 'auto' and key.startswith('sk-ant')): a += ["--engine-key", key]
    elif prov == 'gemini' or (prov == 'auto' and key): a += ["--gemini-key", key]
    if prov == 'auto' and not key: a[1] = 'auto'
    return a


def _ai_cfg_for(cfg, L):
    """Resolve the analyst engine for the web memory pipeline (installs/starts Ollama if needed)."""
    prov, key = cfg.get('ai_provider', 'none'), (cfg.get('ai_key') or '').strip()
    if prov in (None, '', 'none'): return None
    if prov == 'ollama' or (prov == 'auto' and not key):
        L("HEAD", "Analyst engine requirement check: Ollama")
        if not epr_ensure_ollama_ready(epr_OLLAMA_MODEL_DEFAULT, L, auto_yes=True):
            L("WARN", "Ollama is not ready - the analyst review will be skipped"); return None
    elif not key:
        L("WARN", f"Provider '{prov}' was selected but no API key was given - the analyst review will be skipped"); return None
    kw = {}
    if prov == 'anthropic' or (prov == 'auto' and key.startswith('sk-ant')): kw['anthropic_key'] = key
    elif prov in ('gemini', 'auto') and key: kw['gemini_key'] = key
    return epr_resolve_ai_cfg(L, prov, **kw)


def _vol_table(path):
    """Parse a Volatility3 text (tab separated) output file -> (header, rows)."""
    try: lines = Path(path).read_text(errors='ignore').splitlines()
    except Exception: return [], []
    hdr, rows = None, []
    for ln in lines:
        if '\t' not in ln: continue
        parts = [x.strip() for x in ln.split('\t')]
        if hdr is None: hdr = parts
        else: rows.append(parts)
    return hdr or [], rows


def _pick(hdr, rows, wanted):
    """Select columns by (case-insensitive) header name; returns (headers, rows)."""
    low = [h.lower() for h in hdr]
    idx = [(low.index(w.lower()), w) for w in wanted if w.lower() in low]
    if not idx: return [], []
    return [hdr[i] for i, _ in idx], [[r[i] if i < len(r) else '' for i, _ in idx] for r in rows]


def _collect(paths, wanted):
    """Merge several Volatility outputs of the same plugin -> (header, rows), rows fitted to header."""
    hdr, rows = [], []
    for f in paths:
        h_, r_ = _vol_table(f)
        hh, rr = _pick(h_, r_, wanted)
        if not hh: continue
        if not hdr: hdr = hh
        if hh == hdr: rows += [(r + [''] * len(hdr))[:len(hdr)] for r in rr]
    return hdr, rows


def _is_external_ip(v):
    import ipaddress
    try:
        ip = ipaddress.ip_address(v.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)
    except Exception:
        return False


def _mem_report_data(job):
    """Build memory-report sections from the saved Volatility outputs."""
    m = job.get('mem') or {}
    vol = Path(m.get('vol_out', ''))
    findings = m.get('findings', [])
    sections, counts = [], {}
    stems = m.get('dumps') or []

    def files(plugin):
        out = []
        for st in stems:
            out += sorted(vol.glob(f"{st}_{plugin}*.txt"))
        return out

    # findings
    fr = [[f.get('severity', ''), f.get('plugin', ''), str(f.get('line', ''))[:220]] for f in findings]
    fr.sort(key=lambda r: {'CRITICAL': 0, 'HIGH': 1}.get(r[0], 2))
    sections.append(("Suspicious Findings", ["Severity", "Plugin", "Detail"], fr))

    # image info
    for f in files('info'):
        h_, r_ = _vol_table(f)
        if r_: sections.append(("Memory Image Info", (h_ + ['', ''])[:2], [(x + ['', ''])[:2] for x in r_][:40])); break

    # processes (sorted by creation time)
    phdr, procs = _collect(files('pslist'), ['PID', 'PPID', 'ImageFileName', 'Threads', 'SessionId', 'CreateTime', 'ExitTime'])
    counts['processes'] = len(procs)
    if procs:
        lowp = [h.lower() for h in phdr]
        if 'createtime' in lowp:
            ci = lowp.index('createtime')
            procs.sort(key=lambda r: r[ci] if r[ci] not in ('', 'N/A', '-') else '9')
        sections.append(("Processes (by creation time)", phdr, procs))

    # command lines
    chdr, cmds = _collect(files('cmdline'), ['PID', 'Process', 'Args'])
    if cmds: sections.append(("Command Lines", chdr, cmds))

    # network
    nhdr, conns = _collect(files('netscan') + files('netstat'),
                           ['Proto', 'LocalAddr', 'LocalPort', 'ForeignAddr', 'ForeignPort', 'State', 'PID', 'Owner', 'Created'])
    seen, uniq = set(), []
    for r in conns:
        k = tuple(r[:8])
        if k not in seen: seen.add(k); uniq.append(r)
    counts['connections'] = len(uniq)
    counts['external'] = 0
    if uniq:
        lown = [h.lower() for h in nhdr]
        if 'foreignaddr' in lown:
            fi = lown.index('foreignaddr')
            ext = [r for r in uniq if _is_external_ip(r[fi])]
            counts['external'] = len(ext)
            if ext: sections.append(("External Network Connections", nhdr, ext))
        sections.append(("All Network Connections", nhdr, uniq))

    # malfind
    mhdr, mf = _collect(files('malfind'), ['PID', 'Process', 'Start VPN', 'End VPN', 'Protection', 'CommitCharge'])
    counts['malfind'] = len(mf)
    if mf: sections.append(("Injected / Suspicious Memory Regions (malfind)", mhdr, mf))

    # services
    shdr, sv = _collect(files('svcscan'), ['Name', 'Display', 'State', 'Start', 'Binary', 'Pid'])
    counts['services'] = len(sv)
    if sv: sections.append(("Services", shdr, sv))

    # registry autoruns
    khdr, rk = _collect(files('printkey'), ['Last Write Time', 'Key', 'Name', 'Data'])
    counts['runkeys'] = len(rk)
    if rk: sections.append(("Registry Autorun / Service Keys", khdr, rk))

    crit = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    summary_rows = [
        ["Memory dump(s)", ", ".join(stems) or '-'], ["Target OS", str(m.get('os', ''))],
        ["Plugins run", str(m.get('plugins', 0))],
        ["Critical findings", str(crit)], ["High findings", str(high)],
        ["Processes", str(counts.get('processes', 0))],
        ["Network connections", f"{counts.get('connections', 0)} (external: {counts.get('external', 0)})"],
        ["Malfind regions", str(counts.get('malfind', 0))],
        ["Services", str(counts.get('services', 0))],
        ["Autorun/service registry entries", str(counts.get('runkeys', 0))],
    ]
    return {'sections': sections, 'summary_rows': summary_rows}


def _gen_report(jid):
    """Build DOCX + PDF (grouped, de-duplicated, narrative report model)."""
    job = JOBS[jid]
    job['report_state'] = 'generating'; job['report_error'] = ''
    try:
        out = job['output_dir']
        osx = job.get('os_type')
        def _load(name):
            try: return json.loads(Path(out, name).read_text(encoding='utf-8'))
            except Exception: return None
        data = _load('report_data.json')
        if not data:                                    # fall back to dashboard-derived results
            r = job.get('results') or {}
            data = {'critical': [{'severity': 'CRITICAL', 'source': f.get('source', ''), 'desc': f.get('desc', ''), 'ts': f.get('ts', ''), 'data': f.get('detail', '')} for f in r.get('critical', [])],
                    'high': [{'severity': 'HIGH', 'source': f.get('source', ''), 'desc': f.get('desc', ''), 'ts': f.get('ts', ''), 'data': f.get('detail', '')} for f in r.get('high', [])],
                    'medium': [], 'timeline': r.get('timeline', []), 'external_ips': r.get('external_ips', []),
                    'registry_hits': r.get('registry_hits', []), 'c2_indicators': r.get('c2_indicators', [])}
        mem_secs = None
        if osx == 'memory':
            md = _mem_report_data(job)
            mem_secs = md['sections']
            fm = job.get('mem', {}).get('findings', [])
            data = {'critical': [{'severity': 'CRITICAL', 'source': f['plugin'], 'desc': f['line'][:160], 'ts': '', 'data': ''} for f in fm if f['severity'] == 'CRITICAL'],
                    'high': [{'severity': 'HIGH', 'source': f['plugin'], 'desc': f['line'][:160], 'ts': '', 'data': ''} for f in fm if f['severity'] == 'HIGH'],
                    'medium': [], 'timeline': [], 'external_ips': [], 'registry_hits': [], 'c2_indicators': []}
            mem_secs = [x for x in mem_secs if x[0] != 'Suspicious Findings']
        cor = _load('correlation.json')
        csecs = job.get('cor_sections') or _load('correlation_sections.json') or []
        review = job.get('review_text')
        if not review:
            try: review = Path(out, 'analyst_review.txt').read_text(encoding='utf-8')
            except Exception: review = None
        if review and not uni_review_ok(review): review = None
        case = job.get('case')
        stem = f"{case}_report" if case else "forensics_report"
        scope = _load('scope.json')
        blocks = rpt_blocks(osx, job['evidence'], data, job.get('summary') or {}, csecs, review, cor, mem_secs, case=case, scope=scope)
        job['docx_path'] = rpt_docx(blocks, out, stem)
        job['pdf_path'] = rpt_pdf(blocks, out, stem)
        job['report_state'] = 'ready'
        job['log'].append("[+] Report ready - download it from the Reporting tab.")
    except Exception as e:
        import traceback
        job['report_state'] = 'error'; job['report_error'] = str(e)[:200]
        job['log'].append(f"[x] Report failed: {e}")
        job['log'].append(traceback.format_exc()[-400:])


def _run_job(job_id, cfg):
    job = JOBS[job_id]
    log = job['log']

    def L(lvl, msg):
        icons = {"OK":"[+]","WARN":"[!]","ERR":"[✗]","HEAD":"[■]","INFO":"[*]","CRIT":"[!!!]"}
        log.append(f"{icons.get(lvl,'[?]')} {msg}")

    try:
        UNI_CTX['web'] = True
        UNI_CTX['denied'] = []
        os_type  = cfg['os_type']
        evidence = cfg['evidence']
        try:
            if os_type != 'memory':
                _nb, _ex = uni_unreadable(evidence)
                if _nb:
                    L("WARN", f"{_nb} evidence file(s) cannot be read by this user (e.g. {_ex[0]}) - they will be skipped. Fix: start the tool as Administrator / with sudo, "
                              f"or run:  {uni_fix_command(evidence)}")
        except Exception: pass
        case = _safe_case(cfg.get('case_name'))
        if case:
            _base = Path(cfg['output']).expanduser() if cfg.get('output') else OUTPUT_BASE
            output = str(_unique_dir(_base / case))
            job['case'] = case
            L('INFO', f'Case "{case}" -> saving to {output}')
        else:
            output = cfg.get('output') or str(OUTPUT_BASE / job_id)
        Path(output).mkdir(parents=True, exist_ok=True)
        job.update({'output_dir': output, 'status': 'running',
                    'os_type': os_type, 'evidence': evidence})

        L("HEAD", f"Starting {os_type.upper()} analysis")
        L("INFO",  f"Evidence : {evidence}")
        L("INFO",  f"Output   : {output}")

        argv = ["--base", evidence, "--output", output]
        if os_type in ('windows', 'linux', 'kali', 'macos'):
            if cfg.get('ai_provider') == 'ollama' or (cfg.get('ai_provider') == 'auto' and not cfg.get('ai_key')):
                _ai_cfg_for(cfg, L)          # install / start Ollama + pull model if missing
            argv += _ai_args(cfg)
        if cfg.get('vt_key'):     argv += ["--vt-key",    cfg['vt_key']]
        if cfg.get('abuse_key'):  argv += ["--abuse-key", cfg['abuse_key']]
        if cfg.get('skip_setup'): argv += ["--skip-setup"]
        if cfg.get('skip_memory'):argv += ["--skip-memory"]

        class _Tee:
            def write(self, d):
                for line in d.splitlines():
                    if line.strip(): log.append(line)
            def flush(self): pass

        tee = _Tee()
        from contextlib import redirect_stdout, redirect_stderr
        with redirect_stdout(tee), redirect_stderr(tee):
            try:
                if os_type == 'memory':
                    # ── Dedicated Memory-Only Analysis (Volatility3) ──────────
                    mem_path = cfg.get('memory_path', evidence)
                    mem_os   = cfg.get('memory_os', 'windows')
                    L("HEAD", "🧠 Memory-Only Analysis Mode")
                    L("INFO", f"Dump path : {mem_path}")
                    L("INFO", f"Target OS : {mem_os}")
                    # Install volatility3 if needed
                    vol_bin = shutil.which('vol') or shutil.which('vol3') or shutil.which('volatility3')
                    if not vol_bin:
                        L("INFO", "Volatility3 not found — installing...")
                        subprocess.run([sys.executable,'-m','pip','install','volatility3',
                                        '--break-system-packages','-q'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        vol_bin = shutil.which('vol') or shutil.which('vol3') or 'vol'
                        L("OK", f"Volatility3 installed → {vol_bin}")
                    # Find dump files
                    mem_p = Path(mem_path)
                    if mem_p.is_file():
                        dumps = [mem_p]
                    else:
                        dumps = []
                        for ext in ['*.raw','*.dmp','*.vmem','*.mem','*.lime','*.bin']:
                            dumps += [p for p in mem_p.rglob(ext)
                                      if p.stat().st_size > 1024*1024]
                    if not dumps:
                        L("ERR", f"No memory dump found: {mem_path}")
                        L("WARN", "Expected: .raw .dmp .vmem .mem .lime .bin (>1MB)")
                        job['status'] = 'error'; return
                    L("OK", f"{len(dumps)} dump(s) mila:")
                    for d in dumps:
                        L("INFO", f"  {d.name}  ({d.stat().st_size//1024//1024} MB)")
                    vol_out = Path(output) / "volatility"
                    vol_out.mkdir(parents=True, exist_ok=True)
                    # Plugin sets
                    win_plugins = [
                        "windows.info","windows.pslist","windows.pstree","windows.psxview",
                        "windows.cmdline","windows.netscan","windows.netstat",
                        "windows.malfind","windows.dlllist","windows.handles",
                        "windows.svcscan","windows.registry.hivelist",
                        'windows.registry.printkey --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
                        'windows.registry.printkey --key "SYSTEM\\CurrentControlSet\\Services"',
                    ]
                    lin_plugins = [
                        "linux.pslist","linux.pstree","linux.bash","linux.check_syscall",
                        "linux.lsmod","linux.netfilter","linux.sockstat","linux.malfind",
                        "linux.check_creds",
                    ]
                    plugins = win_plugins if mem_os == 'windows' else lin_plugins
                    findings_mem = []
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    # ---- worker count: bounded by CPU and free RAM (each vol3 proc can use GBs)
                    _cpu = os.cpu_count() or 2
                    _w = min(4, _cpu)
                    try:
                        import psutil
                        _w = max(1, min(_w, int(psutil.virtual_memory().available / (2 * 1024**3))))
                    except Exception: pass
                    L("INFO", f"Parallel Volatility workers: {_w}")
                    _eng = _ai_cfg_for(cfg, L)
                    _live = AnalystLive(_eng, L) if _eng else None
                    BAD_RE = re.compile(r'(?<![A-Za-z0-9_])(mimikatz|meterpreter|pwdump|netcat|(?:nc|ncat|wce|procdump(?:64)?|psexec(?:svc)?|lazagne|rubeus|sharphound|cobaltstrike)\.exe)(?![A-Za-z0-9_])', re.I)
                    CMD_RE = re.compile(r'(vssadmin[^\n]*delete[^\n]*shadows|wmic[^\n]*shadowcopy[^\n]*delete|bcdedit[^\n]*(recoveryenabled|bootstatuspolicy)|wbadmin[^\n]*delete|cipher[^\n]*/w|wevtutil[^\n]*\bcl\b|powershell[^\n]*(-enc\b|-encodedcommand|downloadstring|invoke-expression|iex\b)|certutil[^\n]*(-urlcache|-decode)|mshta[^\n]*(http|javascript)|rundll32[^\n]*javascript|schtasks[^\n]*/create|net\s+user[^\n]*/add)', re.I)
                    # slow plugins are queued first so they overlap with the quick ones
                    HEAVY = ('handles', 'dlllist', 'psxview', 'malfind', 'netscan', 'svcscan')

                    def run_plugin(dump, plugin):
                        pname = plugin.split()[0].split('.')[-1]
                        _km = re.search(r'--key "([^"]+)"', plugin)
                        if _km: pname += '_' + re.split(r'[\\/]', _km.group(1))[-1]   # unique file per registry key
                        out_file = vol_out / f"{dump.stem}_{pname}.txt"
                        cmd = f'{vol_bin} -q -f "{dump}" {plugin}'
                        # generous per-plugin timeout: heavy plugins (malfind etc.) can take very long on big dumps
                        _tmo = int(os.environ.get('VOL_TIMEOUT', 0)) or (7200 if any(h in plugin for h in HEAVY) else 1800)
                        try:
                            if job.get('cancel'): return
                            L("INFO", f"  [{pname}]...")
                            _pr = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, text=True,
                                                   start_new_session=True)
                            job.setdefault('procs', []).append(_pr)
                            try:
                                _o, _e = _pr.communicate(timeout=_tmo)
                            except subprocess.TimeoutExpired:
                                _kill_children(job); _pr.communicate(); raise
                            if job.get('cancel'): return
                            txt = (_o or '').strip()
                            if not txt:
                                L("INFO", f"  [{pname}] no output (normal if not applicable)")
                                return
                            out_file.write_text(txt, encoding='utf-8', errors='replace')
                            lines_out = txt.splitlines()
                            for ln in lines_out[1:min(6,len(lines_out))]:
                                if ln.strip(): L("INFO", f"    [{pname}] {ln.rstrip()}")
                            _hits, _seen = 0, set()
                            for ln in lines_out:
                                if _hits >= 25: break
                                _ln = ln.strip()
                                if not _ln or _ln in _seen: continue
                                if BAD_RE.search(_ln):
                                    _seen.add(_ln); _hits += 1
                                    findings_mem.append({'plugin':pname,'line':_ln[:300],'severity':'CRITICAL'})
                                    L("CRIT", f"🚨 Suspicious [{pname}]: {_ln[:120]}")
                                elif pname == 'cmdline' and CMD_RE.search(_ln):
                                    _seen.add(_ln); _hits += 1
                                    findings_mem.append({'plugin':pname,'line':_ln[:300],'severity':'HIGH'})
                                    L("CRIT", f"⚠ Suspicious command line: {_ln[:120]}")
                            if 'malfind' in pname:
                                _n = sum(1 for l in lines_out if '\t' in l) - 1
                                if _n > 0:
                                    findings_mem.append({'plugin':'malfind',
                                        'line':f"{_n} suspicious memory region(s) (RWX / injected code) — review manually, false positives possible",
                                        'severity':'HIGH'})
                            L("OK", f"  [{pname}] → {out_file.name}  ({len(lines_out)} lines)")
                            if _live and any(k in pname for k in ('pslist','cmdline','netscan','netstat','svcscan','printkey','malfind','psxview')):
                                _live.feed(pname, [f"--- {pname}"] + lines_out[:60],
                                           [f"[{f['severity']}] {f['plugin']}: {f['line'][:140]}" for f in findings_mem if f['plugin'] == pname][:20])
                        except subprocess.TimeoutExpired:
                            L("WARN", f"  [{pname}] timeout (>{_tmo}s) — skipped (raise it with the VOL_TIMEOUT=<sec> environment variable)")
                        except Exception as ex:
                            L("WARN", f"  [{pname}] error: {ex}")

                    for dump in dumps:
                        L("HEAD", f"Processing: {dump.name}")
                        # first plugin alone: warms Volatility's symbol/PDB cache so parallel runs don't race/download twice
                        run_plugin(dump, plugins[0])
                        rest = sorted(plugins[1:], key=lambda x: 0 if any(h in x for h in HEAVY) else 1)
                        pool = ThreadPoolExecutor(max_workers=_w)
                        try:
                            futs = [pool.submit(run_plugin, dump, pl) for pl in rest]
                            for _f in as_completed(futs):
                                _f.result()
                        finally:
                            pool.shutdown(wait=False, cancel_futures=True)
                    try:
                        _xr = {'critical': [], 'high': [], 'medium': [], 'external_ips': set()}
                        _tools = Path(cfg.get('tools_dir') or './tools')
                        xt_setup(mem_os, _tools, L, True)
                        xt_run_yara(None, _tools, _xr, L, targets=[str(d) for d in dumps])
                        xt_run_bulk([str(d) for d in dumps], output, L)
                        for _sv in ('critical', 'high'):
                            for _f in _xr[_sv]:
                                findings_mem.append({'plugin': _f['source'].lower(), 'line': _f['desc'], 'severity': _sv.upper()})
                    except Exception as _ex:
                        L("WARN", f"External tools step failed: {_ex}")
                    job['mem'] = {'dumps': [d.stem for d in dumps], 'os': mem_os, 'plugins': len(plugins),
                                  'vol_out': str(vol_out), 'findings': findings_mem}
                    try:
                        _cor = cor_correlate(str(vol_out), log=L, os_type=mem_os)
                        job['cor_sections'] = uni_save_cor(_cor, output)
                        uni_scope(mem_os, str(dumps[0]) if dumps else None, str(vol_out), _cor, output)
                        _ce = _cor['entry']
                        if _eng:
                            _notes = _live.finish() if _live else []
                            _pseudo = {'critical': [{'source': f['plugin'], 'desc': f['line']} for f in findings_mem if f['severity'] == 'CRITICAL'],
                                       'high': [{'source': f['plugin'], 'desc': f['line']} for f in findings_mem if f['severity'] == 'HIGH'], 'medium': []}
                            _rv = cor_review(_eng, _cor, _pseudo, L, _notes)
                            if _rv:
                                job['review_text'] = _rv
                                Path(output, 'analyst_review.txt').write_text(_rv, encoding='utf-8')
                                L("OK", "Analyst review ready (included in report)")
                        L("OK", f"Entry point (memory only): {_ce['status']}" + (f" - {_ce['vector']}" if _ce.get('vector') else ""))
                    except Exception as _ex:
                        L("WARN", f"Correlation step failed: {_ex}")
                    # Write summary JSON
                    summary_json = {
                        'mode': 'memory_only', 'dump_count': len(dumps),
                        'target_os': mem_os, 'findings': findings_mem,
                        'plugins_run': len(plugins),
                        'output_dir': str(vol_out),
                    }
                    (Path(output)/'memory_summary.json').write_text(
                        json.dumps(summary_json, indent=2), encoding='utf-8')
                    # Build simple HTML dashboard for memory
                    suspicious_count = len([f for f in findings_mem if f['severity']=='CRITICAL'])
                    html_mem = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Memory Analysis Report</title>
<style>body{{font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px}}
h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:6px}}
.crit{{color:#ff7b72}} .high{{color:#ffa657}} .ok{{color:#3fb950}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #30363d;padding:6px 10px;text-align:left}}
th{{background:#161b22}} tr:hover{{background:#161b22}}
</style></head><body>
<h1>🧠 Memory Analysis Report</h1>
<p>Dumps: <b>{len(dumps)}</b> &nbsp;|&nbsp; OS: <b>{mem_os}</b> &nbsp;|&nbsp;
Plugins: <b>{len(plugins)}</b> &nbsp;|&nbsp;
Suspicious: <b class="{'crit' if suspicious_count else 'ok'}">{suspicious_count}</b></p>
<h2>🚨 Suspicious Findings</h2>
{'<table><tr><th>Plugin</th><th>Severity</th><th>Details</th></tr>' +
''.join(f"<tr><td>{f['plugin']}</td><td class='{f['severity'].lower()}'>{f['severity']}</td><td>{f['line'][:200]}</td></tr>"
        for f in findings_mem) + '</table>' if findings_mem else '<p class="ok">✅ No suspicious findings detected</p>'}
<h2>📁 Output Files</h2>
<ul>{''.join(f"<li>{p.name}</li>" for p in sorted(vol_out.glob('*.txt')))}</ul>
<h2>📋 Dumps Analyzed</h2>
<ul>{''.join(f"<li>{d.name} ({d.stat().st_size//1024//1024} MB)</li>" for d in dumps)}</ul>
</body></html>"""
                    (Path(output)/'dashboard.html').write_text(html_mem, encoding='utf-8')
                    L("OK", f"Memory analysis complete! Findings: {len(findings_mem)}, Suspicious: {suspicious_count}")
                elif os_type == 'windows':   win_main(argv)
                elif os_type in ('linux','kali'):
                    clean = []
                    i = 0
                    while i < len(argv):
                        if argv[i] == '--skip-memory':
                            i += 1; continue
                        clean.append(argv[i]); i += 1
                    lin_main(clean)
                elif os_type == 'macos':   mac_main([x for x in argv if x != '--skip-memory'])
            except SystemExit: pass

        L("OK", "Analysis complete. Gathering results…")

        # Parse results from dashboard.html if exists
        results_data, summary_data = {}, {}
        dash = Path(output) / "dashboard.html"
        if dash.exists():
            content = dash.read_text(errors='ignore')
            m = re.search(r'<script id="export-data" type="application/json">(.*?)</script>',
                          content, re.DOTALL)
            if m:
                try:
                    ex = json.loads(m.group(1))
                    results_data = {
                        'critical': ex.get('critical_findings',[]),
                        'high':     [f for f in ex.get('all_findings',[]) if f.get('severity')=='HIGH'],
                        'timeline': ex.get('timeline',[]),
                        'external_ips': ex.get('external_ips',[]),
                        'c2_indicators': ex.get('c2_indicators',[]),
                        'cisco_hits': ex.get('edr_detections',[]),
                        'hayabusa': ex.get('hayabusa_hits',[]),
                        'registry_hits': ex.get('registry_hits',[]),
                    }
                    s = ex.get('summary', {})
                    summary_data = {
                        'critical': s.get('critical', len(results_data['critical'])),
                        'high': s.get('high', len(results_data['high'])),
                        'medium': s.get('medium', 0),
                        'total_events': s.get('total_events', 0),
                        'external_ips': s.get('external_ips', 0),
                        'cisco_hits': s.get('cisco_hits', 0),
                        'hayabusa_hits': s.get('hayabusa_hits', 0),
                        'analysis_time': s.get('analysis_time','N/A'),
                    }
                except: pass

        if os_type == 'memory' and job.get('mem'):
            _f = job['mem']['findings']
            summary_data = {'critical': sum(1 for f in _f if f['severity']=='CRITICAL'),
                            'high': sum(1 for f in _f if f['severity']=='HIGH'), 'medium': 0,
                            'total_events': 0, 'external_ips': 0, 'cisco_hits': 0,
                            'hayabusa_hits': 0, 'analysis_time': 'N/A'}
        if not summary_data:
            crits = sum(1 for l in log if 'CRITICAL' in l or '[!!!]' in l)
            summary_data = {'critical': crits, 'high': 0, 'medium': 0,
                            'total_events': 0, 'external_ips': 0, 'cisco_hits': 0,
                            'hayabusa_hits': 0, 'analysis_time': 'N/A'}

        job['results'] = results_data
        job['summary'] = summary_data

        try:
            uni_tidy(output)
            if job.get('mem') and job['mem'].get('vol_out'):
                job['mem']['vol_out'] = str(Path(output) / 'supporting_data' / Path(job['mem']['vol_out']).name)
        except Exception: pass
        job['status'] = 'done'
        job['finished'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        threading.Thread(target=rw_run, args=(job, 'full', None, None, True), daemon=True).start()
        L("OK", "Analysis done! The report is in the Reporting tab.")

    except JobStopped:
        JOBS[job_id]['status'] = 'stopped'
        JOBS[job_id]['log'].append("[!] ⛔ Job stopped by user.")
    except Exception as e:
        import traceback
        if JOBS[job_id].get('cancel'):
            JOBS[job_id]['status'] = 'stopped'
            return
        JOBS[job_id]['status'] = 'error'
        JOBS[job_id]['log'].append(f"[✗] Fatal: {e}")
        JOBS[job_id]['log'].append(traceback.format_exc())


# ══════════════════════════════════════════════════════════════════════
# STEP 5 — WEB UI HTML
# ══════════════════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡 Forensics Master Analyzer</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--border:#30363d;--accent:#238636;--blue:#1f6feb;--red:#f85149;--orange:#f97316;--yellow:#e3b341;--text:#e6edf3;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;gap:14px}
.hdr h1{font-size:19px;font-weight:700}
.ver{font-size:11px;color:var(--dim);background:var(--bg3);padding:2px 8px;border-radius:12px;border:1px solid var(--border)}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:22px}
.tab{padding:10px 16px;cursor:pointer;font-size:13px;color:var(--dim);border-bottom:2px solid transparent;transition:all .15s}
.tab.active{color:var(--text);border-bottom-color:var(--blue)}
.tp{display:none}.tp.active{display:block}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
.ch{padding:13px 18px;border-bottom:1px solid var(--border);font-weight:600;font-size:14px;display:flex;align-items:center;gap:8px}
.cb{padding:18px}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.fr.full{grid-template-columns:1fr}
label{display:block;font-size:11px;color:var(--dim);margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
input[type=text],input[type=password],select{width:100%;padding:8px 11px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;outline:none;transition:border-color .15s}
input:focus,select:focus{border-color:var(--blue)}
.hint{font-size:11px;color:var(--dim);margin-top:3px}
.os-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.os-pill{cursor:pointer;border:2px solid var(--border);border-radius:8px;padding:13px 8px;text-align:center;transition:all .15s}
.os-pill:hover{border-color:var(--blue);background:rgba(31,111,235,.08)}
.os-pill.active{border-color:var(--blue);background:rgba(31,111,235,.15)}
.os-pill .icon{font-size:26px}.os-pill .name{font-size:11px;font-weight:600;margin-top:5px}.os-pill .sub{font-size:10px;color:var(--dim);margin-top:1px}
.cbr{display:flex;align-items:center;gap:8px;margin-bottom:9px}
.cbr input[type=checkbox]{accent-color:var(--blue);width:15px;height:15px}
.cbr label{margin:0;font-size:13px;text-transform:none;letter-spacing:0;color:var(--text);cursor:pointer}
.btn{padding:9px 18px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:600;transition:all .15s}
.btn-g{background:var(--accent);color:#fff}.btn-g:hover{background:#2ea043}
.btn-b{background:var(--blue);color:#fff}.btn-b:hover{background:#388bfd}
.btn-o{background:transparent;border:1px solid var(--border);color:var(--text)}.btn-o:hover{border-color:var(--dim)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-row{display:flex;gap:10px;flex-wrap:wrap}
#log{background:#0d1117;border:1px solid var(--border);border-radius:7px;padding:12px 14px;font-family:'Consolas',monospace;font-size:12px;height:320px;overflow-y:auto;line-height:1.7}
.lok{color:#3fb950}.lwarn{color:#e3b341}.lerr{color:#f85149}.linfo{color:#79c0ff}.lhead{color:#d2a8ff;font-weight:700}.lcrit{color:#ff7b72;font-weight:700}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600}
.bi{background:rgba(139,148,158,.15);color:var(--dim)}
.br{background:rgba(31,111,235,.15);color:#79c0ff}
.bd{background:rgba(35,134,54,.15);color:#3fb950}
.be{background:rgba(248,81,73,.15);color:#f85149}
.pulse{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 1.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.pw{background:var(--bg3);border-radius:4px;height:5px;margin:10px 0;overflow:hidden}
.pb{height:100%;background:var(--blue);border-radius:4px;transition:width .4s ease}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:18px}
.sb{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center}
.sb .n{font-size:26px;font-weight:700}.sb .l{font-size:11px;color:var(--dim);margin-top:2px}
.sb.red .n{color:var(--red)}.sb.ora .n{color:var(--orange)}.sb.blu .n{color:#79c0ff}
.dg{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.dc{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.dc .ic{font-size:34px;margin-bottom:7px}.dc .ti{font-weight:600;font-size:14px;margin-bottom:3px}.dc .de{font-size:11px;color:var(--dim);margin-bottom:12px}
.al{padding:11px 14px;border-radius:6px;font-size:13px;margin-bottom:14px}
.al-i{background:rgba(31,111,235,.1);border:1px solid rgba(31,111,235,.3);color:#79c0ff}
.al-e{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#f85149}
.al-s{background:rgba(35,134,54,.1);border:1px solid rgba(35,134,54,.3);color:#3fb950}
.stit{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;font-weight:600;margin-bottom:12px}
hr{border:none;border-top:1px solid var(--border);margin:18px 0}
.hg{display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px}
.hb{background:var(--bg3);border-radius:6px;padding:10px}
.hb .hl{color:var(--dim);margin-bottom:5px;font-weight:600}
.hb code{font-family:monospace;color:#79c0ff;display:block;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:9px 11px;text-align:left;color:var(--dim);font-weight:600;background:var(--bg3)}
td{padding:8px 11px;border-bottom:1px solid var(--border);word-break:break-all}
@media(max-width:600px){.fr,.os-grid,.dg,.hg{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="hdr">
  <span style="font-size:26px">🛡</span>
  <div><h1>Forensics Master Analyzer</h1><span style="font-size:11px;color:var(--dim)">Windows · Linux · macOS · Kali</span></div>
  <span class="ver">v2.0 All-in-One</span>
  <div style="margin-left:auto">
    <span id="gbadge" class="badge bi"><span class="pulse" style="display:none"></span><span id="gst">Idle</span></span>
  </div>
</div>

<div class="wrap">
<div class="tabs">
  <div class="tab active" onclick="sw('configure',this)">⚙️ Configure</div>
  <div class="tab" onclick="sw('monitor',this)">📊 Monitor</div>
  <div class="tab" onclick="sw('reporting',this)">📊 Reporting</div>
  <div class="tab" onclick="sw('registry',this)">🗝️ Registry</div>
  <div class="tab" onclick="sw('jobs',this)">📋 Jobs</div>
</div>

<!-- CONFIGURE -->
<div id="tp-configure" class="tp active">
  <div class="card" id="card-mode"><div class="ch">🧭 Mode</div><div class="cb">
    <div class="os-grid" style="grid-template-columns:1fr 1fr">
      <div class="os-pill active" id="mode-analysis" onclick="setMode('analysis')"><div class="icon">🔍</div><div class="name">Analysis</div><div class="sub">collected evidence ka analysis + report</div></div>
      <div class="os-pill" id="mode-acq" onclick="setMode('acq')"><div class="icon">📥</div><div class="name">Acquisition</div><div class="sub">collect evidence from this live machine</div></div>
    </div>
  </div></div>

  <div class="card"><div class="ch">🖥️ Target OS</div><div class="cb">
    <div class="os-grid" id="osg">
      <div class="os-pill active" onclick="selOS('windows',this)"><div class="icon">🪟</div><div class="name">Windows</div><div class="sub">EVTX · Registry</div></div>
      <div class="os-pill" onclick="selOS('linux',this)"><div class="icon">🐧</div><div class="name">Linux</div><div class="sub">Ubuntu · CentOS</div></div>
      <div class="os-pill" onclick="selOS('kali',this)"><div class="icon">🎯</div><div class="name">Kali</div><div class="sub">Kali · Debian</div></div>
      <div class="os-pill" onclick="selOS('macos',this)"><div class="icon">🍎</div><div class="name">macOS</div><div class="sub">LaunchAgents · TCC</div></div>
      <div class="os-pill" onclick="selOS('memory',this)"><div class="icon">🧠</div><div class="name">Memory Only</div><div class="sub">RAM dump · Volatility3</div></div>
    </div>
  </div></div>

  <div class="card" id="card-acq" style="display:none"><div class="ch">📥 Acquisition</div><div class="cb">
    <div class="os-grid" style="grid-template-columns:1fr 1fr;margin-bottom:14px">
      <div class="os-pill active" id="dev-net" onclick="setDev('net')"><div class="icon">🌐</div><div class="name">Network Connected Device</div><div class="sub">tools install → is machine ka data collect</div></div>
      <div class="os-pill" id="dev-q" onclick="setDev('q')"><div class="icon">🔒</div><div class="name">Quarantined Device</div><div class="sub">build an offline kit for a USB drive</div></div>
    </div>

    <div id="acq-net">
      <div class="al al-i" id="acq-note">Target OS above = the OS of this machine. Windows needs Administrator and Linux/macOS need sudo/root, otherwise the collection will be incomplete.</div>
      <div class="cbr" style="margin-top:6px"><input type="checkbox" id="amem" checked><label for="amem">Capture RAM — needs Admin/root and produces a large file</label></div>
      <div class="fr full" style="margin-top:8px"><div>
        <label>Output folder (optional)</label>
        <input type="text" id="aop" placeholder="Blank → ~/forensics_output/acquisition_&lt;os&gt;_&lt;time&gt;">
      </div></div>
      <div class="cbr" style="margin-top:14px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg3)"><input type="checkbox" id="awith" onchange="acqToggle()"><label for="awith"><b>With Analysis</b> — run the analysis + report right after collection</label></div>
      <div class="fr full" id="acq-an" style="display:none;margin-top:10px"><div>
        <label>Case Name</label>
        <input type="text" id="acase" placeholder="e.g. HR_Server_Live  →  results ~/forensics_output/&lt;case-name&gt;/">
      </div></div>
    </div>

    <div id="acq-q" style="display:none">
      <div class="fr full"><div>
        <label>Kit folder path (the script and tools will be created here)</label>
        <div style="display:flex;gap:8px"><input type="text" id="qpath" placeholder="Blank → ~/forensics_output" style="flex:1"><button class="btn btn-g" style="padding:6px 16px" onclick="buildKit()">⚙️ Process</button></div>
      </div></div>
      <div class="al al-i" style="margin-top:12px">📌 <b>Note:</b> Once processing finishes, <b>copy this folder to a USB drive and run it on the quarantined system</b> (Windows: <b>RUN_ME.bat</b> · Linux/macOS: <b>sudo ./run_me.sh</b>). The tools collect the data from that system by themselves. The evidence is written to the <code>output/</code> folder on the USB drive.</div>
      <details style="margin-top:8px;font-size:12px;color:var(--dim)"><summary style="cursor:pointer">Command to build it from the CLI</summary>
        <div style="display:flex;gap:8px;margin-top:6px;align-items:center"><code id="kit-cmd" style="flex:1;padding:8px 10px;background:#0d1117;border:1px solid var(--border);border-radius:6px;white-space:nowrap;overflow-x:auto;font-size:12px"></code><button class="btn btn-o" style="padding:5px 11px;font-size:12px" onclick="copyKit()">📋 Copy</button></div></details>
    </div>
  </div></div>

  <div class="card" id="card-ev"><div class="ch">📂 Evidence &amp; Output</div><div class="cb">
    <div class="fr full"><div>
      <label><span id="ev-label">Evidence Folder Path</span> *</label>
      <input type="text" id="ev" placeholder="/path/to/evidence/" onchange="chkPath()" onblur="chkPath()">
      <div id="ev-warn" style="display:none;margin-top:8px;padding:10px 12px;border:1px solid #d29922;border-radius:8px;background:#2d2308;font-size:12.5px"></div>
      <div class="hint" id="ev-hint">EVTX files, Registry hives, memory dumps — tool auto-discovers</div>
    </div></div>
    <div class="fr full" id="mem-row" style="display:none"><div>
      <label>🧠 Memory Dump Path * <span style="font-weight:400;font-size:12px;color:var(--dim)">(folder ya direct .raw/.dmp/.vmem file)</span></label>
      <input type="text" id="mdp" placeholder="/path/to/memory.raw  or  /path/to/dumps/">
      <div class="hint">Supported: .raw .dmp .vmem .mem .lime .bin (minimum 1 MB)</div>
    </div></div>
    <div class="fr full" id="mem-os-row" style="display:none"><div>
      <label>🖥️ OS of the Dumped Machine</label>
      <select id="mem-os" style="width:100%;padding:7px 10px;background:var(--s2);border:1px solid var(--br);border-radius:6px;color:var(--fg)">
        <option value="windows">Windows (use windows.* plugins)</option>
        <option value="linux">Linux (use linux.* plugins)</option>
      </select>
      <div class="hint">Volatility3 plugin set depends on the OS of the original machine</div>
    </div></div>
    <div class="fr full"><div>
      <label>Case Name (optional)</label>
      <input type="text" id="case" placeholder="e.g. Ransomware_HR_Server  →  results save in ~/forensics_output/&lt;case-name&gt;/">
    </div></div>
    <div class="fr full"><div>
      <label>Output Folder (optional)</label>
      <input type="text" id="op" placeholder="Leave blank → ~/forensics_output/&lt;case-name or job-id&gt;">
    </div></div>
  </div></div>

  <div class="card" id="card-keys"><div class="ch">🔑 API Keys <span style="font-weight:400;font-size:12px;color:var(--dim);margin-left:8px">optional</span></div><div class="cb">
    <div class="fr">
      <div><label>VirusTotal Key</label><input type="password" id="vtk" placeholder="Leave blank to skip"></div>
      <div><label>AbuseIPDB Key</label><input type="password" id="abk" placeholder="Leave blank to skip"></div>
    </div>
  </div></div>

  <div class="card" id="card-ai"><div class="ch">🧠 AI Provider <span style="font-weight:400;font-size:12px;color:var(--dim);margin-left:8px">optional - live review during analysis + correlation report at the end</span></div><div class="cb">
    <div class="fr">
      <div><label>AI Provider</label><select id="aip" onchange="aiChg()">
        <option value="none">None (rule-based only)</option>
        <option value="ollama">Ollama (local)</option>
        <option value="anthropic">Anthropic / Claude</option>
        <option value="gemini">Google Gemini</option>
        <option value="auto">Auto-detect</option>
      </select></div>
      <div id="ai-key-wrap" style="display:none"><label id="ai-key-lbl">API Key</label><input type="password" id="aik" placeholder="API key"></div>
    </div>
  </div></div>

  <div class="card" id="card-opts"><div class="ch">⚙️ Options</div><div class="cb">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 22px">
      <div class="cbr"><input type="checkbox" id="sm"><label for="sm">Skip memory analysis</label></div>
    </div>
  </div></div>

  <div class="btn-row" id="acq-run-row" style="display:none">
    <button class="btn btn-g" id="acqbtn" onclick="startAcq()">📥 Start Acquisition</button>
    <button class="btn btn-o" onclick="sw('monitor',document.querySelectorAll('.tab')[1])">📊 Monitor</button>
  </div>
  <div class="btn-row" id="run-row">
    <button class="btn btn-g" id="runbtn" onclick="startJob()">🚀 Start Analysis</button>
    <button class="btn btn-o" onclick="sw('monitor',document.querySelectorAll('.tab')[1])">📊 Monitor</button>
  </div>
</div>

<!-- MONITOR -->
<div id="tp-monitor" class="tp">
  <div class="card">
    <div class="ch">📡 Live Log
      <div style="margin-left:auto;display:flex;gap:8px">
        <span id="mbadge" class="badge bi"><span class="pulse" style="display:none"></span><span>Idle</span></span>
        <button class="btn btn-o" id="stopbtn" style="padding:4px 11px;font-size:12px;display:none;color:#f85149;border-color:#f85149" onclick="stopJob(curJob)">⛔ Stop</button>
        <button class="btn btn-o" style="padding:4px 11px;font-size:12px" onclick="document.getElementById('log').innerHTML='';lastLen=0">Clear</button>
        <button class="btn btn-o" style="padding:4px 11px;font-size:12px" onclick="document.getElementById('log').scrollTop=9e9">↓</button>
      </div>
    </div>
    <div class="cb">
      <div class="pw"><div class="pb" id="pb" style="width:0%"></div></div>
      <div id="log"></div>
    </div>
  </div>
</div>

<!-- REGISTRY -->
<div id="tp-registry" class="tp">
  <div class="card"><div class="ch">🗝️ Registry Hive Analyzer</div><div class="cb">
    <div class="al al-i" style="margin-bottom:14px">Enter a folder or hive file path - NTUSER.DAT, SAM, SYSTEM, SOFTWARE and SECURITY are parsed automatically.</div>
    <div class="fr">
      <div>
        <label>Hive File ya Folder Path</label>
        <input type="text" id="rp" placeholder="/evidence/C/Windows/System32/config/  ya  /evidence/NTUSER.DAT">
      </div>
      <div style="display:flex;align-items:flex-end">
        <button class="btn btn-b" id="regbtn" onclick="runReg()">🔍 Analyze Registry</button>
      </div>
    </div>
    <div style="margin-top:12px">
      <div class="stit">Common Hive Locations (Windows)</div>
      <div class="hg">
        <div class="hb"><div class="hl">System Hives</div>
          <code>C:\Windows\System32\config\SAM</code>
          <code>C:\Windows\System32\config\SYSTEM</code>
          <code>C:\Windows\System32\config\SOFTWARE</code>
          <code>C:\Windows\System32\config\SECURITY</code>
        </div>
        <div class="hb"><div class="hl">User Hives</div>
          <code>C:\Users\&lt;user&gt;\NTUSER.DAT</code>
          <code>C:\Users\&lt;user&gt;\AppData\Local\Microsoft\Windows\UsrClass.dat</code>
        </div>
      </div>
    </div>
  </div></div>

  <div id="rload" style="display:none;text-align:center;padding:36px;color:var(--dim)"><div style="font-size:30px;margin-bottom:10px">⏳</div><div>Parsing registry hives...</div></div>
  <div id="rerr" class="al al-e" style="display:none"></div>

  <div id="rres" style="display:none">
    <div class="sg" id="rsg2"></div>
    <div style="display:flex;gap:8px;margin-bottom:14px;align-items:center;flex-wrap:wrap">
      <span style="font-size:12px;color:var(--dim)">Filter:</span>
      <button class="btn btn-o" style="padding:4px 12px;font-size:12px" onclick="fr2('ALL')">All</button>
      <button class="btn btn-o" style="padding:4px 12px;font-size:12px;border-color:#f85149;color:#f85149" onclick="fr2('CRITICAL')">🔴 Critical</button>
      <button class="btn btn-o" style="padding:4px 12px;font-size:12px;border-color:#f97316;color:#f97316" onclick="fr2('HIGH')">🟠 High</button>
      <button class="btn btn-o" style="padding:4px 12px;font-size:12px;border-color:#e3b341;color:#e3b341" onclick="fr2('MEDIUM')">🟡 Medium</button>
      <input type="text" id="rs" placeholder="Key / value search…" oninput="fr2()" style="margin-left:auto;width:200px;padding:4px 9px;font-size:12px">
    </div>
    <div class="card">
      <div class="ch">🚨 Forensic Findings</div>
      <div style="overflow-x:auto">
        <table><thead><tr>
          <th>Severity</th><th>Hive</th><th>Registry Key</th>
          <th>Value Name</th><th>Value Data</th><th>Last Written</th>
        </tr></thead><tbody id="rtb"></tbody></table>
      </div>
    </div>
    <div class="btn-row" style="margin-top:14px">
      <button class="btn btn-b" onclick="dlReg('json')">⬇ JSON</button>
      <button class="btn btn-g" onclick="dlReg('csv')">⬇ CSV</button>
    </div>
  </div>
</div>

<!-- REPORTING -->
<div id="tp-reporting" class="tp">
  <style>
    input[type=datetime-local]{width:100%;padding:7px 9px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;color-scheme:dark}
    .rjob{border:1px solid var(--border);border-radius:9px;padding:14px 16px;margin-bottom:14px;background:var(--bg3)}
    .rchip{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:7px 0;border-top:1px dashed var(--border);font-size:12.5px}
  </style>
  <div class="card"><div class="ch">📊 Reporting Dashboard <span style="font-weight:400;font-size:12px;color:var(--dim);margin-left:8px">completed tasks - pick a time window and press Analyze</span></div><div class="cb" id="replist">
    <div class="al al-i">No completed tasks yet. A task appears here as soon as its analysis finishes.</div>
  </div></div>
  <div class="card" id="repview" style="display:none"><div class="ch"><span id="repview-title">Dashboard</span><span style="flex:1"></span><button class="btn btn-o" style="padding:4px 11px;font-size:12px" onclick="document.getElementById('repview').style.display='none'">✕ Close</button></div>
    <div style="padding:0"><iframe id="repframe" style="width:100%;height:80vh;border:0;background:#0d1117"></iframe></div></div>
</div>

<!-- JOBS -->
<div id="tp-jobs" class="tp">
  <div class="card"><div class="ch">📋 Running Tasks</div><div class="cb" id="jlist">
    <div class="al al-i">No running tasks. Completed tasks are in the Reporting tab.</div>
  </div></div>
</div>

</div><!-- /wrap -->

<script>
let curOS='windows', curJob=null, poll=null, lastLen=0, regFindings=[];

// ── Tabs ──────────────────────────────────────────────────────────────
function sw(name,el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tp-'+name).classList.add('active');
  clearInterval(window._jt);
  if(name==='jobs'){ loadJobs(); window._jt=setInterval(loadJobs,2500); }
  if(name==='reporting'){ loadReporting(true); window._jt=setInterval(()=>loadReporting(false),2500); }
}

// ── provider -> API key field ─────────────────────────────────────
function aiChg(){
  const p=document.getElementById('aip').value;
  const needs=(p==='anthropic'||p==='gemini'||p==='auto');
  document.getElementById('ai-key-wrap').style.display=needs?'':'none';
  const names={anthropic:'Anthropic / Claude',gemini:'Google Gemini',auto:'Auto-detect'};
  document.getElementById('ai-key-lbl').textContent=needs?('API Key — '+names[p]+(p==='auto'?' (optional, blank = Ollama)':' *')):'API Key';
  document.getElementById('aik').placeholder=p==='anthropic'?'sk-ant-...':p==='gemini'?'AIza...':'API key';
  if(!needs) document.getElementById('aik').value='';
}

// ── OS select ─────────────────────────────────────────────────────────
function selOS(os,el){
  setTimeout(()=>{ if(typeof updKit==='function') updKit(); },0);
  document.querySelectorAll('.os-pill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active'); curOS=os;
  const isMem = os==='memory';
  document.getElementById('ev-label').textContent = isMem ? 'Memory Dump Path (folder ya direct .raw/.dmp/.vmem file)' : 'Evidence Folder Path';
  document.getElementById('mem-row').style.display    = 'none';
  document.getElementById('mem-os-row').style.display = isMem?'':'none';
  document.getElementById('ev-hint').textContent = isMem
    ? 'Supported: .raw .dmp .vmem .mem .lime .bin (minimum 1 MB)'
    : 'EVTX files, Registry hives, memory dumps — tool auto-discovers';
  const evLabel = document.querySelector('label[for="ev"],#tp-configure label');
  // update placeholder
  document.getElementById('ev').placeholder = isMem
    ? '/path/to/memory.raw  or  /path/to/dumps/'
    : '/path/to/evidence/';
}

// ── Evidence permission check ─────────────────────────────────────────
async function chkPath(){
  const box=document.getElementById('ev-warn'); const v=document.getElementById('ev').value.trim();
  if(!v){box.style.display='none';return;}
  let d; try{ d=await (await fetch('/api/checkpath?path='+encodeURIComponent(v))).json(); }catch(e){return;}
  showPerm(d);
}
function showPerm(d){
  const box=document.getElementById('ev-warn');
  if(!d.exists){box.style.display='';box.style.borderColor='#f85149';box.style.background='#2d1214';box.innerHTML='⚠ Path not found.';return;}
  if(!d.unreadable){box.style.display='none';return;}
  box.style.display='';box.style.borderColor='#d29922';box.style.background='#2d2308';
  box.innerHTML='⚠ <b>'+d.unreadable+' file/folder(s) cannot be read by this user</b> (e.g. '+escH((d.examples||[]).join(', '))+'). They would be skipped by the analysis.<br>'
   +'Fix: start the tool with <b>sudo / Administrator</b>, or run this once:<br><code id="fix-cmd" style="display:block;margin:6px 0;padding:6px 8px;background:#0d1117;border-radius:6px;white-space:pre-wrap;word-break:break-all">'+escH(d.fix_cmd||'')+'</code>'
   +'<button class="btn btn-o" style="padding:4px 11px;font-size:12px" onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById(\'fix-cmd\').textContent)">📋 Copy</button> '
   +'<button class="btn btn-b" style="padding:4px 11px;font-size:12px" onclick="fixPerm()">🔧 Try auto-fix</button> <span style="color:var(--dim)">(auto-fix works when the tool runs as root or sudo is passwordless)</span>';
}
async function fixPerm(){
  const v=document.getElementById('ev').value.trim();
  const r=await fetch('/api/fixperms',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:v})});
  const d=await r.json(); if(d.error){alert(d.error);return;}
  if(!d.ok && d.unreadable) alert(d.message);
  showPerm(Object.assign({exists:true},d));
}

// ── Acquisition: device type / mode ───────────────────────────────────
let curMode='analysis', curDev='net', _sys={};
function kitOS(){return (curOS==='kali'||curOS==='ubuntu')?'linux':(curOS==='memory'?'windows':curOS);}
function updKit(){
  const el=document.getElementById('kit-cmd'); if(!el) return;
  const py=(_sys.os==='windows')?'python':'python3';
  el.textContent=py+' "'+(_sys.script||'forensics_master_FINAL.py')+'" --build-kit --os '+kitOS()+' --out ./acq_kit';
}
function copyKit(){const t=document.getElementById('kit-cmd').textContent; if(navigator.clipboard) navigator.clipboard.writeText(t); else {const r=document.createRange(); r.selectNode(document.getElementById('kit-cmd')); getSelection().removeAllRanges(); getSelection().addRange(r); document.execCommand('copy');}}
async function buildKit(){
  const r=await fetch('/api/buildkit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({os_type:kitOS(),output:document.getElementById('qpath').value.trim()})});
  const d=await r.json(); if(d.error){alert(d.error);return;}
  lastLen=0; document.getElementById('log').innerHTML=''; curJob=d.job_id; sw('monitor',document.querySelectorAll('.tab')[1]);
  clearInterval(poll); poll=setInterval(pollJob,1500); pollJob();
}
function acqToggle(){
  const net=(curMode==='acq'&&curDev==='net');
  const on=net && document.getElementById('awith').checked;
  document.getElementById('acq-an').style.display=on?'':'none';
  ['card-keys','card-ai'].forEach(id=>{const e=document.getElementById(id); if(e) e.style.display=(curMode==='acq')?(on?'':'none'):'';});
}
function setDev(d){
  curDev=d; const Q=(d==='q');
  document.getElementById('dev-net').classList.toggle('active',!Q);
  document.getElementById('dev-q').classList.toggle('active',Q);
  document.getElementById('acq-net').style.display=Q?'none':'';
  document.getElementById('acq-q').style.display=Q?'':'none';
  document.getElementById('acq-run-row').style.display=(curMode==='acq'&&!Q)?'':'none';
  acqToggle(); updKit();
  if(!Q) setMode('acq');
}
async function setMode(m){
  curMode=m; const A=(m==='acq');
  document.getElementById('mode-analysis').classList.toggle('active',!A);
  document.getElementById('mode-acq').classList.toggle('active',A);
  ['card-ev','card-opts','run-row'].forEach(id=>{const e=document.getElementById(id); if(e) e.style.display=A?'none':'';});
  document.getElementById('card-acq').style.display=A?'':'none';
  document.getElementById('acq-run-row').style.display=(A&&curDev==='net')?'':'none';
  acqToggle();
  const mp=[...document.querySelectorAll('#osg .os-pill')].find(p=>(p.getAttribute('onclick')||'').includes("'memory'"));
  if(mp) mp.style.display=A?'none':'';
  if(A){
    let si={}; try{ si=await (await fetch('/api/sysinfo')).json(); }catch(e){}
    _sys=si;
    if(si.os && curDev==='net'){
      const want=(si.os==='linux'&&curOS==='kali')?'kali':si.os;
      const pill=[...document.querySelectorAll('#osg .os-pill')].find(p=>(p.getAttribute('onclick')||'').includes("'"+want+"'"));
      if(pill) selOS(want, pill);
      document.getElementById('acq-note').innerHTML='This machine: <b>'+si.system+'</b> ('+(si.admin?'admin/root ✔':'not admin/root - collection may be incomplete')+'). Acquisition only works for the OS of this machine.';
    } else if(curOS==='memory'){
      const pill=[...document.querySelectorAll('#osg .os-pill')].find(p=>(p.getAttribute('onclick')||'').includes("'windows'")); if(pill) selOS('windows',pill);
    }
    updKit();
  }
}
async function startAcq(){
  if(curOS==='memory'){alert('Choose Windows / Linux / Kali / macOS for acquisition.');return;}
  const wa=document.getElementById('awith').checked;
  const _p=document.getElementById('aip').value;
  if(wa && (_p==='anthropic'||_p==='gemini') && !document.getElementById('aik').value.trim()){alert('Enter the API key for this AI provider.');return;}
  document.getElementById('acqbtn').disabled=true; lastLen=0; document.getElementById('log').innerHTML='';
  const body={os_type:curOS, output:document.getElementById('aop').value.trim(), analyze:wa, memory:document.getElementById('amem').checked, procs:'', fuji:false};
  if(wa){ Object.assign(body,{case_name:document.getElementById('acase').value.trim(), ai_provider:_p, ai_key:document.getElementById('aik').value.trim(),
    vt_key:document.getElementById('vtk').value.trim(), abuse_key:document.getElementById('abk').value.trim()}); }
  const r=await fetch('/api/acquire',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json(); document.getElementById('acqbtn').disabled=false;
  if(d.error){alert(d.error);return;}
  curJob=d.job_id; sw('monitor',document.querySelectorAll('.tab')[1]);
  clearInterval(poll); poll=setInterval(pollJob,1500); pollJob();
}
function useEvidence(path,os){
  setMode('analysis');
  const pill=[...document.querySelectorAll('#osg .os-pill')].find(p=>(p.getAttribute('onclick')||'').includes("'"+os+"'"));
  if(pill) selOS(os,pill);
  document.getElementById('ev').value=path; chkPath();
  sw('configure',document.querySelectorAll('.tab')[0]);
}

// ── Start job ─────────────────────────────────────────────────────────
async function startJob(){
  const ev=document.getElementById('ev').value.trim();
  const isMem = curOS==='memory';
  if(!ev){alert(isMem ? 'Memory dump path is required.' : 'Evidence path is required.');return;}
  const mdp = ev;   // Memory Only: the evidence path is the memory dump path
  const _p=document.getElementById('aip').value;
  if((_p==='anthropic'||_p==='gemini') && !document.getElementById('aik').value.trim()){alert('Enter the API key for this provider.');return;}
  document.getElementById('runbtn').disabled=true; lastLen=0;
  const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    os_type:curOS,evidence:ev,
    ai_provider:_p, ai_key:document.getElementById('aik').value.trim(),
    memory_path: mdp,
    memory_os: document.getElementById('mem-os').value,
    output:document.getElementById('op').value.trim(),
    case_name:document.getElementById('case').value.trim(),
    vt_key:document.getElementById('vtk').value.trim(),
    abuse_key:document.getElementById('abk').value.trim(),
    skip_setup:false,
    skip_memory:document.getElementById('sm').checked,
  })});
  const d=await r.json();
  if(d.error){alert(d.error);document.getElementById('runbtn').disabled=false;return;}
  curJob=d.job_id;
  sw('monitor',document.querySelectorAll('.tab')[1]);
  if(poll)clearInterval(poll);
  poll=setInterval(pollJob,1500); pollJob();
}

// ── Poll ─────────────────────────────────────────────────────────────
async function pollJob(){
  if(!curJob)return;
  const d=await (await fetch('/api/status/'+curJob+'?since='+lastLen)).json();
  const el=document.getElementById('log');
  (d.log||[]).forEach(line=>{
    const div=document.createElement('div');
    div.className=(/\[+\]/.test(line)?'lok':/\[!\]/.test(line)?'lwarn':/✗|ERROR/.test(line)?'lerr':/!!!/.test(line)?'lcrit':/■/.test(line)?'lhead':'linfo');
    div.textContent=line; el.appendChild(div);
  });
  lastLen=d.total||lastLen;
  el.scrollTop=el.scrollHeight;
  const prog=Math.min(95,(lastLen/3));
  document.getElementById('pb').style.width=(d.status==='done'?100:prog)+'%';
  const sc={'running':'br','done':'bd','error':'be','stopped':'be'};
  const txt={'running':'Running…','done':'✓ Done','error':'✗ Error','stopped':'⛔ Stopped','pending':'Pending'};
  document.getElementById('stopbtn').style.display=(d.status==='running'||d.status==='pending')?'':'none';
  document.getElementById('mbadge').className='badge '+(sc[d.status]||'bi');
  document.getElementById('mbadge').querySelector('span:last-child').textContent=txt[d.status]||d.status;
  document.getElementById('mbadge').querySelector('.pulse').style.display=d.status==='running'?'':'none';
  document.getElementById('gbadge').className='badge '+(sc[d.status]||'bi');
  document.getElementById('gst').textContent=txt[d.status]||d.status;
  if(d.status==='done' && d.kind==='acquisition' && d.next_job){
    curJob=d.next_job; lastLen=0;
    const dv=document.createElement('div'); dv.className='lhead'; dv.textContent='──── ANALYSIS (collected artifacts) ────'; el.appendChild(dv);
    return;
  }
  if(d.status==='done'||d.status==='error'||d.status==='stopped'){
    clearInterval(poll); document.getElementById('runbtn').disabled=false;
    if(d.status==='done' && d.kind!=='acquisition' && d.kind!=='kit'){ sw('reporting',tabEl('reporting')); }
    else { loadJobs(); sw('jobs',jobsTabEl()); }
    document.getElementById('acqbtn').disabled=false;
  }
}

function jobsTabEl(){return [...document.querySelectorAll('.tab')].find(t=>(t.getAttribute('onclick')||'').includes("'jobs'"));}
function dl(id,fmt){window.location.href='/api/report/'+id+'/'+fmt;}
async function genReport(id){
  const r=await fetch('/api/genreport/'+id,{method:'POST'}); const d=await r.json();
  if(d.error)alert(d.error);
  loadJobs();
}

// ── Reporting dashboard ─────────────────────────────────────────────
let repSig='';
function tabEl(n){return [...document.querySelectorAll('.tab')].find(t=>(t.getAttribute('onclick')||'').includes("'"+n+"'"));}
function escH(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function presetChg(id){
  const sel=document.getElementById('rp-'+id); const o=sel.options[sel.selectedIndex];
  document.getElementById('rf-'+id).value=o.dataset.f; document.getElementById('rt-'+id).value=o.dataset.t;
}
function repCard(j){
  const bs='padding:6px 14px;font-size:12px';
  const rng=(j.range&&j.range.min)?('Evidence time range: <b>'+j.range.min+'</b> → <b>'+j.range.max+'</b> · '+j.range.n+' timestamped events'):'No timestamps in this evidence (memory state) — whole-evidence analysis only';
  const pre=j.presets||[];
  const opts=pre.map((p,i)=>'<option value="'+i+'" data-f="'+p.from+'" data-t="'+p.to+'">'+escH(p.label)+'</option>').join('');
  const f0=pre[0]||{from:'',to:''};
  const picker=pre.length?('<div class="fr" style="grid-template-columns:2.2fr 1fr 1fr auto;align-items:end;margin:12px 0 6px">'
    +'<div><label>Quick select</label><select id="rp-'+j.id+'" onchange="presetChg(\''+j.id+'\')">'+opts+'</select></div>'
    +'<div><label>From</label><input type="datetime-local" id="rf-'+j.id+'" value="'+f0.from+'"></div>'
    +'<div><label>To</label><input type="datetime-local" id="rt-'+j.id+'" value="'+f0.to+'"></div>'
    +'<div><button class="btn btn-g" style="'+bs+'" onclick="analyzeJob(\''+j.id+'\')">🔍 Analyze</button></div></div>')
    :('<div style="margin:12px 0 6px"><button class="btn btn-g" style="'+bs+'" onclick="analyzeJob(\''+j.id+'\')">🔍 Analyze whole evidence</button></div>');
  const engine=j.ai_available?'<span class="badge bd">🧠 analyst review ON</span>':'<span class="badge bi" title="No AI Provider was selected in Configure">rule-based only</span>';
  const chips=(j.analyses||[]).map(a=>{
    const st=a.state==='running'?'<span class="badge br">⏳ running…</span>':a.state==='error'?'<span class="badge be" title="'+escH(a.error)+'">error</span>':'<span class="badge bd">ready</span>';
    const kp=a.kpis?(' · risk <b>'+a.kpis.risk+'</b> · '+a.kpis.critical+' crit / '+a.kpis.high+' high'):'';
    const btn=a.state==='done'?('<button class="btn btn-b" style="'+bs+'" onclick="viewAnalysis(\''+j.id+'\',\''+a.id+'\')">👁 Dashboard</button>'
      +'<button class="btn btn-o" style="'+bs+'" onclick="dlA(\''+j.id+'\',\''+a.id+'\',\'docx\')">⬇ DOCX</button>'
      +'<button class="btn btn-o" style="'+bs+'" onclick="dlA(\''+j.id+'\',\''+a.id+'\',\'pdf\')">⬇ PDF</button>'
      +'<button class="btn btn-o" style="'+bs+'" onclick="dlA(\''+j.id+'\',\''+a.id+'\',\'dashboard\')">⬇ HTML</button>'):'';
    return '<div class="rchip"><div style="flex:1;min-width:260px"><b>'+escH(a.label||a.id)+'</b> '+st+kp+(a.ai?' · 🧠 analyst review':' · rule-based')+'</div>'+btn+'</div>';
  }).join('');
  return '<div class="rjob"><div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">'
    +'<div style="font-size:14px;font-weight:700;flex:1;min-width:240px">'+(j.case?('📁 '+escH(j.case)+' · '):'')+j.os_type.toUpperCase()+(j.host?(' · 🖥 '+escH(j.host)):'')+'</div>'+engine+'</div>'
    +'<div style="font-size:11.5px;color:var(--dim);margin-top:3px">'+escH(j.evidence)+' · finished '+escH(j.finished||j.started)+(j.output_dir?(' · 💾 '+escH(j.output_dir)):'')+'</div>'
    +'<div style="font-size:12px;margin-top:8px">'+rng+'</div>'+picker+'<div style="margin-top:6px">'+chips+'</div></div>';
}
async function loadReporting(force){
  let d; try{ d=await (await fetch('/api/reporting')).json(); }catch(e){ return; }
  const sig=JSON.stringify((d.jobs||[]).map(j=>[j.id,(j.analyses||[]).map(a=>[a.id,a.state])]));
  if(!force && sig===repSig) return; repSig=sig;
  const el=document.getElementById('replist');
  if(!d.jobs||!d.jobs.length){el.innerHTML='<div class="al al-i">No completed tasks yet. A task appears here as soon as its analysis finishes.</div>';return;}
  const keep={}; (d.jobs||[]).forEach(j=>['rp','rf','rt'].forEach(p=>{const e=document.getElementById(p+'-'+j.id); if(e) keep[p+'-'+j.id]=e.value;}));
  el.innerHTML=d.jobs.map(repCard).join('');
  Object.keys(keep).forEach(k=>{const e=document.getElementById(k); if(e) e.value=keep[k];});
}
async function analyzeJob(id){
  const f=document.getElementById('rf-'+id), t=document.getElementById('rt-'+id);
  const body={from:f?f.value:'', to:t?t.value:'', ai:true};
  const r=await fetch('/api/analyze/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json(); if(d.error) alert(d.error);
  loadReporting(true);
}
function viewAnalysis(j,a){
  document.getElementById('repframe').src='/api/analysis/'+j+'/'+a+'/html';
  const c=document.getElementById('repview'); c.style.display=''; c.scrollIntoView({behavior:'smooth'});
}
function dlA(j,a,w){window.location.href='/api/analysis/'+j+'/'+a+'/'+w;}

// ── Jobs ─────────────────────────────────────────────────────────────
async function loadJobs(){
  const d=await (await fetch('/api/jobs')).json();
  d.jobs=(d.jobs||[]).filter(j=>j.status!=='done'||j.kind==='acquisition'||j.kind==='kit');
  const el=document.getElementById('jlist');
  if(!d.jobs.length){el.innerHTML='<div class="al al-i">No running tasks. Completed tasks are in the Reporting tab.</div>';return;}
  el.innerHTML=d.jobs.map(j=>{
    const sm=j.summary||{}; const bs='padding:4px 11px;font-size:12px';
    let act='';
    if(j.status==='running'||j.status==='pending')
      act+=`<button class="btn btn-o" style="${bs};color:#f85149;border-color:#f85149" onclick="stopJob('${j.id}')">⛔ Stop</button>`;
    if(j.status==='done' && j.kind==='acquisition' && j.next_job){
      act+=`<span class="badge bd">→ analysis started (Reporting tab)</span>`;
    } else if(j.status==='done' && j.kind==='acquisition'){
      act+=`<button class="btn btn-g" style="${bs}" onclick="useEvidence('${String(j.evidence).replace(/\\/g,'\\\\').replace(/'/g,"\\'")}','${j.os_type}')">🔍 Analyze this evidence</button>`;
    } else if(j.status==='done'){
      if(j.report_state==='generating') act+=`<span class="badge br">⏳ Building report...</span>`;
      else if(j.report_state==='ready'){
        if(j.has_docx) act+=`<button class="btn btn-b" style="${bs}" onclick="dl('${j.id}','docx')">⬇ DOCX</button>`;
        if(j.has_pdf)  act+=`<button class="btn btn-g" style="${bs}" onclick="dl('${j.id}','pdf')">⬇ PDF</button>`;
        act+=`<button class="btn btn-o" style="${bs}" onclick="genReport('${j.id}')">🔄 Regenerate</button>`;
      } else
        act+=`<button class="btn btn-g" style="${bs}" onclick="genReport('${j.id}')">📄 Generate Report</button>`;
      act+=`<button class="btn btn-o" style="${bs}" onclick="dl('${j.id}','html')">🌐 Dashboard</button>`;
      act+=`<button class="btn btn-o" style="${bs}" onclick="dl('${j.id}','json')">📦 JSON</button>`;
    }
    const err=j.report_state==='error'?`<div style="font-size:11px;color:#f85149">Report error: ${j.report_error}</div>`:'';
    const stats=j.status==='done'?` · 🔴 ${sm.critical||0} · 🟠 ${sm.high||0}`:'';
    return `<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);flex-wrap:wrap">
      <span class="badge ${j.status==='done'?'bd':(j.status==='error'||j.status==='stopped')?'be':'br'}">${j.status}</span>
      <div style="flex:1;min-width:220px"><div style="font-size:13px;font-weight:600">${j.kind==='acquisition'?'📥 ACQUISITION · ':j.kind==='kit'?'🔒 OFFLINE KIT · ':''}${j.case?('📁 '+j.case+' · '):''}${j.os_type.toUpperCase()}${j.evidence?(' — '+j.evidence):''}</div>
      <div style="font-size:11px;color:var(--dim)">${j.started}${stats}${j.output_dir?(' · 💾 '+j.output_dir):''}</div>${err}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${act}</div>
    </div>`;}).join('');
}
async function stopJob(id){
  if(!id||!confirm('Stop this job?'))return;
  const r=await fetch('/api/stop/'+id,{method:'POST'});
  const d=await r.json();
  if(d.error)alert(d.error);
  loadJobs();
  if(id===curJob)pollJob();
}

// ── Registry ─────────────────────────────────────────────────────────
async function runReg(){
  const path=document.getElementById('rp').value.trim();
  if(!path){alert('Path do.');return;}
  document.getElementById('rres').style.display='none';
  document.getElementById('rerr').style.display='none';
  document.getElementById('rload').style.display='';
  document.getElementById('regbtn').disabled=true;
  try{
    const r=await fetch('/api/registry/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
    const d=await r.json();
    document.getElementById('rload').style.display='none';
    document.getElementById('regbtn').disabled=false;
    if(d.error){document.getElementById('rerr').textContent='❌ '+d.error;document.getElementById('rerr').style.display='';return;}
    renderReg(d);
  }catch(e){
    document.getElementById('rload').style.display='none';
    document.getElementById('regbtn').disabled=false;
    document.getElementById('rerr').textContent='❌ '+e;
    document.getElementById('rerr').style.display='';
  }
}
function renderReg(d){
  regFindings=d.findings||[];
  document.getElementById('rres').style.display='';
  const hives=d.hives||[d];
  let tc=0,th=0,tm=0,tv=0;
  hives.forEach(h=>{tc+=h.stats?.critical||0;th+=h.stats?.high||0;tm+=h.stats?.medium||0;tv+=h.stats?.total_values||0;});
  document.getElementById('rsg2').innerHTML=`
    <div class="sb red"><div class="n">${tc}</div><div class="l">Critical</div></div>
    <div class="sb ora"><div class="n">${th}</div><div class="l">High</div></div>
    <div class="sb"><div class="n">${tm}</div><div class="l">Medium</div></div>
    <div class="sb blu"><div class="n">${tv.toLocaleString()}</div><div class="l">Values</div></div>
    <div class="sb"><div class="n">${hives.length}</div><div class="l">Hives</div></div>
    <div class="sb"><div class="n">${(d.external_ips||[]).length}</div><div class="l">Ext. IPs</div></div>`;
  renderRegTbl(regFindings);
}
const SC={'CRITICAL':'#f85149','HIGH':'#f97316','MEDIUM':'#e3b341','INFO':'#8b949e'};
function renderRegTbl(rows){
  const tb=document.getElementById('rtb');
  if(!rows.length){tb.innerHTML='<tr><td colspan="6" style="padding:18px;text-align:center;color:var(--dim)">No findings - the hive looks clean.</td></tr>';return;}
  tb.innerHTML=rows.map(f=>`<tr>
    <td><span style="color:${SC[f.severity]||'#8b949e'};font-weight:700;font-size:11px">${f.severity}</span></td>
    <td style="font-family:monospace;color:#79c0ff;font-size:11px">${h(f.hive||'')}</td>
    <td style="font-family:monospace;font-size:11px;max-width:260px">${h(f.key||'')}</td>
    <td style="font-family:monospace;font-size:11px">${h(f.name||'')}</td>
    <td style="font-size:11px;max-width:280px;color:${f.pattern?'#f85149':'inherit'}">${h(f.data||'')}${f.pattern?` <span style="background:rgba(248,81,73,.15);border-radius:3px;padding:1px 5px;font-size:10px">${f.pattern}</span>`:''}</td>
    <td style="font-size:10px;color:var(--dim);white-space:nowrap">${f.last_written||''}</td>
  </tr>`).join('');
}
function h(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fr2(sev){
  const q=document.getElementById('rs').value.toLowerCase();
  let rows=regFindings;
  if(sev&&sev!=='ALL')rows=rows.filter(r=>r.severity===sev);
  if(q)rows=rows.filter(r=>(r.key||'').toLowerCase().includes(q)||(r.name||'').toLowerCase().includes(q)||(r.data||'').toLowerCase().includes(q));
  renderRegTbl(rows);
}
function dlReg(fmt){
  const path=document.getElementById('rp').value.trim();
  if(!path)return;
  window.location.href='/api/registry/report?path='+encodeURIComponent(path)+'&fmt='+fmt;
}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════
# STEP 6 — FLASK APP + ROUTES
# ══════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
def index():
    return render_template_string(HTML)


def _start_analysis_job(cfg):
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = {'id': jid, 'status': 'pending', 'log': [],
                 'results': {}, 'summary': {}, 'output_dir': None,
                 'docx_path': None, 'pdf_path': None,
                 'os_type': cfg.get('os_type','windows'),
                 'evidence': cfg.get('evidence',''),
                 'started': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    th = threading.Thread(target=_run_job, args=(jid, cfg), daemon=True)
    JOBS[jid]['thread'] = th
    JOBS[jid]['report_state'] = 'none'
    JOBS[jid]['ai'] = {'ai_provider': cfg.get('ai_provider', 'none'), 'ai_key': cfg.get('ai_key', '')}
    JOBS[jid]['vt_key'] = cfg.get('vt_key') or ''
    JOBS[jid]['abuse_key'] = cfg.get('abuse_key') or ''
    th.start()
    return jid


@app.route('/api/run', methods=['POST'])
def api_run():
    cfg = request.get_json()
    if cfg and cfg.get('os_type') == 'memory' and not cfg.get('evidence'):
        cfg['evidence'] = cfg.get('memory_path', '')
    if not cfg or not cfg.get('evidence'):
        return jsonify({'error': 'Evidence path is required'}), 400
    return jsonify({'job_id': _start_analysis_job(cfg)})


def acq_prepare_tools(osl, tools_dir, log):
    """Network-connected device: install / fetch the tools acquisition needs for this OS (WinPmem / AVML) before collecting."""
    td = Path(tools_dir); td.mkdir(parents=True, exist_ok=True)
    if str(td) not in os.environ.get("PATH", ""): os.environ["PATH"] = str(td) + os.pathsep + os.environ.get("PATH", "")
    lg = lambda lvl, msg: log.append(f"[tools] {msg}")
    if osl == "windows":
        if shutil.which("winpmem") or shutil.which("winpmem_mini_x64_rc2.exe"): lg("OK", "WinPmem already available"); return
        url = epr_mem_github_latest_asset("Velocidex/WinPmem", [".exe"], lg) or epr_mem_github_latest_asset("Velocidex/c-aff4", ["winpmem", ".exe"], lg)
        lg("OK" if (url and epr_mem_download_file(url, td / "winpmem.exe", lg)) else "WARN", "WinPmem " + ("installed in " + str(td) if (td / "winpmem.exe").exists() else "could not be downloaded - RAM capture will be skipped"))
    elif osl == "linux":
        if shutil.which("avml"): lg("OK", "AVML already available"); return
        ok = epr_mem_download_file("https://github.com/microsoft/avml/releases/latest/download/avml", td / "avml", lg)
        if ok:
            try: (td / "avml").chmod(0o755)
            except Exception: pass
        lg("OK" if ok else "WARN", "AVML " + ("installed in " + str(td) if ok else "could not be downloaded - RAM capture will be skipped"))
    else:
        lg("INFO", "macOS: no extra tools needed for live collection")


def _run_acq(jid, cfg):
    job = JOBS[jid]; log = job['log']
    from contextlib import redirect_stdout, redirect_stderr
    class _Tee:
        def write(self, d):
            for line in d.splitlines():
                if line.strip(): log.append(line)
        def flush(self): pass
    try:
        osl = cfg['os_type']
        case = _safe_case(cfg.get('case_name'))
        base = Path(cfg['output']).expanduser() if cfg.get('output') else OUTPUT_BASE
        name = f"{case}_acquisition" if case else f"acquisition_{osl}_{datetime.now():%Y%m%d_%H%M%S}"
        output = str(_unique_dir(base / name))
        Path(output).mkdir(parents=True, exist_ok=True)
        job.update({'output_dir': output, 'status': 'running', 'evidence': output, 'case': case or ''})
        log.append(f"[?] Acquisition ({osl}) on THIS machine -> {output}")
        _ACQ_TL.answers = {'memory': bool(cfg.get('memory')), 'procs': (cfg.get('procs') or '').strip(), 'fuji': bool(cfg.get('fuji'))}
        try:
            if cfg.get('memory'): acq_prepare_tools(osl, cfg.get('tools_dir') or './tools', log)
        except Exception as _e: log.append(f"[tools] preparation failed: {_e}")
        fn = {'windows': run_windows_acquisition, 'linux': run_linux_acquisition, 'macos': run_macos_acquisition}[osl]
        with redirect_stdout(_Tee()), redirect_stderr(_Tee()):
            collected = fn(output)
        job['evidence'] = str(collected or output)
        job['status'] = 'done'
        job['finished'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log.append(f"[+] Acquisition complete: {job['evidence']}")
        if cfg.get('analyze'):
            acfg = {'os_type': osl, 'evidence': job['evidence'], 'case_name': cfg.get('case_name') or '',
                    'output': str(base) if case else str(Path(base) / f"{Path(output).name}_analysis"),
                    'ai_provider': cfg.get('ai_provider', 'none'), 'ai_key': cfg.get('ai_key', ''),
                    'vt_key': cfg.get('vt_key', ''), 'abuse_key': cfg.get('abuse_key', '')}
            log.append("[?] Starting the analysis automatically on the collected artifacts...")
            job['next_job'] = _start_analysis_job(acfg)
        else:
            log.append("    (You can run the analysis later from the Jobs tab with 'Analyze this evidence')")
    except JobStopped:
        job['status'] = 'stopped'; log.append("[!] Acquisition stopped by user.")
    except Exception as e:
        import traceback
        if job.get('cancel'): job['status'] = 'stopped'; return
        job['status'] = 'error'; log.append(f"[x] Acquisition failed: {e}"); log.append(traceback.format_exc()[-500:])
    finally:
        _ACQ_TL.answers = None


def _run_kit(jid, cfg):
    job = JOBS[jid]; log = job['log']
    try:
        base = Path(cfg['output']).expanduser() if cfg.get('output') else OUTPUT_BASE
        job.update({'status': 'running', 'output_dir': str(base)})
        kit = kit_build(cfg['os_type'], str(base), not cfg.get('no_python'), lambda lvl, msg: log.append(f"[{lvl}] {msg}"))
        job['evidence'] = str(kit); job['status'] = 'done'; job['finished'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log.append(f"[+] Kit ready: {kit}")
        log.append("    Copy this folder to a USB drive and run " + ("RUN_ME.bat" if kit_norm_os(cfg['os_type']) == 'windows' else "sudo ./run_me.sh") + " on the quarantined system.")
    except Exception as e:
        job['status'] = 'error'; log.append(f"[x] Kit build failed: {e}")


@app.route('/api/buildkit', methods=['POST'])
def api_buildkit():
    cfg = request.get_json(silent=True) or {}
    if not kit_norm_os(cfg.get('os_type')): return jsonify({'error': 'Choose the OS of the quarantined system (windows / linux / macos)'}), 400
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = {'id': jid, 'kind': 'kit', 'status': 'pending', 'log': [], 'results': {}, 'summary': {}, 'output_dir': None,
                 'os_type': kit_norm_os(cfg['os_type']), 'evidence': '', 'started': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    th = threading.Thread(target=_run_kit, args=(jid, cfg), daemon=True); JOBS[jid]['thread'] = th; th.start()
    return jsonify({'job_id': jid})


@app.route('/api/checkpath')
def api_checkpath():
    pth = (request.args.get('path') or '').strip()
    if not pth or not Path(pth).expanduser().exists(): return jsonify({'exists': False, 'unreadable': 0, 'examples': []})
    pth = str(Path(pth).expanduser())
    n, ex = uni_unreadable(pth)
    return jsonify({'exists': True, 'unreadable': n, 'examples': [Path(x).name for x in ex], 'fix_cmd': uni_fix_command(pth) if n else ''})


@app.route('/api/fixperms', methods=['POST'])
def api_fixperms():
    pth = str((request.get_json(silent=True) or {}).get('path') or '').strip()
    if not pth or not Path(pth).expanduser().exists(): return jsonify({'error': 'Path not found'}), 400
    pth = str(Path(pth).expanduser())
    ok, msg = uni_fix_permissions(pth)
    n, ex = uni_unreadable(pth)
    return jsonify({'ok': ok, 'message': msg, 'unreadable': n, 'examples': [Path(x).name for x in ex], 'fix_cmd': uni_fix_command(pth) if n else ''})


@app.route('/api/sysinfo')
def api_sysinfo():
    return jsonify({'script': str(Path(__file__).resolve()), 'system': platform.system(), 'os': {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system(), ''),
                    'admin': (hasattr(os, 'geteuid') and os.geteuid() == 0) or (platform.system() == 'Windows' and bool(__import__('ctypes').windll.shell32.IsUserAnAdmin()) if platform.system() == 'Windows' else False)})


@app.route('/api/acquire', methods=['POST'])
def api_acquire():
    cfg = request.get_json(silent=True) or {}
    osl = {'kali': 'linux', 'ubuntu': 'linux'}.get(cfg.get('os_type'), cfg.get('os_type'))
    here = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system())
    if osl not in ('windows', 'linux', 'macos'):
        return jsonify({'error': 'Choose Windows / Linux / Kali / macOS for acquisition'}), 400
    if here and osl != here:
        return jsonify({'error': f"Acquisition only works for the OS of this machine. This machine is {platform.system()} - choose '{here}'."}), 400
    cfg['os_type'] = osl
    if cfg.get('analyze') and cfg.get('ai_provider') in ('anthropic', 'gemini') and not (cfg.get('ai_key') or '').strip():
        return jsonify({'error': 'Enter the API key for this AI provider'}), 400
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = {'id': jid, 'kind': 'acquisition', 'status': 'pending', 'log': [], 'results': {}, 'summary': {}, 'output_dir': None,
                 'os_type': osl, 'evidence': '', 'started': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    th = threading.Thread(target=_run_acq, args=(jid, cfg), daemon=True)
    JOBS[jid]['thread'] = th
    th.start()
    return jsonify({'job_id': jid})


@app.route('/api/reporting')
def api_reporting():
    rows = []
    for j in sorted(JOBS.values(), key=lambda x: x.get('started', ''), reverse=True):
        if j['status'] != 'done' or j.get('kind') in ('acquisition', 'kit'): continue
        if 'rep_meta' not in j:
            try:
                data, _m, cor, scope, _r = rw_load(j)
                r0, r1, n = rw_range(data)
                j['rep_meta'] = {'range': {'min': r0.strftime('%Y-%m-%d %H:%M') if r0 else '', 'max': r1.strftime('%Y-%m-%d %H:%M') if r1 else '', 'n': n},
                                 'presets': rw_presets(data), 'host': ', '.join((scope or {}).get('hosts', [])[:2])}
            except Exception as e:
                j['rep_meta'] = {'range': {'min': '', 'max': '', 'n': 0}, 'presets': [], 'host': '', 'error': str(e)[:120]}
        m = j['rep_meta']
        an = []
        for a in sorted((j.get('analyses') or {}).values(), key=lambda x: x.get('created', ''), reverse=True):
            an.append({k: a.get(k, '') for k in ('id', 'state', 'error', 'label', 'from', 'to', 'ai', 'kpis', 'created')})
        rows.append({'id': j['id'], 'case': j.get('case', ''), 'os_type': j['os_type'], 'evidence': j['evidence'], 'started': j['started'],
                     'finished': j.get('finished', ''), 'host': m.get('host', ''), 'range': m['range'], 'presets': m['presets'],
                     'ai_available': (j.get('ai') or {}).get('ai_provider', 'none') not in (None, '', 'none'),
                     'output_dir': str(j.get('output_dir') or ''), 'analyses': an})
    return jsonify({'jobs': rows})


@app.route('/api/analyze/<jid>', methods=['POST'])
def api_analyze(jid):
    j = JOBS.get(jid)
    if not j: return jsonify({'error': 'Job not found'}), 404
    if j['status'] != 'done': return jsonify({'error': 'The analysis is not complete yet'}), 400
    body = request.get_json(silent=True) or {}
    t_from, t_to = (body.get('from') or '').strip(), (body.get('to') or '').strip()
    if bool(t_from) != bool(t_to): return jsonify({'error': 'Both From and To are required'}), 400
    if t_from and (not rw_parse(t_from) or not rw_parse(t_to) or rw_parse(t_to) <= rw_parse(t_from)):
        return jsonify({'error': 'Invalid time window (To must be after From)'}), 400
    aid = 'a' + str(len(j.get('analyses') or {}) + 1) + '_' + datetime.now().strftime('%H%M%S')
    j.setdefault('analyses', {})[aid] = {'id': aid, 'state': 'running', 'label': (f"{t_from.replace('T', ' ')} -> {t_to.replace('T', ' ')}" if t_from else 'Whole evidence'),
                                          'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    threading.Thread(target=rw_run, args=(j, aid, t_from or None, t_to or None, bool(body.get('ai', True))), daemon=True).start()
    return jsonify({'ok': True, 'id': aid})


@app.route('/api/analysis/<jid>/<aid>/<what>')
def api_analysis_file(jid, aid, what):
    j = JOBS.get(jid); a = ((j or {}).get('analyses') or {}).get(aid)
    if not a or a.get('state') != 'done': return 'Analysis not ready', 404
    case = j.get('case') or 'forensics'
    if what == 'html': return send_file(a['html'], mimetype='text/html')
    if what == 'dashboard': return send_file(a['html'], mimetype='text/html', as_attachment=True, download_name=f"{case}_dashboard_{aid}.html")
    if what in ('docx', 'pdf') and a.get(what): return send_file(a[what], as_attachment=True, download_name=Path(a[what]).name)
    return 'Not found', 404


@app.route('/api/genreport/<jid>', methods=['POST'])
def api_genreport(jid):
    j = JOBS.get(jid)
    if not j: return jsonify({'error': 'Job not found'}), 404
    if j['status'] != 'done': return jsonify({'error': 'The analysis is not complete yet'}), 400
    if j.get('report_state') == 'generating':
        return jsonify({'error': 'The report is already being built'}), 400
    threading.Thread(target=_gen_report, args=(jid,), daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/stop/<jid>', methods=['POST'])
def api_stop(jid):
    j = JOBS.get(jid)
    if not j: return jsonify({'error': 'Job not found'}), 404
    if j['status'] not in ('running', 'pending'):
        return jsonify({'error': f"Job already {j['status']}"}), 400
    _stop_job(j)
    return jsonify({'ok': True, 'status': j['status']})


@app.route('/api/status/<jid>')
def api_status(jid):
    j = JOBS.get(jid)
    if not j: return jsonify({'error': 'Job not found'}), 404
    _since = request.args.get('since', default=0, type=int)
    return jsonify({'id': j['id'], 'kind': j.get('kind', 'analysis'), 'next_job': j.get('next_job', ''), 'status': j['status'], 'log': j['log'][_since:], 'total': len(j['log']),
                    'summary': j['summary'], 'has_docx': bool(j.get('docx_path')),
                    'has_pdf': bool(j.get('pdf_path'))})


@app.route('/api/jobs')
def api_jobs():
    return jsonify({'jobs': [{'id':j['id'],'kind':j.get('kind','analysis'),'next_job':j.get('next_job',''),'status':j['status'],'os_type':j['os_type'],
                               'evidence':j['evidence'],'started':j['started'],'case':j.get('case',''),'output_dir':str(j.get('output_dir') or ''),
                               'report_state': j.get('report_state','none'),
                               'report_error': j.get('report_error',''),
                               'has_docx': bool(j.get('docx_path')), 'has_pdf': bool(j.get('pdf_path')),
                               'summary': j.get('summary') or {}}
                              for j in reversed(list(JOBS.values()))]})


@app.route('/api/report/<jid>/<fmt>')
def api_report(jid, fmt):
    j = JOBS.get(jid)
    if not j: return jsonify({'error': 'Job not found'}), 404
    if j['status'] != 'done': return jsonify({'error': 'The job is not complete yet'}), 400
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'docx':
        p = j.get('docx_path')
        if not p or not Path(p).exists(): return jsonify({'error': 'DOCX not found'}), 404
        return send_file(p, as_attachment=True, download_name=(f"{j['case']}_report.docx" if j.get('case') else f'forensics_{ts}.docx'),
                         mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    if fmt == 'pdf':
        p = j.get('pdf_path')
        if not p or not Path(p).exists(): return jsonify({'error': 'PDF not found'}), 404
        return send_file(p, as_attachment=True, download_name=(f"{j['case']}_report.pdf" if j.get('case') else f'forensics_{ts}.pdf'),
                         mimetype='application/pdf')
    if fmt == 'html':
        dash = Path(j['output_dir']) / 'dashboard.html'
        if not dash.exists(): return jsonify({'error': 'HTML dashboard not found'}), 404
        return send_file(str(dash), as_attachment=True, download_name=(f"{j['case']}_dashboard.html" if j.get('case') else f'dashboard_{ts}.html'))
    if fmt == 'json':
        buf = io.BytesIO(json.dumps(j['results'], indent=2, default=str).encode())
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f'forensics_{ts}.json',
                         mimetype='application/json')
    return jsonify({'error': 'Unknown format'}), 400


@app.route('/api/registry/analyze', methods=['POST'])
def api_reg_analyze():
    data = request.get_json()
    path = (data or {}).get('path','').strip()
    if not path: return jsonify({'error': 'Path do'}), 400
    p = Path(path)
    if not p.exists(): return jsonify({'error': f'Path not found: {path}'}), 400
    try:
        if p.is_file():
            r = _analyze_hive(p)
            return jsonify({'findings': r['findings'], 'hives': [r],
                            'external_ips': r['stats'].get('external_ips',[])})
        results = _analyze_reg_folder(p)
        if not results:
            return jsonify({'error': 'No registry hive found. Look for NTUSER.DAT, SAM, SYSTEM, SOFTWARE, SECURITY.'}), 404
        all_f, all_ips = [], []
        for r in results:
            all_f.extend(r['findings'])
            all_ips.extend(r['stats'].get('external_ips',[]))
        return jsonify({'findings': all_f, 'hives': results, 'external_ips': list(set(all_ips))})
    except Exception as e:
        import traceback
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500


@app.route('/api/registry/report')
def api_reg_report():
    path = request.args.get('path','').strip()
    fmt  = request.args.get('fmt','json')
    if not path: return jsonify({'error': 'Path do'}), 400
    p = Path(path)
    if not p.exists(): return jsonify({'error': 'Path not found'}), 400
    results = [_analyze_hive(p)] if p.is_file() else _analyze_reg_folder(p)
    all_f = [f for r in results for f in r['findings']]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'json':
        buf = io.BytesIO(json.dumps({'findings': all_f}, indent=2, default=str).encode())
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f'registry_{ts}.json', mimetype='application/json')
    if fmt == 'csv':
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(['Severity','Hive','Key','Value Name','Type','Value Data','Pattern','Last Written'])
        for f in all_f:
            w.writerow([f.get('severity',''),f.get('hive',''),f.get('key',''),
                        f.get('name',''),f.get('type',''),f.get('data','')[:400],
                        f.get('pattern',''),f.get('last_written','')])
        buf = io.BytesIO(out.getvalue().encode()); buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f'registry_{ts}.csv', mimetype='text/csv')
    return jsonify({'error': 'Unknown format'}), 400


# ══════════════════════════════════════════════════════════════════════
# STEP 7 — LAUNCH
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    if '--build-kit' in sys.argv:       # build an offline acquisition kit for a quarantined system
        kit_cli(sys.argv[1:]); sys.exit(0)
    if '--cli' in sys.argv:          # terminal launcher: Forensics + Acquisition menu
        main(); sys.exit(0)
    port = int(os.environ.get('PORT', 5000))
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   🛡  FORENSICS MASTER ANALYZER — Web GUI                       ║
╠══════════════════════════════════════════════════════════════════╣
║   Browser mein kholo:  http://localhost:{port}                     ║
║   Band karne ke liye:  Ctrl+C                                    ║
╠══════════════════════════════════════════════════════════════════╣
╚══════════════════════════════════════════════════════════════════╝
""")
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)
