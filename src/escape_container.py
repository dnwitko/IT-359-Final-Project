#!/usr/bin/env python3
"""
EscapeContainer - Docker container escape-vector fingerprinter.
Usage:
    python3 escape_container.py                    # full report (text)
    python3 escape_container.py --min-severity high # only HIGH/CRITICAL
    python3 escape_container.py --category capabilities
    python3 escape_container.py --json
    python3 escape_container.py --list-checks       # enumerate checks, don't run
    python3 escape_container.py -o report.txt
    python3 escape_container.py --show-passed        # list non-triggered too

Exit code is 0 when no HIGH/CRITICAL findings, 1 otherwise (CI-friendly).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import shutil
import socket
import sys
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Callable, Optional

# ----------------------------------------------------------------------------
# Optional colors
# ----------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    _HAVE_COLOR = True
except Exception:  # pragma: no cover
    _HAVE_COLOR = False

    class _Dummy:
        def __getattr__(self, _n):
            return ""

    Fore = _Dummy()   # type: ignore
    Style = _Dummy()  # type: ignore


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


SEV_COLOR = {
    Severity.INFO: Fore.CYAN,
    Severity.LOW: Fore.BLUE,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.HIGH: Fore.MAGENTA,
    Severity.CRITICAL: Fore.RED,
}

SEV_BY_NAME = {s.name.lower(): s for s in Severity}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    detected: bool
    evidence: str
    why: str
    remediation: str
    category: str = "misc"
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


# ----------------------------------------------------------------------------
# Safe read-only helpers
# ----------------------------------------------------------------------------
def _read(path: str, limit: int = 65536) -> Optional[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return None


def _exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def _listdir(path: str) -> list[str]:
    try:
        return os.listdir(path)
    except Exception:
        return []


# ----------------------------------------------------------------------------
# Environment detection
# ----------------------------------------------------------------------------
def in_container() -> tuple[bool, str]:
    reasons = []
    if _exists("/.dockerenv"):
        reasons.append("/.dockerenv present")
    cgroup = _read("/proc/1/cgroup") or ""
    if re.search(r"docker|containerd|kubepods|lxc", cgroup):
        reasons.append("container keyword in /proc/1/cgroup")
    sched = _read("/proc/1/sched") or ""
    first = sched.splitlines()[0] if sched else ""
    if first and not first.startswith(("systemd", "init")):
        reasons.append(f"PID 1 is '{first.split()[0]}'")
    return (bool(reasons), "; ".join(reasons) if reasons else "no container markers found")


# ----------------------------------------------------------------------------
# Capabilities
# ----------------------------------------------------------------------------
# bit -> (name, severity, why). Full Linux capability set (0..40).
CAP_META: dict[int, tuple[str, Severity, str]] = {
    0:  ("CAP_CHOWN", Severity.LOW, "Change file ownership; can enable privilege tricks on shared mounts."),
    1:  ("CAP_DAC_OVERRIDE", Severity.MEDIUM, "Bypass file read/write/execute permission checks."),
    2:  ("CAP_DAC_READ_SEARCH", Severity.HIGH, "Read any file and traverse any directory, bypassing permissions (shocker-style host file reads)."),
    3:  ("CAP_FOWNER", Severity.MEDIUM, "Bypass permission checks on operations that normally require file ownership."),
    4:  ("CAP_FSETID", Severity.LOW, "Keep setuid/setgid bits when modifying files."),
    5:  ("CAP_KILL", Severity.LOW, "Send signals to arbitrary processes."),
    6:  ("CAP_SETGID", Severity.MEDIUM, "Manipulate group IDs; part of many local-escalation chains."),
    7:  ("CAP_SETUID", Severity.MEDIUM, "Manipulate user IDs; lets a process become root uid in its userns."),
    8:  ("CAP_SETPCAP", Severity.MEDIUM, "Transfer/drop capabilities; can widen a process's own capability set."),
    9:  ("CAP_LINUX_IMMUTABLE", Severity.LOW, "Set/clear immutable and append-only file attributes."),
    10: ("CAP_NET_BIND_SERVICE", Severity.LOW, "Bind to privileged ports (<1024)."),
    11: ("CAP_NET_BROADCAST", Severity.LOW, "Make socket broadcasts."),
    12: ("CAP_NET_ADMIN", Severity.MEDIUM, "Full network configuration: interfaces, firewall, routing, promiscuous mode."),
    13: ("CAP_NET_RAW", Severity.LOW, "Use raw/packet sockets; enables sniffing and ARP/IP spoofing."),
    14: ("CAP_IPC_LOCK", Severity.LOW, "Lock memory; can pin large regions."),
    15: ("CAP_IPC_OWNER", Severity.LOW, "Bypass IPC object permission checks."),
    16: ("CAP_SYS_MODULE", Severity.CRITICAL, "Load/unload kernel modules = run arbitrary code in the host kernel. Direct escape."),
    17: ("CAP_SYS_RAWIO", Severity.HIGH, "Raw I/O port and /dev/mem-style access to physical memory/hardware."),
    18: ("CAP_SYS_CHROOT", Severity.MEDIUM, "Use chroot(); assists some breakout and confinement-evasion tricks."),
    19: ("CAP_SYS_PTRACE", Severity.HIGH, "ptrace any process; with a shared PID namespace, inject into host processes."),
    20: ("CAP_SYS_PACCT", Severity.LOW, "Configure process accounting."),
    21: ("CAP_SYS_ADMIN", Severity.CRITICAL, "The 'god' capability: mount, pivot_root, remount, BPF, and much more. Core of most escapes."),
    22: ("CAP_SYS_BOOT", Severity.HIGH, "Reboot and load a new kernel via kexec."),
    23: ("CAP_SYS_NICE", Severity.LOW, "Change process priority/scheduling and CPU affinity."),
    24: ("CAP_SYS_RESOURCE", Severity.MEDIUM, "Override resource limits, reserved space and quotas."),
    25: ("CAP_SYS_TIME", Severity.MEDIUM, "Set the system clock and RTC (affects the host clock)."),
    26: ("CAP_SYS_TTY_CONFIG", Severity.LOW, "Configure TTY devices; vhangup."),
    27: ("CAP_MKNOD", Severity.MEDIUM, "Create device nodes (mknod); craft a device to reach host storage."),
    28: ("CAP_LEASE", Severity.LOW, "Establish file leases."),
    29: ("CAP_AUDIT_WRITE", Severity.LOW, "Write records to the kernel audit log."),
    30: ("CAP_AUDIT_CONTROL", Severity.LOW, "Enable/disable and configure kernel auditing."),
    31: ("CAP_SETFCAP", Severity.MEDIUM, "Set file capabilities; can grant capabilities to binaries."),
    32: ("CAP_MAC_OVERRIDE", Severity.HIGH, "Override Mandatory Access Control (SMACK/AppArmor) policy."),
    33: ("CAP_MAC_ADMIN", Severity.HIGH, "Configure or disable Mandatory Access Control policy."),
    34: ("CAP_SYSLOG", Severity.LOW, "Read kernel ring buffer; can leak kernel pointers (KASLR bypass aid)."),
    35: ("CAP_WAKE_ALARM", Severity.LOW, "Trigger wake alarms."),
    36: ("CAP_BLOCK_SUSPEND", Severity.LOW, "Block system suspend."),
    37: ("CAP_AUDIT_READ", Severity.LOW, "Read the audit log via multicast netlink."),
    38: ("CAP_PERFMON", Severity.MEDIUM, "Performance monitoring / perf_events; broadens kernel attack surface."),
    39: ("CAP_BPF", Severity.HIGH, "Load BPF programs; historically a rich source of privilege-escalation bugs."),
    40: ("CAP_CHECKPOINT_RESTORE", Severity.MEDIUM, "Checkpoint/restore; can open files by inode and manipulate ns."),
}

# Capabilities Docker grants by default (for contextual evidence).
DOCKER_DEFAULT_CAPS = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD",
    "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

_caps_cache: Optional[set[str]] = None


def effective_caps() -> set[str]:
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache
    status = _read("/proc/self/status") or ""
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status, re.MULTILINE)
    caps: set[str] = set()
    if m:
        try:
            bits = int(m.group(1), 16)
            for bit, (name, _s, _w) in CAP_META.items():
                if bits & (1 << bit):
                    caps.add(name)
            if bits >= (1 << 40) - 1:
                caps.add("CAP_FULL_SET")
        except ValueError:
            pass
    _caps_cache = caps
    return caps


# ----------------------------------------------------------------------------
# Cached mountinfo parse
# ----------------------------------------------------------------------------
@dataclass
class MountEntry:
    root: str          # path within source fs (field 4)
    mountpoint: str    # field 5
    opts: list[str]    # field 6 (per-mount options)
    fstype: str        # after " - "
    source: str


_mounts_cache: Optional[list[MountEntry]] = None


def mounts() -> list[MountEntry]:
    global _mounts_cache
    if _mounts_cache is not None:
        return _mounts_cache
    out: list[MountEntry] = []
    data = _read("/proc/self/mountinfo") or ""
    for line in data.splitlines():
        if " - " not in line:
            continue
        pre, post = line.split(" - ", 1)
        pf = pre.split()
        pp = post.split()
        if len(pf) < 6 or len(pp) < 2:
            continue
        out.append(MountEntry(root=pf[3], mountpoint=pf[4], opts=pf[5].split(","),
                              fstype=pp[0], source=pp[1]))
    _mounts_cache = out
    return out


# ----------------------------------------------------------------------------
# Check factory helpers (data-driven) - each returns a zero-arg callable.
# ----------------------------------------------------------------------------
def _mk_capability_check(bit: int):
    name, sev, why = CAP_META[bit]
    cid = "cap_" + name.replace("CAP_", "").lower()

    def _check() -> Finding:
        present = name in effective_caps() or "CAP_FULL_SET" in effective_caps()
        default_note = " (in Docker default set)" if name in DOCKER_DEFAULT_CAPS else ""
        return Finding(
            check_id=cid,
            title=f"Capability {name} is held",
            severity=sev,
            detected=present,
            evidence=(f"{name} present in effective set{default_note}" if present
                      else f"{name} not in effective set"),
            why=why,
            remediation=(f"Drop it: start from --cap-drop ALL and only --cap-add what is "
                         f"needed. {name} should be added only with a clear justification."),
            category="capabilities",
            references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
        )

    return _check


# Sensitive device nodes: path -> (severity, short desc, why)
DEVICE_META: dict[str, tuple[Severity, str, str]] = {
    "/dev/mem":   (Severity.CRITICAL, "physical memory", "Direct read/write of physical RAM bypasses all isolation."),
    "/dev/kmem":  (Severity.CRITICAL, "kernel virtual memory", "Direct access to kernel memory = full host compromise."),
    "/dev/kcore": (Severity.CRITICAL, "kernel core image", "Exposes kernel memory for reading; leaks secrets and defeats KASLR."),
    "/dev/port":  (Severity.HIGH, "I/O ports", "Raw I/O port access can reach hardware and memory."),
    "/dev/kmsg":  (Severity.LOW, "kernel log buffer", "Leaks kernel messages/pointers useful for exploitation."),
    "/dev/mqueue":(Severity.LOW, "POSIX message queues", "Shared mqueue can leak host IPC state."),
    "/dev/fuse":  (Severity.MEDIUM, "FUSE control", "Userspace filesystems can be abused for confused-deputy mounts."),
    "/dev/dri":   (Severity.MEDIUM, "GPU direct rendering", "GPU device access has a history of escape-grade driver bugs."),
    "/dev/sda":   (Severity.CRITICAL, "host block device", "A host disk device node lets you mount and read/write the host filesystem."),
    "/dev/vda":   (Severity.CRITICAL, "host block device", "A host disk device node lets you mount and read/write the host filesystem."),
    "/dev/nvme0n1":(Severity.CRITICAL, "host NVMe device", "A host disk device node lets you mount and read/write the host filesystem."),
    "/dev/console":(Severity.LOW, "host console", "A mapped host console can leak or accept host-side I/O."),
}


def _mk_device_check(path: str):
    sev, desc, why = DEVICE_META[path]
    cid = "dev_" + re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")

    def _check() -> Finding:
        present = _exists(path)
        mode = ""
        if present:
            r = os.access(path, os.R_OK)
            w = os.access(path, os.W_OK)
            mode = f" ({'r' if r else '-'}{'w' if w else '-'})"
        return Finding(
            check_id=cid,
            title=f"Device node {path} ({desc}) is present",
            severity=sev,
            detected=present,
            evidence=(f"{path} present{mode}" if present else f"{path} not present"),
            why=why,
            remediation="Do not map this device into the container; keep the default device cgroup allow-list and avoid --privileged.",
            category="devices",
            references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"],
        )

    return _check


# Writable sysctl / proc entries: path -> (severity, desc, why)
SYSCTL_META: dict[str, tuple[Severity, str, str]] = {
    "/proc/sys/kernel/core_pattern": (Severity.CRITICAL, "core_pattern", "Writable core_pattern lets the kernel run an attacker program on crash (classic escape)."),
    "/proc/sys/kernel/modprobe": (Severity.CRITICAL, "modprobe path", "Writable modprobe redirects automatic module loading to an attacker binary (runs as root on host)."),
    "/proc/sys/kernel/kexec_load_disabled": (Severity.MEDIUM, "kexec toggle", "Re-enabling kexec can allow loading a new kernel."),
    "/proc/sysrq-trigger": (Severity.MEDIUM, "sysrq trigger", "Writable sysrq-trigger can crash/reboot the host or invoke debug actions."),
    "/proc/sys/kernel/sysrq": (Severity.LOW, "sysrq enable", "Enables magic SysRq key functions affecting the host."),
    "/proc/sys/kernel/kptr_restrict": (Severity.LOW, "kptr_restrict", "Lowering it leaks kernel pointers (defeats KASLR)."),
    "/proc/sys/kernel/dmesg_restrict": (Severity.LOW, "dmesg_restrict", "Lowering it exposes kernel log to unprivileged users."),
    "/sys/kernel/uevent_helper": (Severity.CRITICAL, "uevent_helper", "Writable uevent_helper runs an attacker program on device events in host context."),
}


def _mk_sysctl_check(path: str):
    sev, desc, why = SYSCTL_META[path]
    cid = "sysctl_" + re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")

    def _check() -> Finding:
        present = _exists(path)
        writable = present and os.access(path, os.W_OK)
        return Finding(
            check_id=cid,
            title=f"{desc} ({path}) is writable",
            severity=sev,
            detected=bool(writable),
            evidence=(f"{path} is writable" if writable else
                      (f"{path} present but read-only" if present else f"{path} not present")),
            why=why,
            remediation="Keep /proc/sys and /sys read-only inside containers (Docker default) and avoid CAP_SYS_ADMIN (allows remounting rw).",
            category="proc_sys",
            references=["https://docs.docker.com/engine/security/"],
        )

    return _check


# Secret / credential files that indicate exposure when present.
SECRET_FILE_META: list[tuple[str, list[str], Severity, str]] = [
    ("ssh_private_key", ["/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", os.path.expanduser("~/.ssh/id_rsa")], Severity.MEDIUM, "A private SSH key in the image/container enables lateral movement."),
    ("aws_credentials", ["/root/.aws/credentials", os.path.expanduser("~/.aws/credentials")], Severity.MEDIUM, "AWS credentials enable pivoting to the cloud control plane."),
    ("docker_config", ["/root/.docker/config.json", os.path.expanduser("~/.docker/config.json")], Severity.MEDIUM, "Docker registry credentials can be reused against private registries."),
    ("kube_admin_conf", ["/etc/kubernetes/admin.conf"], Severity.HIGH, "A host Kubernetes admin kubeconfig exposed in the container yields cluster-admin."),
    ("kubeconfig", ["/root/.kube/config", os.path.expanduser("~/.kube/config")], Severity.MEDIUM, "A kubeconfig grants whatever cluster access its context holds."),
    ("netrc", ["/root/.netrc", os.path.expanduser("~/.netrc")], Severity.LOW, "A .netrc commonly stores plaintext credentials."),
    ("gcloud_adc", ["/root/.config/gcloud/application_default_credentials.json"], Severity.MEDIUM, "GCP application-default credentials enable cloud pivoting."),
    ("shell_history", ["/root/.bash_history", "/root/.zsh_history"], Severity.LOW, "Shell history frequently leaks secrets typed on the command line."),
]


def _mk_secret_file_check(cid: str, paths: list[str], sev: Severity, why: str):
    def _check() -> Finding:
        hits = [p for p in paths if p and _exists(p)]
        return Finding(
            check_id="secretfile_" + cid,
            title=f"Credential file present: {cid.replace('_', ' ')}",
            severity=sev,
            detected=bool(hits),
            evidence=("present: " + ", ".join(hits)) if hits else "not present",
            why=why,
            remediation="Do not bake credentials into images or mount host credential files; use a secrets manager and short-lived tokens.",
            category="secret_files",
            references=["https://docs.docker.com/engine/swarm/secrets/"],
        )

    return _check


# Tooling that aids pivoting/recon once a foothold exists.
TOOL_META: dict[str, tuple[Severity, str]] = {
    "nsenter": (Severity.MEDIUM, "nsenter enters other namespaces; a direct aid to crossing into host namespaces if reachable."),
    "docker":  (Severity.LOW, "A docker client inside the container is dangerous if any docker socket is reachable."),
    "kubectl": (Severity.LOW, "kubectl eases cluster recon/pivoting if an API and token are reachable."),
    "runc":    (Severity.LOW, "runc present inside a container can be abused in some escape chains."),
    "ctr":     (Severity.LOW, "containerd CLI eases interaction with a reachable containerd socket."),
    "crictl":  (Severity.LOW, "CRI CLI eases interaction with a reachable CRI runtime."),
    "socat":   (Severity.LOW, "socat is a flexible relay often used to reach host-local services/sockets."),
    "nc":      (Severity.LOW, "netcat aids pivoting and reaching host-local services."),
}


def _mk_tool_check(tool: str):
    sev, why = TOOL_META[tool]

    def _check() -> Finding:
        path = shutil.which(tool)
        return Finding(
            check_id="tool_" + tool,
            title=f"Pivot tool '{tool}' is installed",
            severity=sev,
            detected=bool(path),
            evidence=(f"{tool} at {path}" if path else f"{tool} not found in PATH"),
            why=why,
            remediation="Ship minimal images; omit debugging/pivot tooling from production containers.",
            category="tooling",
            references=["https://docs.docker.com/develop/security-best-practices/"],
        )

    return _check


# Kernel CVE version ranges (advisory, version-string based).
# (cid, name, intro (inclusive) or None, fixed (exclusive), severity, why)
CVE_META: list[tuple[str, str, Optional[tuple[int, int, int]], tuple[int, int, int], Severity, str]] = [
    ("dirtycow", "Dirty COW (CVE-2016-5195)", None, (4, 8, 3), Severity.LOW,
     "COW race giving write access to read-only memory; used for local root and container escape."),
    ("dirtypipe", "Dirty Pipe (CVE-2022-0847)", (5, 8, 0), (5, 16, 11), Severity.LOW,
     "Pipe buffer flaw allowing overwrite of read-only files; usable to escape containers."),
    ("fsconfig", "CVE-2022-0185 (fsconfig heap overflow)", (5, 1, 0), (5, 16, 2), Severity.LOW,
     "Heap overflow in legacy fs context; demonstrated container escape with user namespaces."),
    ("af_packet_7308", "CVE-2017-7308 (af_packet)", None, (4, 10, 7), Severity.LOW,
     "Packet socket overflow enabling local privilege escalation."),
    ("af_packet_8655", "CVE-2016-8655 (af_packet race)", None, (4, 8, 14), Severity.LOW,
     "Race in packet sockets enabling local privilege escalation."),
    ("ufo_112", "CVE-2017-1000112 (UFO)", None, (4, 13, 0), Severity.LOW,
     "UDP fragmentation offload overflow enabling local privilege escalation."),
    ("netfilter_22555", "CVE-2021-22555 (netfilter)", None, (5, 12, 0), Severity.LOW,
     "Netfilter heap out-of-bounds write usable for container escape."),
]


def _parse_kver(release: str) -> Optional[tuple[int, int, int]]:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", release)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())  # type: ignore


def _mk_cve_check(cid: str, name: str, intro, fixed, sev: Severity, why: str):
    def _check() -> Finding:
        release = platform.release()
        ver = _parse_kver(release)
        in_range = False
        if ver is not None:
            in_range = ver < fixed and (intro is None or ver >= intro)
        return Finding(
            check_id="cve_" + cid,
            title=f"Kernel may be affected by {name}",
            severity=sev,
            detected=bool(in_range),
            evidence=(f"kernel {release} is below the fixed version "
                      f"{'.'.join(map(str, fixed))}" if in_range
                      else f"kernel {release} not in the affected range"),
            why=why + " Advisory only: distributions backport fixes, so the version string can over-report. Verify against your distro's tracker.",
            remediation="Confirm the running kernel's real patch level against your distribution's security tracker and keep the host kernel updated.",
            category="kernel_cve",
            references=["https://www.cve.org/"],
        )

    return _check


# ----------------------------------------------------------------------------
# Singleton checks (bespoke logic)
# ----------------------------------------------------------------------------
def check_privileged() -> Finding:
    caps = effective_caps()
    devices = _listdir("/dev")
    host_disks = [d for d in devices if re.match(r"^(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z])", d)]
    likely = ("CAP_FULL_SET" in caps) or bool(host_disks)
    ev = []
    if "CAP_FULL_SET" in caps:
        ev.append("effective capability set is full")
    if host_disks:
        ev.append(f"host block devices in /dev: {', '.join(sorted(host_disks))}")
    return Finding("privileged_mode", "Container appears to run in --privileged mode",
                   Severity.CRITICAL, likely,
                   "; ".join(ev) if ev else "no privileged markers found",
                   "Privileged containers hold all capabilities and see host devices, allowing the host filesystem to be mounted and modified.",
                   "Never use --privileged. Grant specific --cap-add and --device only as needed.",
                   "config",
                   ["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"])


def check_docker_socket() -> Finding:
    found = [p for p in ("/var/run/docker.sock", "/run/docker.sock") if _exists(p)]
    return Finding("docker_socket_mounted", "Docker daemon socket is mounted in the container",
                   Severity.CRITICAL, bool(found),
                   ("present: " + ", ".join(found)) if found else "no docker socket found",
                   "Access to docker.sock is equivalent to root on the host: the daemon can start a container mounting the host filesystem.",
                   "Never bind-mount docker.sock into a container; use a brokered proxy or rootless Docker if the API is truly needed.",
                   "config",
                   ["https://docs.docker.com/engine/security/#docker-daemon-attack-surface"])


def check_containerd_socket() -> Finding:
    found = [p for p in ("/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
                         "/run/podman/podman.sock") if _exists(p)]
    return Finding("runtime_socket_mounted", "A container runtime socket (containerd/CRI-O/podman) is mounted",
                   Severity.CRITICAL, bool(found),
                   ("present: " + ", ".join(found)) if found else "no containerd/CRI-O/podman socket found",
                   "A runtime control socket lets a container create new containers with host mounts, equivalent to host root.",
                   "Do not mount runtime sockets into containers.",
                   "config",
                   ["https://docs.docker.com/engine/security/"])


def check_host_pid() -> Finding:
    pids = [d for d in _listdir("/proc") if d.isdigit()]
    comm = (_read("/proc/1/comm") or "").strip()
    detected = len(pids) > 50 and comm in ("systemd", "init")
    return Finding("host_pid_namespace", "Host PID namespace appears shared (--pid=host)",
                   Severity.HIGH, detected,
                   f"{len(pids)} processes visible, PID 1 comm='{comm}'",
                   "Sharing the host PID namespace exposes all host processes, enabling inspection and, with other privileges, injection.",
                   "Do not use --pid=host unless genuinely required.", "namespaces",
                   ["https://docs.docker.com/engine/reference/run/#pid-settings---pid"])


def check_host_network() -> Finding:
    ifaces = _listdir("/sys/class/net")
    host_like = [i for i in ifaces if re.match(r"^(eth[1-9]|en[ospx]|wl|docker0|br-|virbr|bond|team)", i)]
    return Finding("host_network_namespace", "Host network namespace appears shared (--net=host)",
                   Severity.MEDIUM, bool(host_like),
                   f"interfaces: {', '.join(sorted(ifaces)) or 'none'}"
                   + (f" (host-like: {', '.join(sorted(host_like))})" if host_like else ""),
                   "With --net=host the container shares the host network stack and can reach host-local services and sniff/spoof traffic.",
                   "Use default bridge networking and publish only needed ports.", "namespaces",
                   ["https://docs.docker.com/engine/reference/run/#network-settings"])


def check_host_mounts() -> Finding:
    sensitive = {"/": "host root", "/etc": "host /etc", "/root": "host root home",
                 "/var/run": "host runtime dir", "/run": "host runtime dir",
                 "/boot": "host boot", "/home": "host homes", "/var/lib/docker": "docker data root"}
    hits = []
    for mnt in mounts():
        # A bind of a host path shows that host path as the mount 'root'.
        if mnt.root in sensitive and mnt.mountpoint != "/":
            ro = "ro" in mnt.opts
            hits.append(f"{sensitive[mnt.root]} ({mnt.root}) at {mnt.mountpoint} ({'ro' if ro else 'rw'})")
    return Finding("sensitive_host_mounts", "Sensitive host paths are bind-mounted into the container",
                   Severity.HIGH, bool(hits),
                   "; ".join(sorted(set(hits))) if hits else "no sensitive host bind-mounts detected",
                   "Bind-mounting host paths (especially writable host root, /etc or /root) lets a container modify files the host later trusts (SSH keys, cron, binaries).",
                   "Avoid mounting host system paths; share a narrow, dedicated directory read-only.", "mounts",
                   ["https://docs.docker.com/storage/bind-mounts/"])


def check_cgroup_release_agent() -> Finding:
    hits = []
    for base in ("/sys/fs/cgroup", "/sys/fs/cgroup/rdma", "/sys/fs/cgroup/memory"):
        ra = os.path.join(base, "release_agent")
        if _exists(ra) and os.access(ra, os.W_OK):
            hits.append(ra)
    return Finding("cgroup_release_agent", "Writable cgroup release_agent",
                   Severity.CRITICAL, bool(hits),
                   "; ".join(hits) if hits else "no writable release_agent found",
                   "A writable release_agent plus the ability to create cgroups runs an attacker program on the host when a cgroup empties.",
                   "Keep cgroup mounts read-only and avoid CAP_SYS_ADMIN.", "cgroups",
                   ["https://docs.docker.com/engine/security/"])


def check_core_pattern_pipe() -> Finding:
    # core_pattern is a GLOBAL (non-namespaced) kernel setting, so inside any
    # container it reflects the HOST value. On a systemd host that is normally
    # '|/usr/lib/systemd/systemd-coredump ...'. A pipe handler is only an escape
    # primitive when the container can ALSO write core_pattern (or is privileged)
    # and trigger a crash. A read-only inherited pipe handler is expected and is
    # NOT high severity - rating it HIGH everywhere is a false positive on every
    # systemd host.
    path = "/proc/sys/kernel/core_pattern"
    cp = (_read(path) or "").strip()
    is_pipe = cp.startswith("|")
    writable = _exists(path) and os.access(path, os.W_OK)
    if is_pipe and writable:
        sev, detected = Severity.HIGH, True
        ev = f"core_pattern is a WRITABLE pipe handler: {cp!r}"
    elif is_pipe:
        sev, detected = Severity.INFO, True
        ev = f"core_pattern is a pipe handler, read-only here (inherited from host): {cp!r}"
    else:
        sev, detected = Severity.INFO, False
        ev = f"core_pattern={cp!r}" if cp else "core_pattern empty/unreadable"
    return Finding("core_pattern_pipe", "core_pattern is set to a pipe handler",
                   sev, detected, ev,
                   "A WRITABLE '|handler' core_pattern lets a container run a program on the host at crash time. Inherited read-only from a systemd host it is normal and not exploitable on its own.",
                   "Keep /proc/sys read-only so the container cannot write core_pattern; the pipe handler itself is a host-level setting.", "proc_sys",
                   ["https://man7.org/linux/man-pages/man5/core.5.html"])


def check_proc_host_leak() -> Finding:
    leaks = []
    sd = _read("/proc/sched_debug")
    if sd and re.search(r"\binit\b|\bsystemd\b", sd):
        leaks.append("/proc/sched_debug lists host-level tasks")
    try:
        if os.readlink("/proc/1/root") == "/" and not _exists("/.dockerenv"):
            leaks.append("/proc/1/root resolves to host /")
    except Exception:
        pass
    return Finding("proc_host_leak", "Host information leaks through /proc",
                   Severity.MEDIUM, bool(leaks),
                   "; ".join(leaks) if leaks else "no /proc host leaks detected",
                   "Certain /proc entries reveal host processes or filesystem when masking is incomplete, aiding reconnaissance.",
                   "Keep default /proc masking; avoid mounting host /proc and avoid CAP_SYS_ADMIN.", "namespaces",
                   ["https://docs.docker.com/engine/security/"])


def check_mount_nosuid_nodev() -> Finding:
    risky = []
    for mnt in mounts():
        if "rw" in mnt.opts and mnt.mountpoint.startswith(("/mnt", "/data", "/vol", "/host", "/media")):
            missing = [o for o in ("nosuid", "nodev") if o not in mnt.opts]
            if missing:
                risky.append(f"{mnt.mountpoint} (missing: {', '.join(missing)})")
    return Finding("mount_nosuid_nodev", "Writable volumes allow setuid binaries or device nodes",
                   Severity.MEDIUM, bool(risky),
                   "; ".join(risky) if risky else "writable volumes carry nosuid/nodev",
                   "A writable mount without nosuid lets a planted setuid-root binary run elevated; without nodev it can host device nodes.",
                   "Mount volumes with nosuid,nodev,noexec unless specifically required.", "mounts",
                   ["https://man7.org/linux/man-pages/man8/mount.8.html"])


def check_seccomp() -> Finding:
    status = _read("/proc/self/status") or ""
    m = re.search(r"^Seccomp:\s*(\d+)", status, re.MULTILINE)
    mode = int(m.group(1)) if m else None
    return Finding("seccomp_disabled", "seccomp syscall filtering is disabled",
                   Severity.MEDIUM, mode == 0,
                   f"Seccomp mode={mode}" if mode is not None else "seccomp mode unknown",
                   "seccomp restricts which syscalls a container may make. Unconfined exposes the full kernel syscall surface.",
                   "Keep Docker's default seccomp profile; relax only with a scoped custom profile.", "mac",
                   ["https://docs.docker.com/engine/security/seccomp/"])


def check_apparmor() -> Finding:
    aa = (_read("/proc/self/attr/current") or "").strip()
    unconf = aa in ("", "unconfined")
    return Finding("apparmor_unconfined", "AppArmor confinement is not applied",
                   Severity.MEDIUM, unconf,
                   f"AppArmor profile='{aa or 'none'}'",
                   "AppArmor restricts file and capability operations. 'unconfined' removes that layer.",
                   "Keep Docker's default AppArmor profile or supply a tailored one.", "mac",
                   ["https://docs.docker.com/engine/security/apparmor/"])


def check_selinux() -> Finding:
    enforce = _read("/sys/fs/selinux/enforce")
    if enforce is None:
        return Finding("selinux_not_enforcing", "SELinux is not enforcing",
                       Severity.LOW, False, "SELinux not present on this host",
                       "On SELinux hosts an enforcing policy constrains a container even when otherwise misconfigured.",
                       "On SELinux hosts, run in enforcing mode.", "mac",
                       ["https://docs.docker.com/engine/security/#selinux"])
    val = enforce.strip()
    return Finding("selinux_not_enforcing", "SELinux is not enforcing",
                   Severity.LOW, val != "1",
                   "enforcing" if val == "1" else f"not enforcing (enforce={val})",
                   "A non-enforcing SELinux policy removes a mandatory-access-control backstop.",
                   "Run SELinux in enforcing mode on hosts that use it.", "mac",
                   ["https://docs.docker.com/engine/security/#selinux"])


def check_no_new_privs() -> Finding:
    status = _read("/proc/self/status") or ""
    m = re.search(r"^NoNewPrivs:\s*(\d)", status, re.MULTILINE)
    nnp = m.group(1) if m else None
    return Finding("no_new_privs", "no_new_privs is not set",
                   Severity.LOW, nnp == "0",
                   f"NoNewPrivs={nnp}" if nnp is not None else "NoNewPrivs unknown",
                   "Without no_new_privs, setuid/setgid binaries and file capabilities can still escalate privileges.",
                   "Run with --security-opt no-new-privileges:true.", "mac",
                   ["https://docs.docker.com/engine/reference/run/#security-configuration"])


def check_running_as_root() -> Finding:
    uid = os.getuid() if hasattr(os, "getuid") else -1
    return Finding("running_as_root", "Process runs as root inside the container",
                   Severity.MEDIUM, uid == 0, f"uid={uid}",
                   "Root in the container is the precondition that makes most other misconfigurations exploitable.",
                   "Run as a non-root user (USER / --user) and enable userns-remap.", "config",
                   ["https://docs.docker.com/engine/security/userns-remap/"])


def check_env_secrets() -> Finding:
    key_pat = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AWS_SECRET|CLIENT_SECRET)", re.I)
    val_pat = re.compile(r"\b(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]{10,}\.)")
    keys, vals = [], []
    for k, v in os.environ.items():
        if key_pat.search(k):
            keys.append(k)
        if v and val_pat.search(v) and k not in keys:
            vals.append(k)
    flagged = sorted(set(keys + vals))
    return Finding("env_secrets", "Environment variables appear to contain secrets",
                   Severity.MEDIUM, bool(flagged),
                   (f"suspicious variable names (values hidden): {', '.join(flagged)}" if flagged
                    else "no secret-like environment variables found"),
                   "Secrets in env vars are visible to every process, leak into /proc/<pid>/environ and child processes, and enable lateral movement.",
                   "Use a secrets manager or tmpfs-mounted files, not ENV/-e; rotate exposed values.", "secrets_env",
                   ["https://docs.docker.com/engine/swarm/secrets/"])


def check_kernel_module_loading() -> Finding:
    caps = effective_caps()
    has_mod = "CAP_SYS_MODULE" in caps or "CAP_FULL_SET" in caps
    modprobe_w = os.access("/proc/sys/kernel/modprobe", os.W_OK)
    detected = has_mod or modprobe_w
    parts = [f"CAP_SYS_MODULE={'yes' if has_mod else 'no'}"]
    if modprobe_w:
        parts.append("modprobe path writable")
    return Finding("kernel_module_loading", "Container can influence kernel module loading",
                   Severity.CRITICAL, detected, "; ".join(parts),
                   "CAP_SYS_MODULE loads kernel modules (ring-0 code); a writable modprobe path redirects auto-loading to an attacker binary.",
                   "Never grant CAP_SYS_MODULE; keep /proc/sys read-only.", "capabilities",
                   ["https://man7.org/linux/man-pages/man7/capabilities.7.html"])


def check_sysadmin_mount_primitive() -> Finding:
    caps = effective_caps()
    has = "CAP_SYS_ADMIN" in caps or "CAP_FULL_SET" in caps
    cg_w = os.access("/sys/fs/cgroup", os.W_OK)
    return Finding("sysadmin_mount_primitive", "CAP_SYS_ADMIN present with a writable cgroup mount",
                   Severity.HIGH, has and cg_w,
                   f"CAP_SYS_ADMIN={'yes' if has else 'no'}, /sys/fs/cgroup writable={'yes' if cg_w else 'no'}",
                   "CAP_SYS_ADMIN grants mount/remount/pivot_root; with a writable cgroup hierarchy the release_agent escape can be staged.",
                   "Drop CAP_SYS_ADMIN and keep cgroup mounts read-only.", "capabilities",
                   ["https://man7.org/linux/man-pages/man7/capabilities.7.html"])


def check_k8s_sa_token() -> Finding:
    p = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    return Finding("k8s_sa_token", "Kubernetes service-account token is mounted",
                   Severity.MEDIUM, _exists(p),
                   f"{p} present" if _exists(p) else "no service-account token mounted",
                   "A mounted SA token lets a compromised pod call the Kubernetes API with that account's RBAC permissions - a common pivot.",
                   "Set automountServiceAccountToken: false where the token is not needed; scope RBAC tightly.", "kubernetes",
                   ["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"])


def check_k8s_in_cluster() -> Finding:
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    return Finding("k8s_in_cluster", "Running inside a Kubernetes cluster (API reachable via env)",
                   Severity.INFO, bool(host),
                   f"KUBERNETES_SERVICE_HOST={host}" if host else "not set",
                   "In-cluster API endpoints plus a token expand the attack surface toward the cluster control plane.",
                   "Apply NetworkPolicies and least-privilege RBAC; restrict API reachability from workloads.", "kubernetes",
                   ["https://kubernetes.io/docs/concepts/security/"])


def check_k8s_ca_cert() -> Finding:
    p = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    return Finding("k8s_sa_ca", "Kubernetes service-account CA cert is mounted",
                   Severity.INFO, _exists(p),
                   f"{p} present" if _exists(p) else "not present",
                   "Presence confirms in-cluster service-account mounting; pairs with the token for API access.",
                   "Disable automatic SA mounting where unused.", "kubernetes",
                   ["https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"])


def check_kubelet_ro_port() -> Finding:
    # Read-only kubelet port 10255 reachable is a known info-leak; we can only
    # hint from env/hosts, not scan, in a read-only tool.
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    return Finding("kubelet_ro_hint", "Kubernetes environment present (check kubelet read-only port 10255 manually)",
                   Severity.INFO, bool(host),
                   "in-cluster" if host else "not in-cluster",
                   "The kubelet read-only port (10255), if enabled and reachable, leaks pod and node metadata. This tool only flags that you are in-cluster; test reachability separately.",
                   "Disable the kubelet read-only port (--read-only-port=0).", "kubernetes",
                   ["https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/"])


def check_writable_rootfs() -> Finding:
    # A writable / (no --read-only) lets an attacker persist tools/binaries.
    writable = os.access("/", os.W_OK)
    return Finding("writable_rootfs", "Container root filesystem is writable",
                   Severity.LOW, writable,
                   "/ is writable" if writable else "/ is read-only",
                   "A writable rootfs lets an attacker drop binaries and persist. --read-only shrinks the foothold.",
                   "Run with --read-only and mount tmpfs for the few writable paths needed.", "config",
                   ["https://docs.docker.com/engine/reference/run/#read-only"])


# ----------------------------------------------------------------------------
# Build the full registry
# ----------------------------------------------------------------------------
def build_checks() -> list[Callable[[], Finding]]:
    checks: list[Callable[[], Finding]] = []
    # Singletons (config / namespaces / mac / cgroups)
    checks += [
        check_privileged, check_docker_socket, check_containerd_socket,
        check_running_as_root, check_writable_rootfs,
        check_host_pid, check_host_network, check_proc_host_leak,
        check_host_mounts, check_mount_nosuid_nodev,
        check_cgroup_release_agent, check_core_pattern_pipe,
        check_seccomp, check_apparmor, check_selinux, check_no_new_privs,
        check_env_secrets, check_kernel_module_loading, check_sysadmin_mount_primitive,
        check_k8s_sa_token, check_k8s_ca_cert, check_k8s_in_cluster, check_kubelet_ro_port,
    ]
    # Capabilities (41)
    for bit in sorted(CAP_META):
        checks.append(_mk_capability_check(bit))
    # Devices (12)
    for path in DEVICE_META:
        checks.append(_mk_device_check(path))
    # Writable sysctls (8)
    for path in SYSCTL_META:
        checks.append(_mk_sysctl_check(path))
    # Secret files (8)
    for cid, paths, sev, why in SECRET_FILE_META:
        checks.append(_mk_secret_file_check(cid, paths, sev, why))
    # Tooling (8)
    for tool in TOOL_META:
        checks.append(_mk_tool_check(tool))
    # Kernel CVEs (7)
    for cid, name, intro, fixed, sev, why in CVE_META:
        checks.append(_mk_cve_check(cid, name, intro, fixed, sev, why))
    return checks


CHECKS = build_checks()


# ----------------------------------------------------------------------------
# Runner / rendering
# ----------------------------------------------------------------------------
def run_all(checks: list[Callable[[], Finding]], verbose: bool = False) -> list[Finding]:
    results = []
    for i, fn in enumerate(checks, 1):
        try:
            f = fn()
        except Exception as exc:
            f = Finding(getattr(fn, "__name__", "unknown"),
                        f"Check errored: {getattr(fn, '__name__', '?')}",
                        Severity.INFO, False, f"exception: {exc!r}",
                        "This check could not complete.", "Investigate the audit environment.",
                        "errors")
        if verbose:
            mark = "DETECTED" if f.detected else "ok"
            print(f"[run {i:3}/{len(checks)}] {f.category:13} {f.check_id:34} "
                  f"{f.severity.label:8} {mark:8} {f.evidence}", file=sys.stderr)
        results.append(f)
    return results


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _HAVE_COLOR else text


def highest_severity(findings: list[Finding]) -> Severity:
    det = [f.severity for f in findings if f.detected]
    return max(det) if det else Severity.INFO


def render_text(findings: list[Finding], color: bool, min_sev: Severity,
                show_passed: bool, verbose: bool = False) -> str:
    use_color = color and _HAVE_COLOR
    isc, why = in_container()
    L = []
    L.append("=" * 72)
    L.append("           EscapeContainer - Breakout Vulnerability Report")
    L.append("=" * 72)
    L.append(f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"Host      : {socket.gethostname()}")
    L.append(f"Kernel    : {platform.platform()}")
    L.append(f"In container: {'yes' if isc else 'unclear'} ({why})")
    L.append(f"Checks run : {len(findings)}")
    L.append("")

    triggered = [f for f in findings if f.detected and f.severity >= min_sev]
    triggered.sort(key=lambda f: f.severity, reverse=True)

    counts: dict[str, int] = {}
    for f in triggered:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    summary = ", ".join(f"{counts[k]} {k}" for k in order if k in counts) or "no findings at this threshold"
    hidden = sum(1 for f in findings if f.detected and f.severity < min_sev)
    L.append(f"SUMMARY: {len(triggered)} finding(s) at/above {min_sev.label} -> {summary}"
             + (f"  (+{hidden} lower-severity hidden)" if hidden else ""))
    L.append("-" * 72)

    if not triggered:
        L.append("")
        L.append("No findings at or above the selected severity. (Not proof of safety.)")
    for i, f in enumerate(triggered, 1):
        sev = _c(f"[{f.severity.label}]", SEV_COLOR.get(f.severity, "")) if use_color else f"[{f.severity.label}]"
        L.append("")
        L.append(f"{i}. {sev} {f.title}  (id: {f.check_id}, cat: {f.category})")
        L.append(f"   Evidence   : {f.evidence}")
        L.append(f"   Why        : {f.why}")
        L.append(f"   Remediation: {f.remediation}")
        if f.references:
            L.append(f"   Reference  : {f.references[0]}")

    if verbose:
        # Full enumeration of every check, grouped by category, detected first.
        L.append("")
        L.append("=" * 72)
        L.append("FULL CHECK ENUMERATION (verbose)")
        L.append("=" * 72)
        cats: dict[str, list[Finding]] = {}
        for f in findings:
            cats.setdefault(f.category, []).append(f)
        for cat in sorted(cats):
            group = sorted(cats[cat], key=lambda x: (not x.detected, -int(x.severity), x.check_id))
            ndet = sum(1 for f in group if f.detected)
            L.append("")
            L.append(f"### {cat}  ({ndet}/{len(group)} detected)")
            for f in group:
                if f.detected:
                    mark = _c("DETECTED", SEV_COLOR.get(f.severity, "")) if (color and _HAVE_COLOR) else "DETECTED"
                else:
                    mark = "   ok   "
                L.append(f"  [{mark}] {f.severity.label:8} {f.check_id:34} {f.evidence}")
    else:
        passed = [f for f in findings if not f.detected]
        L.append("")
        L.append("-" * 72)
        if show_passed:
            L.append(f"Checks that did NOT trigger ({len(passed)}):")
            for f in sorted(passed, key=lambda x: (x.category, x.check_id)):
                L.append(f"   - [{f.category}] {f.check_id}: {f.evidence}")
        else:
            bycat: dict[str, int] = {}
            for f in passed:
                bycat[f.category] = bycat.get(f.category, 0) + 1
            cat_str = ", ".join(f"{k}:{v}" for k, v in sorted(bycat.items()))
            L.append(f"{len(passed)} checks did not trigger (by category: {cat_str}).")
            L.append("Use --show-passed to list them, or --verbose for full detail.")

    L.append("")
    L.append("=" * 72)
    L.append("This tool only fingerprints configuration. It performs no exploitation.")
    L.append("=" * 72)
    return "\n".join(L)


# ----------------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------------
_SEV_HTML = {
    Severity.CRITICAL: ("#d32029", "#2a0d10"),
    Severity.HIGH:     ("#c04bd6", "#230f27"),
    Severity.MEDIUM:   ("#d98a00", "#271c07"),
    Severity.LOW:      ("#2f6fed", "#0e1830"),
    Severity.INFO:     ("#2aa5b5", "#07201f"),
}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def render_html(findings: list[Finding], min_sev: Severity) -> str:
    isc, why = in_container()
    triggered = [f for f in findings if f.detected and f.severity >= min_sev]
    triggered.sort(key=lambda f: f.severity, reverse=True)
    passed = [f for f in findings if not f.detected]
    other_detected = [f for f in findings if f.detected and f.severity < min_sev]

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    counts = {s: sum(1 for f in triggered if f.severity == s) for s in order}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    chips = "".join(
        f'<span class="chip" style="--c:{_SEV_HTML[s][0]}">{counts[s]} {s.label}</span>'
        for s in order if counts[s]
    ) or '<span class="chip" style="--c:#2aa5b5">no findings at this threshold</span>'

    cards = []
    for i, f in enumerate(triggered, 1):
        fg, bg = _SEV_HTML[f.severity]
        ref = (f'<a href="{_esc(f.references[0])}" target="_blank" rel="noopener">reference &#8599;</a>'
               if f.references else "")
        cards.append(f"""
      <article class="card" style="--c:{fg};--cbg:{bg}">
        <header>
          <span class="badge">{f.severity.label}</span>
          <h3>{i}. {_esc(f.title)}</h3>
        </header>
        <div class="row"><span class="k">Evidence</span><span class="val mono">{_esc(f.evidence)}</span></div>
        <div class="row"><span class="k">Why it matters</span><span class="val">{_esc(f.why)}</span></div>
        <div class="row"><span class="k">Remediation</span><span class="val">{_esc(f.remediation)}</span></div>
        {f'<div class="row"><span class="k"></span><span class="val">{ref}</span></div>' if ref else ''}
      </article>""")

    # compact non-triggered list grouped by category
    bycat: dict[str, int] = {}
    for f in passed:
        bycat[f.category] = bycat.get(f.category, 0) + 1
    passed_rows = "".join(
        f"<tr><td>{_esc(c)}</td><td>{n}</td></tr>" for c, n in sorted(bycat.items())
    )

    empty_note = ("" if triggered else
                  '<p class="empty">No findings at or above the selected severity. '
                  '(Absence of findings is not proof of safety.)</p>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EscapeContainer Report</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0b0e14; color:#e6e9ef;
         font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .mono {{ font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:13px; }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 28px 20px 64px; }}
  h1 {{ font-size: 22px; margin:0 0 4px; }}
  .sub {{ color:#8b93a7; font-size:13px; margin-bottom:20px; }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
               gap:10px; background:#121722; border:1px solid #1e2636; border-radius:10px;
               padding:14px 16px; margin-bottom:18px; }}
  .meta-grid div span {{ display:block; }}
  .meta-grid .lbl {{ color:#7b8398; font-size:11px; text-transform:uppercase; letter-spacing:.04em; }}
  .meta-grid .v {{ font-size:14px; }}
  .chips {{ margin:14px 0 24px; display:flex; flex-wrap:wrap; gap:8px; }}
  .chip {{ border:1px solid var(--c); color:var(--c); border-radius:999px;
          padding:4px 12px; font-size:13px; font-weight:600; }}
  .card {{ border:1px solid #1e2636; border-left:4px solid var(--c);
          background:var(--cbg); border-radius:10px; padding:14px 16px; margin:12px 0; }}
  .card header {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }}
  .badge {{ background:var(--c); color:#0b0e14; font-weight:700; font-size:11px;
           padding:3px 9px; border-radius:6px; letter-spacing:.03em; }}
  .card h3 {{ font-size:15px; margin:0; flex:1 1 auto; }}
  .meta {{ color:#8b93a7; font-size:12px; }}
  .row {{ display:grid; grid-template-columns:130px 1fr; gap:10px; padding:3px 0; }}
  .row .k {{ color:#8b93a7; font-size:12px; text-transform:uppercase; letter-spacing:.03em; padding-top:2px; }}
  .row .val {{ color:#d7dbe6; }}
  a {{ color:#6ea8fe; }}
  .empty {{ color:#8b93a7; padding:18px; border:1px dashed #28324a; border-radius:10px; text-align:center; }}
  h2 {{ font-size:15px; margin:30px 0 8px; color:#aab2c5; }}
  table {{ border-collapse:collapse; font-size:13px; }}
  td {{ border:1px solid #1e2636; padding:4px 12px; color:#aab2c5; }}
  footer {{ margin-top:34px; color:#6a7286; font-size:12px; border-top:1px solid #1e2636; padding-top:14px; }}
</style></head>
<body><div class="wrap">
  <h1>EscapeContainer &mdash; Breakout Vulnerability Report</h1>
  <div class="sub">Read-only container escape-vector audit. This tool fingerprints configuration only; it performs no exploitation.</div>
  <div class="meta-grid">
    <div><span class="lbl">Generated</span><span class="v">{now}</span></div>
    <div><span class="lbl">Host</span><span class="v">{_esc(socket.gethostname())}</span></div>
    <div><span class="lbl">Kernel</span><span class="v mono">{_esc(platform.platform())}</span></div>
    <div><span class="lbl">In container</span><span class="v">{'yes' if isc else 'unclear'}</span></div>
    <div><span class="lbl">Checks run</span><span class="v">{len(findings)}</span></div>
    <div><span class="lbl">Shown at/above</span><span class="v">{min_sev.label}</span></div>
  </div>
  <div class="chips">{chips}</div>
  {empty_note}
  {''.join(cards)}
  {f'<p class="sub">+ {len(other_detected)} lower-severity finding(s) hidden below the {min_sev.label} threshold.</p>' if other_detected else ''}
  <h2>Checks that did not trigger ({len(passed)})</h2>
  <table><tr><td><b>Category</b></td><td><b>Passed</b></td></tr>{passed_rows}</table>
  <footer>Generated by EscapeContainer. Findings describe configuration conditions and their remediation; verify in your own environment.</footer>
</div></body></html>"""


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Fingerprint a Docker container for escape-vector misconfigurations (read-only).")
    p.add_argument("-o", "--output", metavar="FILE", help="write the plain-text report to FILE")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--min-severity", choices=[s.name.lower() for s in Severity],
                   default="info", help="hide detected findings below this severity (default: info = show all)")
    p.add_argument("--category", help="only run checks in this category (e.g. capabilities, devices, kernel_cve)")
    p.add_argument("--show-passed", action="store_true", help="list checks that did not trigger, in full")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="trace each check to stderr as it runs and print a full per-category enumeration")
    p.add_argument("--list-checks", action="store_true", help="list all checks and exit without running")
    p.add_argument("--html", metavar="FILE", help="write a self-contained HTML report to FILE (open in a browser)")
    args = p.parse_args(argv)

    checks = CHECKS
    if args.category:
        # Run everything, then filter by category (categories are on the Finding).
        sample = run_all(CHECKS, verbose=args.verbose)
        cats = sorted({f.category for f in sample})
        if args.category not in cats:
            print(f"Unknown category '{args.category}'. Known: {', '.join(cats)}", file=sys.stderr)
            return 2
        findings = [f for f in sample if f.category == args.category]
    else:
        findings = None  # run below

    if args.list_checks:
        tmp = run_all(CHECKS)
        print(f"{len(tmp)} checks:")
        for f in sorted(tmp, key=lambda x: (x.category, x.check_id)):
            print(f"  [{f.category:14}] {f.check_id:34} {f.severity.label:8} {f.title}")
        return 0

    if findings is None:
        findings = run_all(checks, verbose=args.verbose)

    min_sev = SEV_BY_NAME[args.min_severity]

    # HTML report can be written alongside any other output mode.
    if args.html:
        try:
            with open(args.html, "w") as fh:
                fh.write(render_html(findings, min_sev))
            print(f"[+] HTML report written to {args.html}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] Could not write HTML report: {exc}", file=sys.stderr)

    if args.json:
        payload = {
            "generated": datetime.datetime.now().isoformat(),
            "host": socket.gethostname(),
            "kernel": platform.platform(),
            "checks_run": len(findings),
            "highest_severity": highest_severity(findings).label,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
    elif args.html:
        # HTML already written above; keep stdout quiet except the written-to note.
        pass
    else:
        report = render_text(findings, not args.no_color, min_sev, args.show_passed, args.verbose)
        print(report)
        if args.output:
            try:
                with open(args.output, "w") as fh:
                    fh.write(render_text(findings, False, min_sev, args.show_passed, args.verbose))
                print(f"\n[+] Plain-text report written to {args.output}")
            except Exception as exc:
                print(f"\n[!] Could not write report: {exc}", file=sys.stderr)

    return 1 if highest_severity(findings) >= Severity.HIGH else 0


if __name__ == "__main__":
    sys.exit(main())
