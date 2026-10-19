import glob
import os
import re
import subprocess
import time
from typing import Any


class ProcessTracker:
    """Maps network socket ports to Linux processes (PID, name, cmdline) using kernel ss and /proc."""

    def __init__(self, cache_ttl_sec: float = 2.0):
        self.cache_ttl = cache_ttl_sec
        self.last_refresh = 0.0
        self.port_to_process: dict[int, dict[str, Any]] = {}

    def get_process_for_port(self, port: int) -> dict[str, Any] | None:
        """Returns process information associated with a local port number."""
        if not port or port <= 0:
            return None
        now = time.time()
        if now - self.last_refresh > self.cache_ttl:
            self._refresh_cache()

        return self.port_to_process.get(port)

    def refresh(self) -> dict[int, dict[str, Any]]:
        """Force cache refresh and return port to process dictionary."""
        self._refresh_cache()
        return self.port_to_process

    def _refresh_cache(self):
        self.last_refresh = time.time()
        updated_map = {}

        # 1. Fast & precise kernel socket introspection via `ss -H -tanp` and `ss -H -tulpn`
        for cmd in [["ss", "-H", "-tanp"], ["ss", "-H", "-tulpn"]]:
            try:
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=1.0,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            for part in parts[3:5]:
                                port_match = re.search(r":(\d+)$", part)
                                if port_match:
                                    port = int(port_match.group(1))
                                    user_match = re.search(
                                        r'users:\(\("([^"]+)",pid=(\d+)', line
                                    )
                                    if user_match:
                                        comm = user_match.group(1)
                                        pid = int(user_match.group(2))

                                        # Get real command line from /proc
                                        cmdline = comm
                                        cmd_file = f"/proc/{pid}/cmdline"
                                        if os.path.exists(cmd_file):
                                            try:
                                                with open(
                                                    cmd_file, errors="ignore"
                                                ) as cmdf:
                                                    raw_cmd = (
                                                        cmdf.read()
                                                        .replace("\x00", " ")
                                                        .strip()
                                                    )
                                                    if raw_cmd:
                                                        cmdline = raw_cmd[:120]
                                            except (PermissionError, OSError):
                                                pass

                                        updated_map[port] = {
                                            "pid": pid,
                                            "name": comm,
                                            "cmdline": cmdline,
                                        }
            except Exception:
                pass

        # 2. Comprehensive /proc fallback for any remaining sockets
        inode_to_port = {}
        net_files = [
            "/proc/net/tcp",
            "/proc/net/tcp6",
            "/proc/net/udp",
            "/proc/net/udp6",
        ]
        for fpath in net_files:
            if not os.path.exists(fpath):
                continue
            try:
                with open(fpath) as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 10:
                            local_addr = parts[1]
                            inode = parts[9]
                            if ":" in local_addr:
                                port_hex = local_addr.split(":")[1]
                                try:
                                    port = int(port_hex, 16)
                                    if port not in updated_map:
                                        inode_to_port[inode] = port
                                except ValueError:
                                    continue
            except Exception:
                continue

        if inode_to_port:
            for pid_dir in glob.glob("/proc/[0-9]*"):
                pid_str = os.path.basename(pid_dir)
                fd_dir = os.path.join(pid_dir, "fd")
                if not os.path.isdir(fd_dir):
                    continue

                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            target = os.readlink(os.path.join(fd_dir, fd))
                            if target.startswith("socket:["):
                                inode = target[8:-1]
                                if inode in inode_to_port:
                                    port = inode_to_port[inode]
                                    if port in updated_map:
                                        continue

                                    comm_file = os.path.join(pid_dir, "comm")
                                    comm = pid_str
                                    if os.path.exists(comm_file):
                                        try:
                                            with open(comm_file) as cf:
                                                comm = cf.read().strip()
                                        except OSError:
                                            pass

                                    cmd_file = os.path.join(pid_dir, "cmdline")
                                    cmdline = comm
                                    if os.path.exists(cmd_file):
                                        try:
                                            with open(cmd_file, errors="ignore") as cmdf:
                                                raw_cmd = (
                                                    cmdf.read()
                                                    .replace("\x00", " ")
                                                    .strip()
                                                )
                                                if raw_cmd:
                                                    cmdline = raw_cmd[:120]
                                        except OSError:
                                            pass

                                    updated_map[port] = {
                                        "pid": int(pid_str),
                                        "name": comm,
                                        "cmdline": cmdline,
                                    }
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
                except (PermissionError, FileNotFoundError, OSError):
                    continue

        self.port_to_process = updated_map

    def get_all_active_processes(self) -> dict[int, dict[str, Any]]:
        if time.time() - self.last_refresh > self.cache_ttl:
            self._refresh_cache()
        return self.port_to_process
