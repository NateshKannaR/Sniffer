import glob
import os
import time
from typing import Any


class ProcessTracker:
    """Maps network socket ports to Linux processes (PID, name, cmdline) using /proc."""

    def __init__(self, cache_ttl_sec: float = 2.0):
        self.cache_ttl = cache_ttl_sec
        self.last_refresh = 0.0
        self.port_to_process: dict[int, dict[str, Any]] = {}

    def get_process_for_port(self, port: int) -> dict[str, Any] | None:
        """Returns process information associated with a local port number."""
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
        inode_to_port = {}

        # 1. Parse /proc/net/{tcp, tcp6, udp, udp6}
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
                                    inode_to_port[inode] = port
                                except ValueError:
                                    continue
            except Exception:
                continue

        # 2. Match socket inodes against open file descriptors in /proc/[PID]/fd
        updated_map = {}
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid = os.path.basename(pid_dir)
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

                                # Get process name
                                comm_file = os.path.join(pid_dir, "comm")
                                comm = pid
                                if os.path.exists(comm_file):
                                    with open(comm_file) as cf:
                                        comm = cf.read().strip()

                                # Get command line
                                cmd_file = os.path.join(pid_dir, "cmdline")
                                cmdline = comm
                                if os.path.exists(cmd_file):
                                    with open(cmd_file, errors="ignore") as cmdf:
                                        raw_cmd = cmdf.read().replace("\x00", " ").strip()
                                        if raw_cmd:
                                            cmdline = raw_cmd[:120]

                                updated_map[port] = {
                                    "pid": int(pid),
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
