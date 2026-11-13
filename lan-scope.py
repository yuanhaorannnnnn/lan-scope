#!/usr/bin/env python3
"""
LAN Scope backend — HTTP server that probes the local subnet + monitors downloads.
Only external dependency: pexpect (SSH).  Python 3 stdlib otherwise.

Endpoints:
  GET /scan?mode=full|ssh|quick  — subnet scan
  GET /health                    — liveness check
  GET /config                    — subnet config
  GET /downloads/scan            — aggregate downloads from LAN agents
  POST /downloads/agent/deploy   — deploy download-agent.py to a host via SSH
  GET /ssh/read|exec|tab         — interactive SSH terminal
  POST /ssh/open|close            — SSH session lifecycle

Each scanned host returns:
  { ip, http, ssh, hostname, latency_ms }
"""
import socket
import json
import threading
import time
import glob
import fcntl
import struct
import subprocess
import uuid
import re
import os
import pexpect
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

SUBNET = None  # auto-detected below
START, END = 1, 254
TIMEOUT = 2.0
CONCURRENCY = 50
SSH_CONCURRENCY = 200
PORT = 19876
AGENT_PORT = 19877
AGENT_TIMEOUT = 1.5  # seconds to wait for agent response
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Cache of last scan results for download-agent discovery
_last_hosts: list[dict] = []
_last_hosts_lock = threading.Lock()


def get_subnet() -> tuple[str, str]:
    """Auto-detect local subnet from primary interface. Returns (prefix, cidr)."""
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                          capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            parts = line.split()
            for p in parts:
                if "/" in p and "." in p:
                    ip_cidr = p
                    ip_part = ip_cidr.split("/")[0]
                    prefix = ".".join(ip_part.split(".")[:3])
                    return prefix, ip_part
    except Exception:
        pass
    # Fallback: try hostname -I
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=2)
        ip = r.stdout.strip().split()[0]
        prefix = ".".join(ip.split(".")[:3])
        return prefix, ip
    except Exception:
        return "192.168.1", "192.168.1.1"


SUBNET, LOCAL_IP = get_subnet()

# SSH session store
ssh_sessions: dict[str, pexpect.spawn] = {}
ssh_locks: dict[str, threading.Lock] = {}
ssh_lock = threading.Lock()
ssh_host_map: dict[str, str] = {}   # host → session_id
ssh_host_user: dict[str, str] = {}  # host → username
ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][0-9;]*[^\x07]*\x07|[\ue000-\uf8ff]')


def probe_port(ip: str, port: int, timeout: float = TIMEOUT) -> tuple[int, bool, float]:
    """Try TCP connect to ip:port. Returns (port, reachable, latency_ms)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.perf_counter() - t0) * 1000
            return (port, True, round(latency, 1))
    except (socket.timeout, ConnectionRefusedError, OSError):
        latency = (time.perf_counter() - t0) * 1000
        return (port, False, round(latency, 1))



def probe_hostname(ip: str, timeout: float = 1.5) -> str | None:
    """Resolve hostname via reverse DNS, mDNS, and NetBIOS."""
    # 1. Reverse DNS
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0].removesuffix(".")
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass

    # 2. mDNS (avahi) — short timeout, most hosts won't respond
    try:
        r = subprocess.run(
            ["timeout", "1", "avahi-resolve-address", ip],
            capture_output=True, text=True, timeout=1.5
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split("\t")[-1].removesuffix(".local")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 3. NetBIOS (nmblookup)
    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=timeout
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "<00>" in line and "<GROUP>" not in line:
                    name = line.split()[0].strip()
                    if name and name != ip:
                        return name
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return None


def get_local_macs() -> dict[str, str]:
    """Get IP→MAC for local interfaces from /sys/class/net."""
    import glob, fcntl, struct
    macs = {}
    for iface_dir in glob.glob("/sys/class/net/*"):
        iface = iface_dir.split("/")[-1]
        if iface == "lo":
            continue
        try:
            with open(f"{iface_dir}/address") as f:
                mac = f.read().strip()
            if mac == "00:00:00:00:00:00":
                continue
            # Get IP via ioctl
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ip = socket.inet_ntoa(
                    fcntl.ioctl(sock.fileno(), 0x8915,
                    struct.pack("256s", iface[:15].encode()))[20:24]
                )
                macs[ip] = mac
            except OSError:
                pass
            finally:
                sock.close()
        except OSError:
            pass
    return macs


def get_arp_table() -> dict[str, str]:
    """Read /proc/net/arp to get IP→MAC mapping. Also include local interfaces."""
    macs = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip, _, _, mac = parts[0], parts[1], parts[2], parts[3]
                    if mac != "00:00:00:00:00:00":
                        macs[ip] = mac
    except OSError:
        pass

    # Merge local interface MACs
    try:
        macs.update(get_local_macs())
    except Exception:
        pass

    return macs


def probe_host_ssh(i: int, arp_table: dict[str, str]) -> dict:
    """Fast probe: SSH port + hostname, skip HTTP and MAC."""
    ip = f"{SUBNET}.{i}"
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_ssh = pool.submit(probe_port, ip, 22, timeout=0.8)
        f_name = pool.submit(probe_hostname, ip)
        _, ok, lat = f_ssh.result()
        hostname = f_name.result()
    return {"ip": ip, "http": None, "ssh": ok, "hostname": hostname, "mac": None,
            "latency_http": None, "latency_ssh": lat if ok else None}


def probe_host_full(i: int, arp_table: dict[str, str]) -> dict:
    """Probe a single IP: HTTP (80), SSH (22), hostname, and MAC."""
    ip = f"{SUBNET}.{i}"
    result = {"ip": ip, "http": False, "ssh": False, "hostname": None, "mac": arp_table.get(ip),
              "latency_http": None, "latency_ssh": None}

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(probe_port, ip, 80): "http",
            pool.submit(probe_port, ip, 22): "ssh",
            pool.submit(probe_hostname, ip): "hostname",
        }
        for f in as_completed(futures):
            key = futures[f]
            if key == "hostname":
                result["hostname"] = f.result()
            else:
                port, ok, lat = f.result()
                if port == 80:
                    result["http"] = ok
                    result["latency_http"] = lat
                else:
                    result["ssh"] = ok
                    result["latency_ssh"] = lat

    return result


def build_range(mode: str) -> list[int]:
    if mode == "quick":
        r = list(range(1, 31)) + list(range(100, 201))
        if 158 not in r:
            r.append(158)
        return sorted(set(r))
    return list(range(START, END + 1))


# ═══════════════════════════════════════════════════════════════════
# Download-agent integration
# ═══════════════════════════════════════════════════════════════════

def probe_agent(ip: str, timeout: float = AGENT_TIMEOUT) -> dict | None:
    """Query a download agent on the given IP. Returns parsed JSON or None."""
    try:
        with socket.create_connection((ip, AGENT_PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n")
            resp = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                except socket.timeout:
                    break
            if not resp:
                return None
            # Split headers from body
            parts = resp.split(b"\r\n\r\n", 1)
            if len(parts) < 2:
                return None
            return json.loads(parts[1].decode("utf-8", errors="replace"))
    except (socket.timeout, ConnectionRefusedError, OSError, json.JSONDecodeError):
        return None


def scan_all_agents(hosts: list[dict], timeout: float = AGENT_TIMEOUT) -> dict:
    """Concurrently query download agents on all online hosts that have a known IP.
    Returns {ip: agent_data, ...} for hosts that responded.
    """
    results: dict[str, dict] = {}
    targets = [h for h in hosts if h.get("ip")]
    if not targets:
        return results

    with ThreadPoolExecutor(max_workers=min(30, len(targets))) as pool:
        futures = {pool.submit(probe_agent, h["ip"], timeout): h["ip"] for h in targets}
        for f in as_completed(futures):
            ip = futures[f]
            try:
                data = f.result()
                if data and "downloads" in data:
                    results[ip] = data
            except Exception:
                pass
    return results


def valid_ssh_target(host, username):
    return (isinstance(host, str) and isinstance(username, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host) is not None
            and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", username) is not None)


def ssh_args(host, username):
    return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "-o", "ConnectTimeout=5", f"{username}@{host}"]


def deploy_agent_to(host: str, username: str, password: str) -> tuple[bool, str]:
    """SCP download-agent.py + SSH launch it on the target machine.
    Returns (success, message).
    """
    if not valid_ssh_target(host, username):
        return False, "Invalid host or username"
    agent_path = os.path.join(SCRIPT_DIR, "download-agent.py")
    if not os.path.exists(agent_path):
        return False, f"Agent script not found: {agent_path}"

    ssh_opts = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "HostKeyAlgorithms=+ssh-rsa",
        "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
        "-o", "ConnectTimeout=5",
    ]

    # SCP the agent script
    try:
        r = subprocess.run(
            ["sshpass", "-p", password, "scp"] + ssh_opts +
            [agent_path, f"{username}@{host}:/tmp/download-agent.py"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            return False, f"SCP failed: {r.stderr.strip() or r.stdout.strip()}"
    except FileNotFoundError:
        # Fallback: use pexpect for scp?  Try ssh + heredoc
        pass
    except subprocess.TimeoutExpired:
        return False, "SCP timed out"
    except Exception as e:
        return False, f"SCP error: {e}"

    # SSH: launch the agent in background
    try:
        r = subprocess.run(
            ["sshpass", "-p", password, "ssh"] + ssh_opts +
            [f"{username}@{host}",
             "nohup python3 /tmp/download-agent.py > /tmp/download-agent.log 2>&1 &"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return True, f"Agent deployed to {host} — check port {AGENT_PORT}"
        return False, f"SSH launch failed: {r.stderr.strip() or r.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return False, "SSH launch timed out"
    except FileNotFoundError:
        # sshpass not available — try pexpect
        return _deploy_via_pexpect(host, username, password)
    except Exception as e:
        return False, f"SSH error: {e}"


def _deploy_via_pexpect(host: str, username: str, password: str) -> tuple[bool, str]:
    """Fallback deployment using pexpect (sshpass not available)."""
    import base64
    if not valid_ssh_target(host, username):
        return False, "Invalid host or username"
    agent_path = os.path.join(SCRIPT_DIR, "download-agent.py")
    if not os.path.exists(agent_path):
        return False, "Agent script not found"

    try:
        with open(agent_path, "rb") as f:
            content = base64.b64encode(f.read()).decode()
    except OSError as e:
        return False, f"Cannot read agent script: {e}"

    try:
        child = pexpect.spawn("ssh", ssh_args(host, username), encoding="utf-8", timeout=10)
        idx = child.expect(["password:", "Password:", pexpect.EOF, pexpect.TIMEOUT], timeout=8)
        if idx >= 2:
            child.close()
            return False, "SSH connection failed"

        child.sendline(password)
        try:
            child.expect([pexpect.TIMEOUT], timeout=1.5)
        except pexpect.TIMEOUT:
            pass

        if not child.isalive():
            child.close()
            return False, "SSH login failed (check credentials)"

        # Write agent script via base64 decode
        child.sendline(f"echo '{content}' | base64 -d > /tmp/download-agent.py")
        child.sendline("chmod +x /tmp/download-agent.py")
        child.sendline("nohup python3 /tmp/download-agent.py > /tmp/download-agent.log 2>&1 &")
        child.sendline("echo 'AGENT_DEPLOYED'")
        try:
            idx = child.expect(["AGENT_DEPLOYED", pexpect.TIMEOUT], timeout=5)
            child.sendline("exit")
            child.close()
            if idx == 0:
                return True, f"Agent deployed to {host} via SSH"
            return False, "Agent script deployed but failed to start"
        except pexpect.TIMEOUT:
            child.close(force=True)
            return False, "Agent start timed out"
    except Exception as e:
        return False, f"Deployment error: {e}"


def ssh_oneshot_downloads(host: str, username: str, password: str, timeout: float = 8.0) -> dict | None:
    """SSH into a host, pipe download-agent.py via stdin, run --oneshot, return parsed JSON.
    No deployment required — the script runs inline and exits immediately.
    Returns None on failure.
    """
    if not valid_ssh_target(host, username):
        return None
    import base64
    agent_path = os.path.join(SCRIPT_DIR, "download-agent.py")
    try:
        with open(agent_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
    except OSError:
        return None

    try:
        command = f"echo '{b64}' | base64 -d | python3 /dev/stdin --oneshot"
        child = pexpect.spawn("ssh", ssh_args(host, username) + [command], encoding="utf-8", timeout=timeout)
        idx = child.expect(["password:", "Password:", pexpect.EOF, pexpect.TIMEOUT], timeout=6)
        if idx < 2:
            child.sendline(password)
            try:
                child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
            except pexpect.TIMEOUT:
                pass
            output = child.before or ""
        elif idx == 2:
            output = child.before or ""
        else:
            child.close()
            return None
        child.close()

        # Extract JSON from output (find outermost {})
        if output:
            # Strip ANSI codes
            clean = ANSI_RE.sub("", output)
            start = clean.find("{")
            end = clean.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(clean[start:end + 1])
                except json.JSONDecodeError:
                    pass
        return None
    except Exception:
        return None


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    def _local_request(self):
        port = self.server.server_port
        hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}
        host = self.headers.get("Host", "").lower()
        origin = self.headers.get("Origin")
        if (host not in hosts or
                (origin and origin.lower() not in {f"http://{h}" for h in hosts}) or
                self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site"):
            self.send_error(403, "Local requests only")
            return False
        return True

    def log_message(self, fmt, *args):
        pass  # silence access logs

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        if not self._local_request(): return
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json({"status": "ok"})
            return

        if parsed.path == "/config":
            try:
                import pwd
                local_user = pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                local_user = os.environ.get("USER", "")
            self._send_json({"subnet": f"{SUBNET}.0/24", "local_ip": LOCAL_IP, "prefix": SUBNET,
                             "local_user": local_user})
            return

        if parsed.path == "/" or parsed.path == "/index.html":
            try:
                with open(os.path.join(SCRIPT_DIR, "lan-scope.html"), "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except OSError:
                self._send_json({"error": "page not found"}, 404)
            return

        if parsed.path == "/scan":
            qs = parse_qs(parsed.query)
            mode = qs.get("mode", ["full"])[0]
            ip_range = build_range(mode)
            results = []
            arp_table = get_arp_table()
            if mode == "ssh":
                workers = SSH_CONCURRENCY
                probe_fn = probe_host_ssh
            else:
                workers = CONCURRENCY
                probe_fn = probe_host_full
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(probe_fn, i, arp_table): i for i in ip_range}
                for f in as_completed(futures):
                    results.append(f.result())
            def sort_key(r):
                return int(r["ip"].rsplit(".", 1)[1])
            results.sort(key=sort_key)
            # Cache for download-agent discovery
            with _last_hosts_lock:
                _last_hosts.clear()
                _last_hosts.extend(results)
            self._send_json({"subnet": f"{SUBNET}.0/24", "total": len(ip_range), "hosts": results})
            return

        if parsed.path == "/downloads/scan":
            qs = parse_qs(parsed.query)
            ssh_user = qs.get("ssh_user", [None])[0]
            ssh_pass = qs.get("ssh_pass", [None])[0]

            with _last_hosts_lock:
                hosts_snapshot = list(_last_hosts)
            online = [h for h in hosts_snapshot if h.get("http") or h.get("ssh")]
            host_lookup = {h["ip"]: h for h in online}
            enriched: dict[str, dict] = {}

            if not online:
                self._send_json({"agents": {}, "agent_count": 0, "online_hosts": 0,
                                 "total_downloads": 0, "total_speed_bps": 0})
                return

            # Step 1: query HTTP agents in parallel (fast)
            agents = scan_all_agents(online)
            agent_ips: set[str] = set()
            for ip, data in agents.items():
                hinfo = host_lookup.get(ip, {})
                enriched[ip] = {**data, "hostname": hinfo.get("hostname"),
                    "mac": hinfo.get("mac"), "has_ssh": bool(hinfo.get("ssh")),
                    "has_http": bool(hinfo.get("http")), "method": "agent"}
                agent_ips.add(ip)

            # Step 2: SSH oneshot for hosts with SSH but no agent
            if ssh_user:
                ssh_targets = [h for h in online
                               if h.get("ssh") and h["ip"] not in agent_ips]
                if ssh_targets:
                    with ThreadPoolExecutor(max_workers=min(10, len(ssh_targets))) as pool:
                        futures = {}
                        for h in ssh_targets:
                            f = pool.submit(ssh_oneshot_downloads, h["ip"], ssh_user, ssh_pass, 8.0)
                            futures[f] = h["ip"]
                        for f in as_completed(futures):
                            ip = futures[f]
                            try:
                                data = f.result()
                                if data and "downloads" in data:
                                    hinfo = host_lookup.get(ip, {})
                                    enriched[ip] = {**data, "hostname": hinfo.get("hostname"),
                                        "mac": hinfo.get("mac"),
                                        "has_ssh": bool(hinfo.get("ssh")),
                                        "has_http": bool(hinfo.get("http")),
                                        "method": "ssh"}
                            except Exception:
                                pass

            self._send_json({
                "agents": enriched,
                "agent_count": len(enriched),
                "online_hosts": len(online),
                "total_downloads": sum(
                    d.get("active_count", 0) for d in enriched.values()
                ),
                "total_speed_bps": sum(
                    d.get("total_speed_bps", 0) for d in enriched.values()
                ),
            })
            return

        if parsed.path == "/downloads/agent/status":
            qs = parse_qs(parsed.query)
            host = qs.get("host", [None])[0]
            if not host:
                self._send_json({"error": "host parameter required"}, 400)
                return
            data = probe_agent(host, timeout=AGENT_TIMEOUT)
            if data:
                self._send_json(data)
            else:
                self._send_json({"error": "agent unreachable"}, 404)
            return

        if parsed.path == "/downloads/ssh-scan":
            qs = parse_qs(parsed.query)
            host = qs.get("host", [None])[0]
            ssh_user = qs.get("ssh_user", [None])[0]
            ssh_pass = qs.get("ssh_pass", [None])[0]
            if not host or not ssh_user:
                self._send_json({"error": "host and ssh_user required"}, 400)
                return
            # Try agent first (fast), then SSH
            data = probe_agent(host, timeout=0.8)
            if data and "downloads" in data:
                data["method"] = "agent"
                self._send_json(data)
                return
            data = ssh_oneshot_downloads(host, ssh_user, ssh_pass, timeout=10.0)
            if data:
                data["method"] = "ssh"
                self._send_json(data)
            else:
                self._send_json({"error": "SSH scan failed"}, 404)
            return

        if parsed.path == "/ssh/sessions":
            with ssh_lock:
                sessions = []
                for host, sid in list(ssh_host_map.items()):
                    child = ssh_sessions.get(sid)
                    sessions.append({
                        "host": host,
                        "username": ssh_host_user.get(host, ""),
                        "session_id": sid,
                        "alive": child.isalive() if child else False,
                    })
            self._send_json({"sessions": sessions})
            return

        if parsed.path == "/downloads/connected":
            # Scan downloads through all active SSH sessions
            import base64
            agent_path = os.path.join(SCRIPT_DIR, "download-agent.py")
            b64 = ""
            try:
                with open(agent_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
            except OSError:
                pass

            results: dict[str, dict] = {}
            with ssh_lock:
                hosts_to_scan = list(ssh_host_map.items())

            for host, sid in hosts_to_scan:
                with ssh_lock:
                    child = ssh_sessions.get(sid)
                    lock = ssh_locks.get(sid)
                if not child or not child.isalive() or not lock or not b64:
                    if not child or not child.isalive():
                        with ssh_lock:
                            ssh_host_map.pop(host, None)
                            ssh_host_user.pop(host, None)
                            ssh_sessions.pop(sid, None)
                            ssh_locks.pop(sid, None)
                    continue

                with lock:
                    try:
                        # Clear stale buffer: send newline, wait for prompt
                        child.sendline("")
                        try:
                            child.expect([pexpect.TIMEOUT], timeout=0.3)
                        except pexpect.TIMEOUT:
                            pass
                        # Drain
                        try:
                            while True:
                                child.read_nonblocking(size=4096, timeout=0.05)
                        except pexpect.TIMEOUT:
                            pass

                        # Send inline oneshot script, collect all output
                        child.sendline(
                            f"echo '{b64}' | base64 -d | python3 /dev/stdin --oneshot"
                        )
                        # Wait for command to finish — read in small chunks
                        output = ""
                        deadline = time.time() + 10.0
                        while time.time() < deadline:
                            try:
                                chunk = child.read_nonblocking(size=65536, timeout=0.3)
                                output += chunk
                            except pexpect.TIMEOUT:
                                # If we have a complete JSON object already, done
                                if output.count("{") > 0 and output.count("{") == output.count("}"):
                                    break
                                continue
                            except pexpect.EOF:
                                break

                        clean = ANSI_RE.sub("", output)
                        # Find the outermost JSON object in the output
                        start = clean.find("{")
                        end = clean.rfind("}")
                        if start >= 0 and end > start:
                            try:
                                data = json.loads(clean[start:end + 1])
                                data["method"] = "session"
                                data["hostname"] = host
                                results[host] = data
                            except json.JSONDecodeError:
                                pass
                    except (pexpect.EOF, Exception):
                        with ssh_lock:
                            ssh_host_map.pop(host, None)
                            ssh_host_user.pop(host, None)
                            ssh_sessions.pop(sid, None)
                            ssh_locks.pop(sid, None)

            self._send_json({
                "agents": results,
                "agent_count": len(results),
                "total_downloads": sum(d.get("active_count", 0) for d in results.values()),
                "total_speed_bps": sum(d.get("total_speed_bps", 0) for d in results.values()),
            })
            return

        if parsed.path == "/ssh/read":
            qs = parse_qs(parsed.query)
            sid = qs.get("session_id", [None])[0]
            with ssh_lock:
                child = ssh_sessions.get(sid)
                lock = ssh_locks.get(sid)
            if not child or not lock:
                self._send_json({"error": "session not found"}, 404)
                return
            with lock:
                try:
                    output = ""
                    while True:
                        try:
                            chunk = child.read_nonblocking(size=4096, timeout=0.05)
                            output += chunk
                        except pexpect.TIMEOUT:
                            break
                        except pexpect.EOF:
                            output += child.before or ""
                            break
                    text = ANSI_RE.sub("", output)
                    self._send_json({"output": text, "alive": child.isalive()})
                except Exception as e:
                    self._send_json({"output": "", "alive": False, "error": str(e)})
            return

        if parsed.path == "/ssh/exec":
            qs = parse_qs(parsed.query)
            sid = qs.get("session_id", [None])[0]
            text = qs.get("input", [""])[0]
            with ssh_lock:
                child = ssh_sessions.get(sid)
                lock = ssh_locks.get(sid)
            if not child or not child.isalive() or not lock:
                self._send_json({"error": "session not found or closed"}, 404)
                return
            with lock:
                try:
                    if text:
                        child.sendline(text)
                    try:
                        child.expect([pexpect.TIMEOUT], timeout=1.5)
                    except pexpect.TIMEOUT:
                        pass
                    output = ANSI_RE.sub("", child.before or "")
                    self._send_json({"output": output, "alive": child.isalive()})
                except pexpect.EOF:
                    before = ANSI_RE.sub("", child.before or "")
                    self._send_json({"output": before, "alive": False})
                except Exception as e:
                    self._send_json({"output": "", "alive": False, "error": str(e)})
            return

        if parsed.path == "/ssh/tab":
            qs = parse_qs(parsed.query)
            sid = qs.get("session_id", [None])[0]
            text = qs.get("input", [""])[0]
            with ssh_lock:
                child = ssh_sessions.get(sid)
                lock = ssh_locks.get(sid)
            if not child or not child.isalive() or not lock:
                self._send_json({"error": "session not found or closed"}, 404)
                return
            with lock:
                try:
                    child.send(text + "\t")
                    try:
                        child.expect([pexpect.TIMEOUT], timeout=0.8)
                    except pexpect.TIMEOUT:
                        pass
                    output = ANSI_RE.sub("", child.before or "")
                    self._send_json({"output": output, "alive": child.isalive()})
                except pexpect.EOF:
                    self._send_json({"output": "", "alive": False})
                except Exception as e:
                    self._send_json({"error": str(e)})
            return

        self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._local_request(): return
        parsed = urlparse(self.path)

        if parsed.path == "/downloads/agent/deploy":
            data = self._read_body()
            host = data.get("host", "")
            username = data.get("username", "")
            password = data.get("password", "")
            if not valid_ssh_target(host, username):
                self._send_json({"error": "invalid host or username"}, 400)
                return
            ok, msg = deploy_agent_to(host, username, password)
            self._send_json({"ok": ok, "message": msg})
            return

        if parsed.path == "/ssh/open":
            data = self._read_body()
            host = data.get("host", "")
            username = data.get("username", "")
            password = data.get("password", "")
            if not valid_ssh_target(host, username):
                self._send_json({"error": "invalid host or username"}, 400)
                return
            try:
                child = pexpect.spawn("ssh", ssh_args(host, username), encoding="utf-8", timeout=10)
                idx = child.expect(["password:", "Password:", pexpect.EOF, pexpect.TIMEOUT], timeout=8)
                if idx < 2:
                    child.sendline(password)
                    # Wait for login to complete (fancy prompts won't match simple patterns)
                    try:
                        child.expect([pexpect.TIMEOUT], timeout=1.5)
                    except pexpect.TIMEOUT:
                        pass
                    if child.isalive():
                        # Send newline to trigger prompt, then capture
                        child.sendline("")
                        try:
                            child.expect([pexpect.TIMEOUT], timeout=0.5)
                        except pexpect.TIMEOUT:
                            pass
                        initial = ANSI_RE.sub("", child.before or "")
                        # Check if login failed
                        if "Permission denied" in initial or "Please try again" in initial:
                            self._send_json({"error": "密码错误"}, 401)
                            child.close()
                            return
                        sid = uuid.uuid4().hex[:12]
                        with ssh_lock:
                            # Close old session for same host
                            old_sid = ssh_host_map.pop(host, None)
                            if old_sid and old_sid in ssh_sessions:
                                try:
                                    with ssh_locks.get(old_sid, threading.Lock()):
                                        ssh_sessions[old_sid].close(force=True)
                                except Exception:
                                    pass
                                ssh_sessions.pop(old_sid, None)
                                ssh_locks.pop(old_sid, None)
                            ssh_sessions[sid] = child
                            ssh_locks[sid] = threading.Lock()
                            ssh_host_map[host] = sid
                            ssh_host_user[host] = username
                        self._send_json({"session_id": sid, "output": initial, "host": host})
                        return
                else:
                    self._send_json({"error": "SSH 连接超时或主机无响应"}, 500)
                    child.close()
                    return
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if parsed.path == "/ssh/close":
            data = self._read_body()
            sid = data.get("session_id", "")
            with ssh_lock:
                child = ssh_sessions.pop(sid, None)
                lock = ssh_locks.pop(sid, None)
                # Clean up host mapping
                for h, s in list(ssh_host_map.items()):
                    if s == sid:
                        del ssh_host_map[h]
                        ssh_host_user.pop(h, None)
            if child and lock:
                with lock:
                    try:
                        child.sendline("exit")
                        child.close(force=True)
                    except Exception:
                        pass
            self._send_json({"ok": True})
            return

        self._send_json({"error": "not found"}, 404)

    def do_OPTIONS(self):
        if not self._local_request(): return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def main():
    server = ReusableHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"LAN Scope backend → http://localhost:{PORT}")
    print(f"  /scan?mode=full   — scan {SUBNET}.{START}-{END}")
    print(f"  /scan?mode=quick  — scan common ranges")
    print(f"  /health           — liveness check")
    print(f"  Concurrency: {CONCURRENCY}, timeout: {TIMEOUT}s per port")
    print(f"\nOpen http://localhost:{PORT} in browser.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        with ssh_lock:
            for sid, child in list(ssh_sessions.items()):
                try:
                    with ssh_locks.get(sid, threading.Lock()):
                        child.close(force=True)
                except Exception:
                    pass
            ssh_sessions.clear()
            ssh_locks.clear()
        server.shutdown()


if __name__ == "__main__":
    main()
