#!/usr/bin/env python3
"""
Download Agent — monitor active downloads on this machine.
Zero dependencies beyond Python 3 stdlib.
Exposes HTTP API on port 19877 for the LAN Scope dashboard.

Endpoints:
  GET /health  — liveness check + hostname
  GET /status  — JSON list of active downloads with progress/speed/URL

Detected tools: wget, curl, aria2c, axel, yt-dlp, youtube-dl
Tracks: PID, tool, URL, output file, current size, speed (EMA-smoothed),
        progress %, ETA, process start time.
"""

import os
import re
import json
import sys
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = 19877

# ── Tool definitions ──────────────────────────────────────────────
DOWNLOAD_TOOLS: dict[str, dict] = {
    'wget':       {'output_flag': ['-O', '--output-document']},
    'curl':       {'output_flag': ['-o', '--output'], 'remote_name_flag': ['-O', '--remote-name']},
    'aria2c':     {'output_flag': ['-o', '--out'], 'dir_flag': ['-d', '--dir']},
    'axel':       {'output_flag': ['-o', '--output']},
    'yt-dlp':     {'output_flag': ['-o', '--output']},
    'youtube-dl': {'output_flag': ['-o', '--output']},
    'httrack':    {'output_flag': ['-O', '--path']},
}

URL_RE = re.compile(r'^https?://')
TOOL_NAMES = set(DOWNLOAD_TOOLS)

# ── Persistent state for speed tracking ───────────────────────────
# {pid: (timestamp, file_size, smoothed_speed_bps)}
_prev_stats: dict[int, tuple[float, int, int]] = {}
_stats_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════
# Process inspection helpers
# ═══════════════════════════════════════════════════════════════════

def _tool_from_argv0(argv0: str) -> str | None:
    """Match argv[0] against known download tools."""
    basename = os.path.basename(argv0)
    for name in TOOL_NAMES:
        if basename == name or basename.startswith(f'{name}.'):
            return name
    # Check if full path contains tool name (e.g. /usr/bin/wget)
    for name in TOOL_NAMES:
        if name in basename:
            return name
    return None


def parse_cmdline(pid: int) -> list[str]:
    """Read /proc/<pid>/cmdline → argument list."""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            raw = f.read()
        if not raw:
            return []
        args = raw.decode('utf-8', errors='replace').split('\0')
        return [a for a in args if a]  # drop empty trailing
    except (OSError, PermissionError, FileNotFoundError):
        return []


def public_url(url: str | None) -> str:
    if not url:
        return '(unknown)'
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https', 'ftp') or not parsed.hostname:
        return '(redacted)'
    host = parsed.hostname
    if ':' in host:
        host = f'[{host}]'
    try:
        port = f':{parsed.port}' if parsed.port else ''
    except ValueError:
        return '(redacted)'
    return f'{parsed.scheme}://{host}{port}{parsed.path}'


def extract_url(args: list[str]) -> str | None:
    """Pull the download URL from the argument list (usually last positional)."""
    for arg in reversed(args):
        # Skip flag arguments
        if arg.startswith('-'):
            continue
        if URL_RE.match(arg):
            return arg.strip('\'"')
        if arg.startswith('magnet:') or arg.startswith('ftp://'):
            return arg
    # Fallback: first http arg
    for arg in args:
        if URL_RE.match(arg):
            return arg.strip('\'"')
    return None


def resolve_path(path: str, pid: int) -> str:
    """Resolve relative path against the process cwd."""
    if os.path.isabs(path) or not path:
        return path
    try:
        cwd = os.readlink(f'/proc/{pid}/cwd')
        return os.path.normpath(os.path.join(cwd, path))
    except (OSError, PermissionError):
        return path


def _parse_output_flag(args: list[str], flags: list[str]) -> str | None:
    """Extract value for a flag like -O <file> or --output=<file>."""
    for i, arg in enumerate(args):
        for flag in flags:
            if arg == flag and i + 1 < len(args):
                val = args[i + 1]
                return None if val.startswith('-') else val
            if arg.startswith(flag + '='):
                return arg[len(flag) + 1:]
    return None


def extract_output_file(args: list[str], tool: str, pid: int) -> str | None:
    """Determine the output file path from command-line flags."""
    info = DOWNLOAD_TOOLS.get(tool, {})
    output_flags = info.get('output_flag', [])

    path = _parse_output_flag(args, output_flags)
    if path:
        return resolve_path(path, pid)

    # curl -O → derive filename from URL
    if tool == 'curl':
        remote_flags = info.get('remote_name_flag', [])
        if any(a in args for a in remote_flags):
            url = extract_url(args)
            if url:
                basename = url.split('?')[0].split('#')[0].rsplit('/', 1)[-1] or 'index.html'
                return resolve_path(basename, pid)

    # aria2c with -d <dir> + URL basename
    if tool == 'aria2c':
        out_dir = _parse_output_flag(args, info.get('dir_flag', []))
        url = extract_url(args)
        if url:
            basename = url.split('?')[0].split('#')[0].rsplit('/', 1)[-1] or 'download'
            target = f"{out_dir}/{basename}" if out_dir else basename
            return resolve_path(target, pid)

    return None


def find_output_by_fd(pid: int, *, exclude: str | None = None) -> str | None:
    """Scan /proc/<pid>/fd/ for the largest regular file being written to."""
    best_path = None
    best_size = -1
    try:
        fd_dir = f'/proc/{pid}/fd'
        for entry in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, entry))
                # Only real files, skip devices / pipes / sockets
                if not link.startswith('/'):
                    continue
                skip_prefixes = ('/dev/', '/proc/', '/sys/')
                if any(link.startswith(p) for p in skip_prefixes):
                    continue
                if 'pipe:' in link or 'socket:' in link or 'anon_inode:' in link:
                    continue
                if exclude and link == exclude:
                    continue
                st = os.stat(link)
                # Regular files (or .part/.tmp temporary download files)
                if st.st_size > best_size:
                    best_size = st.st_size
                    best_path = link
            except OSError:
                pass
    except (OSError, PermissionError):
        pass
    return best_path


def proc_start_time(pid: int) -> float | None:
    """Return wall-clock time when the process started."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            parts = f.read().split()
        if len(parts) < 22:
            return None
        start_ticks = int(parts[21])
        with open('/proc/uptime', 'r') as f:
            uptime = float(f.read().split()[0])
        clk = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        return time.time() - (uptime - start_ticks / clk)
    except (OSError, PermissionError, ValueError):
        return None


def read_total_size(pid: int) -> int | None:
    """Try to read expected file size from process environment."""
    try:
        with open(f'/proc/{pid}/environ', 'rb') as f:
            env = f.read().decode('utf-8', errors='replace').split('\0')
        for var in env:
            if var.startswith('CONTENT_LENGTH='):
                try:
                    return int(var.split('=', 1)[1])
                except ValueError:
                    pass
    except (OSError, PermissionError):
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
# Core scan
# ═══════════════════════════════════════════════════════════════════

def get_process_info(pid: int) -> dict | None:
    """Gather download metadata for a single PID, or None if not a download."""
    args = parse_cmdline(pid)
    if not args:
        return None

    tool = _tool_from_argv0(args[0])
    if not tool:
        return None

    url = extract_url(args)
    output_file = extract_output_file(args, tool, pid)

    # Fallback: find output file via open FDs
    if not output_file:
        output_file = find_output_by_fd(pid)

    # Get current file size
    file_size = 0
    if output_file:
        try:
            file_size = os.path.getsize(output_file)
        except OSError:
            alt = find_output_by_fd(pid, exclude=output_file)
            if alt:
                output_file = alt
                try:
                    file_size = os.path.getsize(output_file)
                except OSError:
                    pass

    # ── Speed (EMA) ──
    speed_bps = 0
    now = time.time()
    with _stats_lock:
        prev = _prev_stats.get(pid)
        if prev and file_size >= prev[1]:
            dt = now - prev[0]
            if dt > 0.1:
                raw = (file_size - prev[1]) / dt
                old = prev[2] if len(prev) > 2 else 0
                speed_bps = int(old * 0.4 + raw * 0.6)
        _prev_stats[pid] = (now, file_size, speed_bps)

    # ── Total size / progress ──
    total_size = read_total_size(pid)
    progress_pct = None
    if total_size and total_size > 0:
        progress_pct = round(file_size / total_size * 100, 1)

    # ── ETA ──
    eta = None
    if speed_bps > 0 and total_size and total_size > file_size:
        eta = int((total_size - file_size) / speed_bps)

    # ── Status (alive check) ──
    try:
        os.kill(pid, 0)
        status = 'downloading'
    except (OSError, PermissionError, ProcessLookupError):
        status = 'exited'
        with _stats_lock:
            _prev_stats.pop(pid, None)

    return {
        'pid': pid,
        'tool': tool,
        'url': public_url(url),
        'output_file': output_file or '(unknown)',
        'file_size': file_size,
        'total_size': total_size,
        'progress_pct': progress_pct,
        'speed_bps': speed_bps,
        'speed_display': _fmt_speed(speed_bps),
        'eta_seconds': eta,
        'eta_display': _fmt_eta(eta),
        'started_at': round(proc_start_time(pid), 1) if proc_start_time(pid) else None,
        'status': status,
    }


def scan_downloads() -> list[dict]:
    """Walk /proc and return all active-download records."""
    results: list[dict] = []
    seen: set[int] = set()

    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = int(entry)
        seen.add(pid)
        try:
            info = get_process_info(pid)
            if info:
                results.append(info)
        except Exception:
            pass

    # Clean stale tracking
    with _stats_lock:
        dead = [p for p in _prev_stats if p not in seen]
        for p in dead:
            del _prev_stats[p]

    results.sort(key=lambda d: d['speed_bps'], reverse=True)
    return results


# ═══════════════════════════════════════════════════════════════════
# Formatting helpers
# ═══════════════════════════════════════════════════════════════════

def _fmt_speed(bps: int) -> str:
    if bps >= 1_048_576:
        return f"{bps / 1_048_576:.1f} MB/s"
    if bps >= 1024:
        return f"{bps / 1024:.0f} KB/s"
    if bps > 0:
        return f"{bps} B/s"
    return "—"


def _fmt_eta(sec: int | None) -> str:
    if sec is None:
        return "—"
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


# ═══════════════════════════════════════════════════════════════════
# HTTP server
# ═══════════════════════════════════════════════════════════════════

class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)

        if p.path == '/health':
            self._send_json({'status': 'ok', 'hostname': socket.gethostname()})
            return

        if p.path == '/status':
            try:
                downloads = scan_downloads()
                active = sum(1 for d in downloads if d['status'] == 'downloading')
                total_speed = sum(d['speed_bps'] for d in downloads if d['status'] == 'downloading')
                self._send_json({
                    'hostname': socket.gethostname(),
                    'downloads': downloads,
                    'active_count': active,
                    'total_speed_bps': total_speed,
                    'total_speed_display': _fmt_speed(total_speed),
                    'timestamp': time.time(),
                })
            except Exception as e:
                self._send_json({'error': str(e)}, 500)
            return

        if p.path == '/' or p.path == '/index.html':
            hostname = socket.gethostname()
            try:
                ds = scan_downloads()
                active = sum(1 for d in ds if d['status'] == 'downloading')
            except Exception:
                ds, active = [], 0
            body = json.dumps(ds, indent=2, ensure_ascii=False)
            html = (
                '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<title>Download Agent — {hostname}</title>'
                '<style>body{font-family:system-ui;max-width:720px;margin:40px auto;'
                'padding:0 20px;background:#faf9f5;color:#141413}'
                'pre{background:#141413;color:#e1e3e8;padding:16px;border-radius:8px;'
                'overflow-x:auto;font-size:13px;line-height:1.5}'
                'code{background:#e3dacc;padding:1px 5px;border-radius:3px;font-size:13px}'
                '</style></head><body>'
                f'<h1>📥 Download Agent</h1>'
                f'<p>Host: <strong>{hostname}</strong> &middot; Active: <strong>{active}</strong></p>'
                '<p>Endpoints: <code>GET /health</code> &middot; <code>GET /status</code></p>'
                f'<pre>{body}</pre>'
                '</body></html>'
            )
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode())
            return

        self._send_json({'error': 'not found'}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def main():
    server = HTTPServer(('0.0.0.0', PORT), AgentHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    hostname = socket.gethostname()
    print(f"Download Agent → http://0.0.0.0:{PORT}  ({hostname})")
    print(f"  GET /health  — liveness check")
    print(f"  GET /status  — active downloads JSON")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == '__main__':
    if '--oneshot' in sys.argv:
        import sys
        result = {
            'hostname': socket.gethostname(),
            'downloads': scan_downloads(),
            'timestamp': time.time(),
        }
        result['active_count'] = sum(1 for d in result['downloads'] if d['status'] == 'downloading')
        result['total_speed_bps'] = sum(d['speed_bps'] for d in result['downloads'] if d['status'] == 'downloading')
        print(json.dumps(result, ensure_ascii=False))
    else:
        main()
