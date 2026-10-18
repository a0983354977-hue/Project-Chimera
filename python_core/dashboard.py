"""Chimera-Vision: a zero-dependency local web dashboard for Project Chimera.

This module is intentionally stdlib-only. It never imports the analysis stack
(pydantic / yara) itself; instead it drives a persistent ``chimera.exe --daemon``
child process over the existing stdio JSON-lines IPC and renders the returned
records in a browser.

Run it directly::

    python python_core/dashboard.py
    python python_core/dashboard.py --open sample.exe
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
UI_PATH = Path(__file__).resolve().parent / "dashboard_ui.html"
DEFAULT_PORT = 8765


def find_executable() -> str:
    """Locate chimera.exe beside the project, else fall back to PATH."""
    for candidate in ("chimera.exe", "chimera"):
        local = APP_DIR / candidate
        if local.is_file():
            return str(local)
    found = shutil.which("chimera") or shutil.which("chimera.exe")
    if found:
        return found
    raise FileNotFoundError(
        "chimera executable not found; build it with build.bat or add it to PATH"
    )


class ChimeraDaemon:
    """Persistent stdio IPC client for ``chimera.exe --daemon``."""

    def __init__(self, executable: str, rules_path: str = "") -> None:
        self._executable = executable
        self._rules_path = rules_path
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None

    # -- lifecycle ---------------------------------------------------------
    def _start(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        command = [self._executable, "--daemon"]
        if self._rules_path:
            command += ["--rules", self._rules_path]
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(APP_DIR),
        )

    def _stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None

    def close(self) -> None:
        with self._lock:
            self._stop()

    def healthy(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def warm(self) -> bool:
        """Start the daemon on demand so the UI can report a truthful status."""
        with self._lock:
            try:
                self._start()
            except (OSError, ValueError):
                return False
            return self.healthy()

    # -- request -----------------------------------------------------------
    def scan(self, file_path: str) -> dict[str, object]:
        request = json.dumps({"file_path": file_path})
        with self._lock:
            self._start()
            assert self._proc is not None and self._proc.stdin and self._proc.stdout
            try:
                self._proc.stdin.write(request + "\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, ValueError) as error:
                self._stop()
                raise RuntimeError(f"daemon pipe closed: {error}") from error
            line = self._proc.stdout.readline()
            if not line:
                self._stop()
                raise RuntimeError("daemon terminated before responding")
            try:
                return json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"daemon returned invalid JSON: {line[:200]}") from error


class ExportRunner:
    """Runs one-shot CLI invocations for SARIF / JSON / HTML report export."""

    def __init__(self, executable: str, rules_path: str = "") -> None:
        self._executable = executable
        self._rules_path = rules_path

    def run(self, file_path: str, report_format: str) -> tuple[bytes, str]:
        if report_format == "sarif":
            command = [self._executable, "--sarif", "--no-cache", file_path]
            content = self._capture(command)
            return content, "application/sarif+json"
        if report_format == "json":
            command = [self._executable, "--json", file_path]
            content = self._capture(command)
            return content, "application/json"
        if report_format == "html":
            with tempfile.TemporaryDirectory(prefix="chimera-vision-report-") as tmp:
                target = Path(tmp) / "report.html"
                command = [self._executable, "--report", str(target),
                           "--report-format", "html", file_path]
                if self._rules_path:
                    command += ["--rules", self._rules_path]
                self._capture(command)
                return target.read_bytes(), "text/html; charset=utf-8"
        raise ValueError(f"unsupported export format: {report_format}")

    def _capture(self, command: list[str]) -> bytes:
        if self._rules_path and "--rules" not in command:
            command += ["--rules", self._rules_path]
        completed = subprocess.run(
            command, cwd=str(APP_DIR), capture_output=True, timeout=120
        )
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(message or f"chimera exited with {completed.returncode}")
        return completed.stdout


class DashboardServer:
    def __init__(self, executable: str, rules_path: str = "") -> None:
        self.daemon = ChimeraDaemon(executable, rules_path)
        self.exporter = ExportRunner(executable, rules_path)
        self.uploads = Path(tempfile.mkdtemp(prefix="chimera-vision-"))
        self.pending = ""
        self.ui_html = UI_PATH.read_text(encoding="utf-8")

    def shutdown(self) -> None:
        self.daemon.close()
        shutil.rmtree(self.uploads, ignore_errors=True)


def build_handler(server: DashboardServer):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # -- helpers -------------------------------------------------------
        def _send(self, status: int, content_type: str, payload: bytes,
                  extra: dict[str, str] | None = None, body: bool = True) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(payload)

        def _json(self, payload: object, status: int = 200,
                  body: bool = True) -> None:
            self._send(status, "application/json; charset=utf-8",
                       json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       body=body)

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def log_message(self, fmt: str, *args: object) -> None:
            return  # keep the console quiet; the UI shows the IPC stream

        # -- routes --------------------------------------------------------
        def do_GET(self) -> None:
            self._route_get(body=True)

        def do_HEAD(self) -> None:
            self._route_get(body=False)

        def _route_get(self, body: bool) -> None:
            route = self.path.split("?", 1)[0]
            if route in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8",
                           server.ui_html.encode("utf-8"), body=body)
            elif route == "/api/health":
                self._json({"ok": server.daemon.warm(),
                            "pending": server.pending}, body=body)
            else:
                self._json({"error": "not found"}, status=404, body=body)

        def do_POST(self) -> None:
            route = self.path.split("?", 1)[0]
            try:
                if route == "/api/scan":
                    self._handle_scan()
                elif route == "/api/upload":
                    self._handle_upload()
                elif route == "/api/export":
                    self._handle_export()
                else:
                    self._json({"error": "not found"}, status=404)
            except Exception as error:  # boundary: surface errors to the UI
                self._json({"status": "error", "error": str(error)}, status=200)

        def _handle_scan(self) -> None:
            body = json.loads(self._read_body() or b"{}")
            paths = body.get("paths") or []
            if isinstance(paths, str):
                paths = [paths]
            results = []
            for path in paths:
                try:
                    record = server.daemon.scan(str(path))
                except Exception as error:
                    record = {"file_path": str(path), "status": "error",
                              "error": str(error)}
                results.append(record)
            self._json(results)

        def _handle_upload(self) -> None:
            name = "sample.bin"
            query = urllib.parse.urlparse(self.path).query
            for key, value in urllib.parse.parse_qsl(query):
                if key == "name" and value:
                    name = os.path.basename(value)
            payload = self._read_body()
            target = server.uploads / name
            target.write_bytes(payload)
            try:
                record = server.daemon.scan(str(target))
            except Exception as error:
                record = {"file_path": str(target), "status": "error",
                          "error": str(error)}
            record["original_name"] = name
            self._json(record)

        def _handle_export(self) -> None:
            body = json.loads(self._read_body() or b"{}")
            path = str(body.get("path") or "")
            report_format = str(body.get("format") or "sarif")
            if not path:
                self._json({"error": "path is required"}, status=400)
                return
            content, content_type = server.exporter.run(path, report_format)
            self._send(200, content_type, content)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Chimera-Vision dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--rules", default="", help="optional YARA rules file")
    parser.add_argument("--open", dest="open_path", default="",
                        help="PE path to preload into the dashboard")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    try:
        executable = find_executable()
    except FileNotFoundError as error:
        print(f"[Chimera-Vision] {error}", file=sys.stderr)
        return 1

    server = DashboardServer(executable, args.rules)
    server.pending = args.open_path
    atexit.register(server.shutdown)

    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), build_handler(server))
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}/"
    print(f"[Chimera-Vision] dashboard ready at {url}")
    print(f"[Chimera-Vision] backend: {executable} --daemon")
    if args.open_path:
        print(f"[Chimera-Vision] preloaded sample: {args.open_path}")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Chimera-Vision] shutting down")
    finally:
        httpd.server_close()
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
