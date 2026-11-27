#!/usr/bin/env python3
"""
Local web server for the Zendure Hyper 2000 all-in-one Download + Patch + BLE OTA webapp.

Binds strictly to 127.0.0.1 so Web Bluetooth works in Chrome/Edge at http://localhost:8080
and handles Zendure cloud API calls locally (avoiding browser CORS & RSA-PKCS1v1.5 limits).
Credentials and tokens live only in process RAM and are never written to disk.

Usage:
  python3 ble_ota_webapp/server.py
  python3 ble_ota_webapp/server.py --port 8080
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import sys
import tempfile
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

WEBAPP_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEBAPP_DIR.parent
sys.path.insert(0, str(REPO_ROOT))

from download_hyper2000_fw import DEFAULT_BASE_URL, ZendureClient  # noqa: E402

# In-memory sessions: session_id -> {"client": ZendureClient, "allowed_urls": set[str]}
SESSIONS: dict[str, dict] = {}


class OtaWebHandler(BaseHTTPRequestHandler):
    server_version = "Hyper2000OtaLocal/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[http] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 1024 * 1024:
            raise ValueError("Invalid request body size")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            html = (WEBAPP_DIR / "index.html").read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html)
            return

        if parsed.path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "cloudDownload": True})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/zendure/login":
                self._handle_login()
            elif parsed.path == "/api/zendure/firmware":
                self._handle_firmware()
            elif parsed.path == "/api/zendure/download":
                self._handle_download()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Unknown API endpoint"})
        except Exception as e:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(e)})

    def _handle_login(self):
        body = self._read_json()
        account = str(body.get("account", "")).strip()
        password = str(body.get("password", ""))
        base_url = str(body.get("baseUrl") or DEFAULT_BASE_URL).strip()
        if not account or not password:
            raise ValueError("Account (email) and password are required")

        client = ZendureClient(base_url=base_url)
        login_data = client.login(account, password)
        devices = client.list_devices()

        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = {"client": client, "allowed_urls": set()}

        safe_devices = [
            {
                "id": d.get("id") or d.get("deviceId"),
                "name": d.get("name") or "",
                "productName": d.get("productName") or "",
                "productType": str(d.get("productType") or "17"),
                "deviceKey": d.get("deviceKey") or "",
                "snNumber": d.get("snNumber") or "",
                "otaBatch": d.get("otaBatch"),
            }
            for d in devices
        ]
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "sessionId": sid,
                "serverNode": login_data.get("serverNode") or "",
                "baseUrl": client.base_url,
                "iotUrl": login_data.get("iotUrl") or "",
                "devices": safe_devices,
            },
        )

    def _handle_firmware(self):
        body = self._read_json()
        sid = str(body.get("sessionId", ""))
        sess = SESSIONS.get(sid)
        if not sess:
            raise ValueError("Session expired or invalid — please log in again")

        device_id = int(body["deviceId"])
        product_type = str(body.get("productType") or "17")
        client: ZendureClient = sess["client"]

        fw_items = []
        batch_err = None
        try:
            batch_data = client.get_batch_firmware(device_id)
            if isinstance(batch_data, dict) and batch_data.get("firmwareList"):
                fw_items = batch_data["firmwareList"]
        except Exception as e:
            batch_err = str(e)

        if not fw_items:
            single_data = client.get_single_firmware(device_id, product_type)
            if isinstance(single_data, dict) and single_data.get("firmwareList"):
                fw_items = single_data["firmwareList"]

        results = []
        for item in fw_items:
            url = item.get("firmwareUrl") or ""
            if url:
                sess["allowed_urls"].add(url)
            module = item.get("moduleName") or item.get("module") or "firmware"
            version = item.get("version") or item.get("upgradeVersion") or item.get("intVersion") or "unknown"
            ext = Path(urlparse(url).path).suffix or ".bin"
            filename = f"{module}_v{version}{ext}".replace("/", "_")
            results.append(
                {
                    "module": module,
                    "version": str(version),
                    "intVersion": item.get("intVersion"),
                    "upgrade": bool(item.get("upgrade", True)),
                    "md5": item.get("md5") or "",
                    "url": url,
                    "filename": filename,
                }
            )

        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "firmwareList": results, "batchFallbackNote": batch_err},
        )

    def _handle_download(self):
        body = self._read_json()
        sid = str(body.get("sessionId", ""))
        url = str(body.get("url", ""))
        expected_md5 = str(body.get("expectedMd5", "")).strip().lower()
        filename = str(body.get("filename") or "firmware.bin").replace('"', "")

        sess = SESSIONS.get(sid)
        if not sess:
            raise ValueError("Session expired or invalid — please log in again")
        if url not in sess["allowed_urls"]:
            raise ValueError("URL not in authorized firmware list for this session")

        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.content
        actual_md5 = hashlib.md5(data).hexdigest().lower()
        md5_ok = (not expected_md5) or (actual_md5 == expected_md5)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-MD5", actual_md5)
        self.send_header("X-MD5-Match", "1" if md5_ok else "0")
        self.send_header("X-Filename", filename)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def detect_lan_ips() -> list[str]:
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


def make_self_signed_ssl_context(extra_ips: list[str]) -> ssl.SSLContext:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hyper2000-ota.local")])
    sans: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    for ip_str in set(extra_ips):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.NamedTemporaryFile(delete=False) as cf, tempfile.NamedTemporaryFile(delete=False) as kf:
        cf.write(cert_pem)
        kf.write(key_pem)
        cert_path, key_path = cf.name, kf.name
    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)
    return ctx


def main():
    parser = argparse.ArgumentParser(description="Local server for Hyper 2000 Download + Patch + BLE OTA webapp.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1; use 0.0.0.0 for LAN)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--https-port", type=int, default=0, help="Optional self-signed HTTPS port (e.g. 8443 for LAN Web Bluetooth)")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), OtaWebHandler)
    lan_ips = detect_lan_ips() if args.host == "0.0.0.0" else []

    print(f"Hyper 2000 BLE OTA Webapp HTTP  : http://localhost:{args.port}/")
    for ip in lan_ips:
        print(f"Hyper 2000 BLE OTA Webapp LAN   : http://{ip}:{args.port}/")

    httpsd = None
    if args.https_port:
        ctx = make_self_signed_ssl_context(lan_ips)
        httpsd = ThreadingHTTPServer((args.host, args.https_port), OtaWebHandler)
        httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
        threading.Thread(target=httpsd.serve_forever, daemon=True).start()
        print(f"Hyper 2000 BLE OTA Webapp HTTPS : https://localhost:{args.https_port}/")
        for ip in lan_ips:
            print(f"Hyper 2000 BLE OTA Webapp LAN   : https://{ip}:{args.https_port}/")

    print("Open in Chrome, Edge, or Chromium (Ctrl+C to stop).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if httpsd:
            httpsd.shutdown()


if __name__ == "__main__":
    main()
