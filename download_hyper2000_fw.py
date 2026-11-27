#!/usr/bin/env python3
"""
Download the latest firmware for a Zendure Hyper 2000 (or other Zendure device)
via the Zendure cloud API extracted from com.zendure.iot v7.2.0.

Usage:
  ./download_hyper2000_fw.py
  ./download_hyper2000_fw.py --account you@example.com --device-id 123456
  ./download_hyper2000_fw.py --urls-only
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

DEFAULT_BASE_URL = "https://app.zendure.tech/v2/"
APP_VERSION = "7.2.0"

# X.509 SPKI RSA public key from libzen_native.so (JNIHelper.getPublicKey)
RSA_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwoqArnVK5cuSHL3t9uf3d1CGl"
    "mcaFE/NT+t84RuMfLZzfuZbmElP3XmyywvTkNUlBdr6Za2tjVKQqKo5AVV1cxVpa"
    "+GLrLpSuH4U/zeLzeKLpNy9k+B9FoLXBDT4LaJoIcj9VLhlZWMTLxVwXU5NhI/lx"
    "Wj7cK337dux7NbKltwIDAQAB"
)


def load_public_key():
    der = base64.b64decode(RSA_PUBLIC_KEY_B64)
    return serialization.load_der_public_key(der)


def sign_request(public_key, rel_path: str, ts_sec: int, app_version: str = APP_VERSION) -> str:
    # Matches HeaderInterceptor.intercept + MyEncryptUtils.OOO0
    path = rel_path.split("?", 1)[0].split("#", 1)[0]
    if path.startswith("tdengine/"):
        path = path[len("tdengine/"):]
    payload = f"{app_version}./{path}/{ts_sec}".encode("utf-8")
    encrypted = public_key.encrypt(payload, padding.PKCS1v15())
    return base64.b64encode(encrypted).decode("ascii")


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


class ZendureClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, app_version: str = APP_VERSION):
        self.base_url = ensure_trailing_slash(base_url)
        self.app_version = app_version
        self.token = ""
        self.public_key = load_public_key()
        self.session = requests.Session()

    def _headers(self, rel_path: str) -> dict:
        # MyTimeUtils.OooO() returns Unix timestamp in SECONDS (OoO0() / 1000)
        ts_sec = int(time.time())
        headers = {
            "Accept-Language": "en-US",
            "appVersion": self.app_version,
            "timestamps": str(ts_sec),
            "sign": sign_request(self.public_key, rel_path, ts_sec, self.app_version),
            "style": "light",
            "Content-Type": "application/json",
        }
        if self.token:
            headers["Blade-Auth"] = f"bearer {self.token}"
        return headers

    def post(self, rel_path: str, payload=None) -> dict:
        url = self.base_url + rel_path.lstrip("/")
        resp = self.session.post(
            url,
            headers=self._headers(rel_path.lstrip("/")),
            json=payload if payload is not None else {},
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"HTTP {resp.status_code} on {url}: {resp.text}")
        data = resp.json()
        if not data.get("success", False):
            code = data.get("code")
            msg = data.get("msg") or data.get("message") or str(data)
            raise RuntimeError(f"API error on {rel_path} (code={code}): {msg}")
        return data.get("data")

    def login(self, account: str, password: str) -> dict:
        body = {
            "grantType": "password",
            "tenantId": "",
            "account": account,
            "password": password,
            "appType": "Android",
        }
        data = self.post("auth/app/token", body)
        if not isinstance(data, dict) or not data.get("accessToken"):
            raise RuntimeError(f"Login succeeded but no accessToken in response: {data}")
        self.token = data["accessToken"]
        server_node_url = data.get("serverNodeUrl")
        if server_node_url:
            self.base_url = ensure_trailing_slash(server_node_url)
        return data

    def list_devices(self) -> list:
        data = self.post("productModule/device/queryDeviceListByConsumerId", {})
        return data if isinstance(data, list) else []

    def get_batch_firmware(self, device_id: int) -> dict:
        return self.post("ota/batch/firmware", {"deviceId": device_id})

    def get_single_firmware(self, device_id: int, product_type: str = "17") -> dict:
        return self.post(
            "productModule/device/getFirmwareVersion",
            {"deviceId": device_id, "productType": product_type},
        )


def download_file(url: str, dest: Path, expected_md5: str = "") -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  Downloading -> {dest}")
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        hasher = hashlib.md5()
        total = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    hasher.update(chunk)
                    total += len(chunk)
    digest = hasher.hexdigest()
    print(f"  Saved {total} bytes (md5={digest})")
    if expected_md5 and digest.lower() != expected_md5.lower():
        print(f"  WARNING: MD5 mismatch! expected={expected_md5} actual={digest}", file=sys.stderr)


def pick_device(devices: list) -> tuple[int, str]:
    if not devices:
        raise RuntimeError("No devices found on this account.")
    print("\nDevices on your account:")
    for idx, d in enumerate(devices):
        did = d.get("id") or d.get("deviceId")
        name = d.get("name", "")
        pname = d.get("productName", "")
        ptype = d.get("productType", "")
        sn = d.get("snNumber", "")
        ota_batch = d.get("otaBatch")
        print(f"  [{idx}] id={did} | {name} ({pname}, productType={ptype}, sn={sn}, otaBatch={ota_batch})")

    raw = input("\nEnter device index or numeric deviceId: ").strip()
    if raw.isdigit():
        val = int(raw)
        if 0 <= val < len(devices):
            d = devices[val]
            return int(d.get("id") or d.get("deviceId")), str(d.get("productType") or "17")
        return val, "17"
    raise ValueError(f"Invalid selection: {raw}")


def main():
    parser = argparse.ArgumentParser(description="Fetch and download latest Zendure Hyper 2000 firmware.")
    parser.add_argument("--account", default=os.environ.get("ZENDURE_ACCOUNT", ""), help="Zendure account email")
    parser.add_argument("--password", default=os.environ.get("ZENDURE_PASSWORD", ""), help="Zendure account password")
    parser.add_argument("--device-id", type=int, default=None, help="Numeric Zendure deviceId (omit to list devices)")
    parser.add_argument("--product-type", default="17", help="Product type for non-batch fallback (default: 17 = Hyper 2000)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"API base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--out-dir", default="./hyper2000_fw", help="Directory to save downloaded firmware files")
    parser.add_argument("--urls-only", action="store_true", help="Print firmware metadata & URLs without downloading")
    parser.add_argument("--all", action="store_true", help="Download all entries even if upgrade=false")
    args = parser.parse_args()

    account = args.account or input("Zendure account (email): ").strip()
    password = args.password or getpass.getpass("Zendure password: ")
    if not account or not password:
        print("Account and password are required.", file=sys.stderr)
        sys.exit(1)

    client = ZendureClient(base_url=args.base_url)
    print(f"Logging in to {client.base_url} ...")
    login_data = client.login(account, password)
    print(f"Logged in (serverNode={login_data.get('serverNode')}, baseUrl={client.base_url})")

    device_id = args.device_id
    product_type = args.product_type
    if device_id is None:
        devices = client.list_devices()
        device_id, product_type = pick_device(devices)

    print(f"\nQuerying batch firmware for deviceId={device_id} ...")
    fw_items = []
    try:
        batch_data = client.get_batch_firmware(device_id)
        print("Batch OTA response:")
        print(json.dumps(batch_data, indent=2, ensure_ascii=False))
        if isinstance(batch_data, dict) and batch_data.get("firmwareList"):
            fw_items = batch_data["firmwareList"]
    except Exception as e:
        print(f"Batch endpoint failed ({e}); trying legacy getFirmwareVersion...")

    if not fw_items:
        print(f"\nQuerying getFirmwareVersion for deviceId={device_id}, productType={product_type} ...")
        single_data = client.get_single_firmware(device_id, product_type)
        print("Single OTA response:")
        print(json.dumps(single_data, indent=2, ensure_ascii=False))
        if isinstance(single_data, dict) and single_data.get("firmwareList"):
            fw_items = single_data["firmwareList"]

    if not fw_items:
        print("\nNo firmware entries returned (device may already be on the latest firmware).")
        return

    out_dir = Path(args.out_dir)
    print(f"\nFound {len(fw_items)} firmware entry/entries:")
    for item in fw_items:
        module = item.get("moduleName") or item.get("module") or "firmware"
        version = item.get("version") or item.get("upgradeVersion") or item.get("intVersion") or "unknown"
        url = item.get("firmwareUrl") or ""
        md5 = item.get("md5") or ""
        upgrade = item.get("upgrade", True)
        print(f"- module={module} version={version} upgrade={upgrade} md5={md5}")
        print(f"  url={url}")

        if args.urls_only or not url:
            continue
        if not upgrade and not args.all:
            print("  Skipping (upgrade=false; pass --all to download anyway)")
            continue

        ext = Path(urlparse(url).path).suffix or ".bin"
        filename = f"{module}_v{version}{ext}".replace("/", "_")
        download_file(url, out_dir / filename, expected_md5=md5)


if __name__ == "__main__":
    main()
