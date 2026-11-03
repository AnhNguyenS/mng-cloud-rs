#!/usr/bin/env python3
"""Build the MNG Cloud Trusted browser extension.

The extension is plain WebExtensions (Chromium MV3, also loadable in Orion).
This script stamps the deployment/release origins into manifest.json and emits
config.js with the pinned P-256 public key. It does not sign anything: the
signed release metadata always comes from the offline signer.

Usage:
    python tools/build-extension.py \
        --config extension/config.example.json \
        --out dist/extension

Add --production to reject loopback or placeholder origins, and --zip to create
a reproducible archive next to the output directory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "extension" / "src"
DEFAULT_PUBLIC_KEY = ROOT / "ops" / "update-public.jwk"
COPY_FILES = [
    "background.js",
    "content.js",
    "popup.html",
    "popup.js",
    "popup.css",
    "trust.js",
]
ICON_SIZES = (16, 32, 48, 128)
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
PLACEHOLDER_MARKERS = ("example.com", "your_github", "your-", "changeme")


def fail(message: str) -> None:
    print(f"build-extension: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing file: {path}")
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in {path}: {error}")


def b64url_decode(value: str, label: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value or ""):
        fail(f"{label} is not base64url")
    padded = value.replace("-", "+").replace("_", "/")
    padded += "=" * ((4 - len(padded) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception as error:  # noqa: BLE001 - report the validation reason
        fail(f"{label} is not valid base64url: {error}")


def validate_public_key(jwk: dict) -> None:
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        fail("pinned public key must be an EC P-256 JWK")
    if len(b64url_decode(jwk.get("x", ""), "pinned key x")) != 32:
        fail("pinned key x must be 32 bytes")
    if len(b64url_decode(jwk.get("y", ""), "pinned key y")) != 32:
        fail("pinned key y must be 32 bytes")


def parse_https_url(value: str, label: str, *, production: bool) -> urlparse:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        fail(f"{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        fail(f"{label} must not contain credentials")
    host = parsed.hostname.lower()
    loopback = host in LOOPBACK_HOSTS
    if parsed.scheme == "http" and not loopback:
        fail(f"{label} must use HTTPS")
    if production and loopback:
        fail(f"{label} points to loopback; refusing a production build")
    return parsed


def validate_config(config: dict, *, production: bool) -> dict:
    if config.get("schema") != 1:
        fail("config schema must be 1")
    version = str(config.get("extensionVersion", ""))
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
        fail("extensionVersion must be 1-4 dot-separated integers")
    deployments = config.get("deployments")
    if not isinstance(deployments, list) or not deployments:
        fail("at least one deployment is required")
    normalized = []
    for index, item in enumerate(deployments):
        if not isinstance(item, dict):
            fail(f"deployments[{index}] is not an object")
        origin = item.get("origin")
        if not isinstance(origin, str):
            fail(f"deployments[{index}].origin is missing")
        parsed = parse_https_url(origin, f"deployments[{index}].origin", production=production)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            fail(f"deployments[{index}].origin must not contain a path")
        app_base = item.get("appBase")
        if (
            not isinstance(app_base, str)
            or not app_base.startswith("/")
            or not app_base.endswith("/")
            or ".." in app_base
            or "?" in app_base
            or "#" in app_base
            or "\\" in app_base
        ):
            fail(f"deployments[{index}].appBase must start and end with /")
        if production and any(marker in parsed.hostname.lower() for marker in PLACEHOLDER_MARKERS):
            fail(f"deployments[{index}].origin still contains a placeholder")
        normalized.append({"origin": f"{parsed.scheme}://{parsed.netloc}", "appBase": app_base})

    release_base = config.get("releaseBase")
    if not isinstance(release_base, str):
        fail("releaseBase is missing")
    release = parse_https_url(release_base, "releaseBase", production=production)
    if not release.path.endswith("/"):
        fail("releaseBase must end with /")
    if production and any(marker in release.hostname.lower() for marker in PLACEHOLDER_MARKERS):
        fail("releaseBase still contains a placeholder")

    jwk = config.get("pinnedPublicJwk")
    validate_public_key(jwk)
    limits = config.get("limits") or {}
    for key in ("maxAssetBytes", "maxTotalBytes", "releaseTimeoutMs", "pageTimeoutMs"):
        if key in limits and (not isinstance(limits[key], int) or limits[key] <= 0):
            fail(f"limits.{key} must be a positive integer")

    normalized_config = dict(config)
    normalized_config["extensionVersion"] = version
    normalized_config["deployments"] = normalized
    normalized_config["releaseBase"] = release_base
    normalized_config["pinnedPublicJwk"] = jwk
    return normalized_config


def host_pattern(parsed: urlparse) -> str:
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}/*"


def build_manifest(config: dict) -> dict:
    template = load_json(SRC / "manifest.template.json")
    manifest = dict(template)
    manifest["version"] = config["extensionVersion"]
    origins = []
    app_matches = []
    for deployment in config["deployments"]:
        parsed = urlparse(deployment["origin"])
        origins.append(host_pattern(parsed))
        app_matches.append(host_pattern(parsed))
    release = urlparse(config["releaseBase"])
    origins.append(host_pattern(release))
    manifest["host_permissions"] = sorted(set(origins))
    manifest["content_scripts"] = [
        {
            "matches": sorted(set(app_matches)),
            "js": ["content.js"],
            "run_at": "document_start",
            "all_frames": False,
        }
    ]
    return manifest


def generate_config_js(config: dict) -> str:
    payload = json.dumps(config, ensure_ascii=False, indent=2)
    return (
        "/* Generated by tools/build-extension.py. Do not edit the built copy. */\n"
        f"export const CONFIG = Object.freeze({payload});\n"
    )


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def point_segment_distance(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx = bx - ax
    dy = by - ay
    length_sq = dx * dx + dy * dy
    if length_sq == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length_sq))
    qx = ax + t * dx
    qy = ay + t * dy
    return ((px - qx) ** 2 + (py - qy) ** 2) ** 0.5


def make_icon(size: int) -> bytes:
    scale = 4
    width = size * scale
    pixels = [[(0, 0, 0, 0)] * width for _ in range(width)]
    center = width / 2.0
    radius = width * 0.46
    thickness = width * 0.085
    for y in range(width):
        for x in range(width):
            dx = x + 0.5 - center
            dy = y + 0.5 - center
            distance = (dx * dx + dy * dy) ** 0.5
            if distance > radius:
                continue
            shade = (15, 123, 63, 255) if distance < radius - width * 0.035 else (9, 74, 40, 255)
            check = min(
                point_segment_distance(x, y, width * 0.28, width * 0.53, width * 0.44, width * 0.69),
                point_segment_distance(x, y, width * 0.44, width * 0.69, width * 0.73, width * 0.36),
            )
            pixels[y][x] = (255, 255, 255, 255) if check <= thickness else shade

    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            total = [0, 0, 0, 0]
            for sy in range(scale):
                for sx in range(scale):
                    pixel = pixels[y * scale + sy][x * scale + sx]
                    for index in range(4):
                        total[index] += pixel[index]
            rows.extend(value // (scale * scale) for value in total)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + png_chunk(b"IEND", b"")
    )


def zip_tree(root: Path, output: Path) -> None:
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"zip: {output} sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "extension" / "config.example.json")
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "extension")
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--zip", action="store_true")
    args = parser.parse_args()

    config = load_json(args.config)
    if args.public_key:
        config["pinnedPublicJwk"] = load_json(args.public_key)
    config = validate_config(config, production=args.production)

    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    for name in COPY_FILES:
        source = SRC / name
        if not source.is_file():
            fail(f"missing source file: {source}")
        shutil.copy2(source, out / name)

    manifest = build_manifest(config)
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (out / "config.js").write_text(generate_config_js(config), encoding="utf-8")

    icons = out / "icons"
    icons.mkdir()
    for size in ICON_SIZES:
        (icons / f"{size}.png").write_bytes(make_icon(size))

    print(f"built: {out}")
    print(f"version: {config['extensionVersion']}")
    for deployment in config["deployments"]:
        print(f"deployment: {deployment['origin']}{deployment['appBase']}")
    print(f"release: {config['releaseBase']}")
    print(f"pinned key: {config['pinnedPublicJwk']['x'][:12]}…")

    if args.zip:
        zip_tree(out, out.with_suffix(".zip"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
