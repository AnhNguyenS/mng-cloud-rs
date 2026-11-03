#!/usr/bin/env python3
"""Serve a signed release directory for local extension testing.

GitHub Pages and raw.githubusercontent.com send CORS headers; Python's stock
http.server does not, and an extension service worker fetch is cross-origin.
This development helper adds the header and refuses path traversal.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import os
from pathlib import Path


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8092)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")
    handler = functools.partial(Handler, directory=str(root))
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    print(f"serving {root} at http://{args.bind}:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
