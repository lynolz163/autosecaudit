"""Lightweight socket-based validation script example."""

from __future__ import annotations

import argparse
import json
import socket


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Socket port validation check")
    parser.add_argument("--target", required=True)
    parser.add_argument("--options-json", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        options = json.loads(args.options_json)
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "is_confirmed": False,
                    "response_snippet": f"Invalid options JSON: {exc}",
                }
            )
        )
        return 2

    port = int(options.get("port", 80))
    timeout = float(options.get("timeout", 3.0))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((args.target, port))
    except OSError as exc:
        print(
            json.dumps(
                {
                    "is_confirmed": False,
                    "response_snippet": f"Socket error: {exc}",
                }
            )
        )
        return 1
    finally:
        sock.close()

    is_open = code == 0
    message = f"Port {port} {'open' if is_open else 'closed/unreachable'} on {args.target}"
    print(json.dumps({"is_confirmed": is_open, "response_snippet": message}))
    return 0 if is_open else 1


if __name__ == "__main__":
    raise SystemExit(main())
