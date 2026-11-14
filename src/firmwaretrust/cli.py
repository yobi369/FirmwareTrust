from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from firmwaretrust.core import (
    FirmwareTrustError,
    generate_key_pair,
    sign_firmware,
    verify_firmware,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firmwaretrust",
        description="Sign firmware release manifests and verify firmware integrity.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="Generate an Ed25519 development key pair.")
    keygen.add_argument("--private-key", required=True, type=Path)
    keygen.add_argument("--public-key", required=True, type=Path)

    sign = commands.add_parser("sign", help="Sign a firmware file into a JSON manifest.")
    sign.add_argument("--firmware", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--manifest", required=True, type=Path)

    verify = commands.add_parser("verify", help="Verify firmware and its signed manifest.")
    verify.add_argument("--firmware", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "keygen":
            identifier = generate_key_pair(args.private_key, args.public_key)
            print(json.dumps({"created": True, "key_id": identifier}, indent=2))
        elif args.command == "sign":
            result = sign_firmware(args.firmware, args.private_key, args.manifest)
            print(json.dumps({
                "signed": True,
                "manifest": str(args.manifest),
                "key_id": result["signature"]["key_id"],
                "sha256": result["artifact"]["digest"],
            }, indent=2))
        else:
            result = verify_firmware(args.firmware, args.manifest, args.public_key)
            print(json.dumps(result, indent=2))
        return 0
    except (FirmwareTrustError, OSError) as exc:
        print(f"firmwaretrust: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
