"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from veilrelay.config import Settings
from veilrelay.detectors import BuiltinDetector, SecretDetector
from veilrelay.policy import PolicyConfig, PrivacyEngine
from veilrelay.vault import TokenVault


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="veil", description="Local-first LLM privacy proxy")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="start the OpenAI-compatible proxy")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--config", default=None)
    scan = subparsers.add_parser("scan", help="dry-run detection and tokenization")
    scan.add_argument("text", help="text to inspect")
    scan.add_argument("--config", default=None)
    subparsers.add_parser("bench", help="run the reproducible synthetic benchmark")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "serve":
        if args.config:
            import os

            os.environ["VEIL_POLICY_FILE"] = args.config
        settings = Settings.from_env()
        host, port = args.host or settings.host, args.port or settings.port
        import uvicorn

        uvicorn.run("veilrelay.proxy:app", host=host, port=port, log_level="info")
        return
    if args.command == "scan":
        policy = PolicyConfig.from_yaml(args.config) if args.config else PolicyConfig()
        engine = PrivacyEngine([BuiltinDetector(), SecretDetector()], policy)
        vault = TokenVault(policy.ttl_seconds)
        try:
            result = engine.scan(args.text, vault)
            print(result.safe_text)
            print(json.dumps({"entity_counts": result.counts, "actions": result.actions}, sort_keys=True))
        finally:
            vault.clear()
        return
    if args.command == "bench":
        from veilrelay.benchmark import main as benchmark_main

        benchmark_main()
        return
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)


if __name__ == "__main__":
    main()
