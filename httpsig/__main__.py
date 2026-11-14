"""CLI. inspect already works; verify and sign are the pieces to implement."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from httpsig.engine import EngineError
from httpsig.load import LoadError, load_keys, load_message, load_policy, signature_labels


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="httpsig")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show method, target, and signature header text")
    ins.add_argument("--message", required=True)
    ver = sub.add_parser("verify", help="verify signatures on a request snapshot")
    ver.add_argument("--message", required=True)
    ver.add_argument("--keys", required=True)
    ver.add_argument("--policy", required=True)
    ver.add_argument("--report", required=True)
    sgn = sub.add_parser("sign", help="add a signature to a request snapshot")
    sgn.add_argument("--message", required=True)
    sgn.add_argument("--keys", required=True)
    sgn.add_argument("--policy", required=True)
    sgn.add_argument("--output", required=True)
    sgn.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        message = load_message(args.message)
    except (LoadError, OSError, KeyError, ValueError) as exc:
        print(f"failed to load message: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps({
            "method": message["method"],
            "scheme": message["scheme"],
            "authority": message["authority"],
            "path": message["path"],
            "query": message.get("query", ""),
            "now": message["now"],
            "header_names": [h[0] for h in message["headers"]],
            "signature_input": signature_labels(message),
            "body_chars": len(message.get("body") or ""),
        }, ensure_ascii=False, indent=2))
        return 0
    try:
        keys = load_keys(args.keys)
        policy = load_policy(args.policy)
    except (LoadError, OSError) as exc:
        print(f"failed to load keys or policy: {exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "verify":
            from httpsig.engine import verify
            report = verify(message, keys, policy)
            if isinstance(report, dict):
                report.setdefault('input', args.message)
                report.setdefault("policy", args.policy)
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            decision = str(report.get("decision", "")).lower()
            if decision == "ok":
                return 0
            if decision == "reject":
                return 1
            print("report is missing a decision of ok or reject", file=sys.stderr)
            return 2
        if args.cmd == "sign":
            from httpsig.engine import sign
            output, report = sign(message, keys, policy)
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            if isinstance(report, dict):
                report.setdefault('input', args.message)
                report.setdefault("policy", args.policy)
            Path(args.output).write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            decision = str(report.get("decision", "")).lower()
            if decision == "ok":
                return 0
            if decision == "reject":
                return 1
            print("report is missing a decision of ok or reject", file=sys.stderr)
            return 2
    except (NotImplementedError, EngineError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
