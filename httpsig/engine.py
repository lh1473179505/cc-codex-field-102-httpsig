"""sign and verify for the RFC 9421 subset described in docs/sign-rules.md."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any
from urllib.parse import unquote_plus

from httpsig.sfv import (
    InnerList,
    Item,
    SfToken,
    SfvError,
    _is_token,
    dumps_dict,
    dumps_inner_list,
    dumps_item,
    parse_dict,
)

ALG = "hmac-sha256"
DERIVED = {"@method", "@authority", "@scheme", "@path", "@query", "@query-param", "@target-uri"}
FORBIDDEN = {"signature", "signature-input", "@signature-params"}


class EngineError(Exception):
    """Fatal snapshot/key/signature-header parse problem -> exit 2."""


class _Codes:
    """Collects reason codes for one label, deduped in first-seen order."""

    def __init__(self) -> None:
        self.codes: list[str] = []

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


def _header_values(message: dict[str, Any], name: str) -> list[str]:
    lname = name.lower()
    return [
        v
        for n, v in message.get("headers") or []
        if isinstance(n, str) and n.lower() == lname and isinstance(v, str)
    ]


def _combined_header(message: dict[str, Any], name: str) -> str | None:
    vals = _header_values(message, name)
    return ", ".join(vals) if vals else None


def _parse_signature_headers(message: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    si_text = _combined_header(message, "signature-input")
    sig_text = _combined_header(message, "signature")
    try:
        inputs = parse_dict(si_text) if si_text else {}
        sigs = parse_dict(sig_text) if sig_text else {}
    except SfvError as exc:
        raise EngineError(f"cannot parse signature headers: {exc}") from exc
    for label, value in inputs.items():
        if not isinstance(value, InnerList):
            raise EngineError(f"signature-input member {label!r} is not an inner list")
    for label, value in sigs.items():
        if not isinstance(value, Item) or not isinstance(value.value, bytes):
            raise EngineError(f"signature member {label!r} is not a byte sequence")
    if set(inputs) != set(sigs):
        raise EngineError("signature and signature-input labels do not pair up")
    return inputs, sigs


def _query_pairs(query: str) -> list[tuple[str, str]]:
    pairs = []
    if not query:
        return pairs
    for part in query.split("&"):
        name, _, value = part.partition("=")
        pairs.append((unquote_plus(name), unquote_plus(value)))
    return pairs


def _derived_value(message: dict[str, Any], lname: str, params: dict[str, Any], codes: _Codes) -> str | None:
    if lname == "@method":
        return str(message["method"]).upper()
    if lname == "@authority":
        return str(message["authority"]).lower()
    if lname == "@scheme":
        return str(message["scheme"]).lower()
    if lname == "@path":
        path = str(message["path"])
        if not path.startswith("/"):
            codes.add("bad_path")
            return None
        return path
    if lname == "@query":
        query = message.get("query") or ""
        if query.startswith("?"):
            codes.add("bad_query")
            return None
        return "?" + query
    if lname == "@query-param":
        query = message.get("query") or ""
        if query.startswith("?"):
            codes.add("bad_query")
            return None
        target = params["name"]
        matches = [v for n, v in _query_pairs(query) if n == target]
        if not matches:
            codes.add("missing_component")
            return None
        if len(matches) > 1:
            codes.add("duplicate_query_param")
            return None
        return matches[0]
    if lname == "@target-uri":
        uri = str(message["scheme"]).lower() + "://" + str(message["authority"]).lower() + str(message["path"])
        query = message.get("query") or ""
        if query:
            uri += "?" + query
        return uri
    codes.add("missing_component")
    return None


def _component_value(message: dict[str, Any], comp: Item, codes: _Codes) -> str | None:
    name = comp.value
    params = comp.params or {}
    if not isinstance(name, str):
        codes.add("missing_component")
        return None
    lname = name.lower()
    if lname in FORBIDDEN:
        codes.add("forbidden_component")
        return None
    if lname.startswith("@"):
        if lname not in DERIVED:
            codes.add("missing_component")
            return None
        if lname == "@query-param":
            pname = params.get("name")
            if not isinstance(pname, str) or isinstance(pname, SfToken):
                codes.add("query_param_name")
                return None
            if any(k != "name" for k in params):
                codes.add("unsupported_param")
                return None
        elif params:
            codes.add("unsupported_param")
            return None
        return _derived_value(message, lname, params, codes)
    if params:
        codes.add("unsupported_param")
        return None
    vals = _header_values(message, lname)
    if not vals:
        codes.add("missing_component")
        return None
    return ", ".join(vals)


def _base_string(components: list[tuple[Item, str]], inner: InnerList) -> str:
    lines = [f"{dumps_item(comp)}: {value}" for comp, value in components]
    lines.append('"@signature-params": ' + dumps_inner_list(inner))
    return "\n".join(lines)


def _check_required_components(policy: dict[str, Any], covered: list[tuple[str, dict[str, Any]]], codes: _Codes) -> None:
    for req in policy.get("required_components") or []:
        if isinstance(req, str):
            if req.lower() not in {name for name, _ in covered}:
                codes.add("missing_component")
        elif isinstance(req, dict):
            rname = str(req.get("name", "")).lower()
            rparams = req.get("params") or {}
            if not any(
                name == rname and all(params.get(k) == v for k, v in rparams.items())
                for name, params in covered
            ):
                codes.add("missing_component")


def _check_content_digest(message: dict[str, Any], covered_names: set, codes: _Codes) -> None:
    body = message.get("body") or ""
    if body == "":
        return
    ok = False
    vals = _header_values(message, "content-digest")
    if vals:
        try:
            parsed = parse_dict(", ".join(vals))
            entry = parsed.get("sha-256")
            if isinstance(entry, Item) and isinstance(entry.value, bytes):
                ok = hmac.compare_digest(entry.value, hashlib.sha256(body.encode("utf-8")).digest())
        except SfvError:
            ok = False
    if not ok or "content-digest" not in covered_names:
        codes.add("content_digest_mismatch")


def _key_bytes(keys: dict[str, Any], keyid: Any, policy: dict[str, Any], codes: _Codes) -> bytes | None:
    table = keys.get("keys") or {}
    allowed = policy.get("allowed_keyids")
    if (
        not isinstance(keyid, str)
        or isinstance(keyid, SfToken)
        or keyid not in table
        or (allowed is not None and keyid not in allowed)
    ):
        codes.add("unknown_keyid")
        return None
    entry = table[keyid]
    if isinstance(entry, dict) and entry.get("alg", ALG) != ALG:
        codes.add("alg_not_allowed")
        return None
    try:
        return bytes.fromhex(entry["hex"])
    except (KeyError, TypeError, ValueError):
        codes.add("unknown_keyid")
        return None


def _check_time_and_tag(message: dict[str, Any], policy: dict[str, Any], params: dict[str, Any], codes: _Codes) -> None:
    now = message["now"]
    skew = policy.get("max_clock_skew", 0)
    created = params.get("created")
    if not isinstance(created, int) or isinstance(created, bool):
        codes.add("missing_created")
    elif created > now + skew:
        codes.add("not_yet_valid")
    expires = params.get("expires")
    if isinstance(expires, int) and not isinstance(expires, bool) and expires < now - skew:
        codes.add("expired")
    required_tag = policy.get("required_tag")
    if required_tag is not None and params.get("tag") != required_tag:
        codes.add("tag_mismatch")


def _verify_label(
    message: dict[str, Any],
    keys: dict[str, Any],
    policy: dict[str, Any],
    inner: InnerList,
    sig_item: Item,
) -> tuple[list, str | None]:
    codes = _Codes()
    components: list[tuple[Item, str]] = []
    covered: list[tuple[str, dict[str, Any]]] = []
    for item in inner.items:
        value = _component_value(message, item, codes)
        if value is None:
            continue
        components.append((item, value))
        covered.append((str(item.value).lower(), dict(item.params or {})))
    params = inner.params or {}
    alg = params.get("alg", SfToken(ALG))
    allowed_algs = policy.get("allowed_algs") or [ALG]
    if str(alg) != ALG or str(alg) not in allowed_algs:
        codes.add("alg_not_allowed")
    key = _key_bytes(keys, params.get("keyid"), policy, codes)
    _check_time_and_tag(message, policy, params, codes)
    _check_required_components(policy, covered, codes)
    if policy.get("require_content_digest"):
        _check_content_digest(message, {name for name, _ in covered}, codes)
    base: str | None = None
    if len(components) == len(inner.items):
        base = _base_string(components, inner)
        if key is not None:
            expected = hmac.new(key, base.encode("utf-8"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, sig_item.value):
                codes.add("bad_signature")
    return codes.codes, base


def verify(message: dict[str, Any], keys: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    inputs, sigs = _parse_signature_headers(message)
    labels = list(inputs.keys())
    report: dict[str, Any] = {"decision": "ok", "reason_codes": [], "labels": labels, "bases": {}}
    if not labels:
        report["decision"] = "reject"
        report["reason_codes"] = ["missing_signature"]
        return report
    all_codes: list[str] = []
    for label in labels:
        codes, base = _verify_label(message, keys, policy, inputs[label], sigs[label])
        if base is not None:
            report["bases"][label] = base
        for code in codes:
            if code not in all_codes:
                all_codes.append(code)
    if all_codes:
        report["decision"] = "reject"
        report["reason_codes"] = all_codes
    return report


def _component_item(name: Any) -> Item:
    text = str(name)
    if text.startswith("@") or not _is_token(text):
        return Item(text, {})
    return Item(SfToken(text), {})


def sign(message: dict[str, Any], keys: dict[str, Any], policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = policy.get("sign")
    if not isinstance(cfg, dict):
        raise EngineError("policy has no sign object")
    label = cfg.get("label")
    keyid = cfg.get("keyid")
    components_cfg = cfg.get("components")
    if not isinstance(label, str) or not label or not isinstance(components_cfg, list):
        raise EngineError("policy sign object needs label and components")

    headers = [list(h) for h in message.get("headers") or []]
    body = message.get("body") or ""
    if cfg.get("ensure_content_digest"):
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        headers = [h for h in headers if not (isinstance(h[0], str) and h[0].lower() == "content-digest")]
        headers.append(["content-digest", dumps_dict({"sha-256": Item(digest, {})})])

    output = {k: v for k, v in message.items() if not str(k).startswith("_")}
    output["headers"] = headers

    codes = _Codes()
    key = _key_bytes(keys, keyid, policy, codes)
    items = [_component_item(c) for c in components_cfg]
    components: list[tuple[Item, str]] = []
    for item in items:
        value = _component_value(output, item, codes)
        if value is not None:
            components.append((item, value))
    params: dict[str, Any] = {}
    if "created" in cfg:
        params["created"] = cfg["created"]
    if keyid is not None:
        params["keyid"] = keyid
    params["alg"] = SfToken(ALG)
    for opt in ("expires", "nonce", "tag"):
        if opt in cfg:
            params[opt] = cfg[opt]
    inner = InnerList(items, params)

    base: str | None = None
    if not codes.codes and key is not None and len(components) == len(items):
        base = _base_string(components, inner)
        sig_bytes = hmac.new(key, base.encode("utf-8"), hashlib.sha256).digest()
        inputs, sigs = _parse_signature_headers(output)
        inputs.pop(label, None)
        sigs.pop(label, None)
        inputs[label] = inner
        sigs[label] = Item(sig_bytes, {})
        headers = [
            h for h in headers
            if not (isinstance(h[0], str) and h[0].lower() in ("signature-input", "signature"))
        ]
        headers.append(["signature-input", dumps_dict(inputs)])
        headers.append(["signature", dumps_dict(sigs)])
        output["headers"] = headers

    report: dict[str, Any] = {
        "decision": "reject" if codes.codes else "ok",
        "reason_codes": codes.codes,
        "labels": [label],
        "bases": {label: base} if base is not None else {},
    }
    return output, report
