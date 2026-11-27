#!/usr/bin/env python3
"""배포된 사이트의 보안 헤더와 노출 경로 점검.

사용: python3 scripts/check_live_headers.py https://pickhub.site [--wait 300]
--wait 초 동안 헤더가 반영될 때까지 재시도한다(배포 직후 반영 지연 대비).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 배포되면 안 되는 경로 (404 여야 함)
MUST_NOT_EXIST = ["/.git/config", "/.github/workflows/security.yml", "/scripts/security_check.py", "/.env"]


def expected_headers() -> dict[str, str]:
    cfg = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    out = {}
    for rule in cfg.get("headers", []):
        if rule.get("source") == "/(.*)":
            for h in rule["headers"]:
                out[h["key"].lower()] = h["value"]
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url: str, follow: bool = True):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "pickhub-security-check"})
    try:
        r = opener.open(req, timeout=20)
        return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}


def check(base: str) -> list[str]:
    problems = []
    want = expected_headers()
    for path in ("/", "/en/index.html"):
        status, got = fetch(base + path)
        if status != 200:
            problems.append(f"{path}: HTTP {status}")
            continue
        for k, v in want.items():
            if k not in got:
                problems.append(f"{path}: `{k}` 헤더 없음")
            elif got[k].strip() != v.strip():
                problems.append(f"{path}: `{k}` 값이 vercel.json과 다름 → {got[k]}")
    for path in MUST_NOT_EXIST:
        status, _ = fetch(base + path)
        if status != 404:
            problems.append(f"{path}: 공개되어 있음 (HTTP {status}, 404 여야 함)")
    if base.startswith("https://"):
        status, got = fetch("http://" + base[len("https://"):] + "/", follow=False)
        if status not in (301, 302, 307, 308) or not got.get("location", "").startswith("https://"):
            problems.append(f"http → https 리다이렉트 안 됨 (HTTP {status})")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--wait", type=int, default=0)
    args = ap.parse_args()
    base = args.url.rstrip("/")
    deadline = time.time() + args.wait
    while True:
        problems = check(base)
        if not problems or time.time() >= deadline:
            break
        print(f"미반영 {len(problems)}건, 30초 후 재시도…")
        time.sleep(30)
    for p in problems:
        print(f"::error::{base}{p if p.startswith('/') else ' ' + p}")
    print(f"\n배포 사이트 점검({base}): 문제 {len(problems)}건")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
