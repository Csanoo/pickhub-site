#!/usr/bin/env python3
"""배포 전 정적 보안 점검.

저장소의 HTML/JS와 vercel.json을 검사해 문제가 있으면 exit 1로 끝난다.
GitHub Actions의 security 워크플로에서 실행되며, 로컬에서도
`python3 scripts/security_check.py`로 돌릴 수 있다. 외부 패키지 불필요.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []
warnings: list[str] = []


def err(path: Path | str, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def warn(path: Path | str, msg: str) -> None:
    warnings.append(f"{path}: {msg}")


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
        return [ROOT / p for p in out.splitlines() if p]
    except Exception:
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


# 1. 올라가면 안 되는 파일 -------------------------------------------------
SENSITIVE = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_rsa.*|id_ed25519.*|"
    r"credentials(\.json)?|.*\.sqlite3?|.*\.bak|.*\.zip)$",
    re.I,
)

# 2. HTML 검사 ---------------------------------------------------------------
class HtmlCheck(HTMLParser):
    def __init__(self, path: Path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.in_inline_script = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        line = self.getpos()[0]
        where = f"{self.path.relative_to(ROOT)}:{line}"

        for k, v in a.items():
            if k.startswith("on"):
                err(where, f"인라인 이벤트 핸들러 `{k}` — CSP(script-src 'self')에서 차단됨, JS 파일로 옮길 것")
            if k in ("href", "src", "action", "formaction") and v.strip().lower().startswith("javascript:"):
                err(where, f"`{k}`에 javascript: URL 사용")

        if tag == "script":
            if "src" not in a:
                self.in_inline_script = True
            else:
                self._check_external(where, tag, a["src"], a)
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower():
            self._check_external(where, tag, a.get("href", ""), a)
        elif tag in ("img", "iframe", "source", "audio", "video", "embed"):
            src = a.get("src", "")
            if src.lower().startswith("http://"):
                err(where, f"<{tag}>가 http:// 리소스를 불러옴 (mixed content): {src}")
            if tag in ("iframe", "embed"):
                warn(where, f"<{tag}> 사용 — CSP frame-src/object-src 허용 여부 확인 필요")

        if tag == "a" and a.get("target", "").lower() == "_blank":
            rel = a.get("rel", "").lower()
            if "noopener" not in rel and "noreferrer" not in rel:
                err(where, "target=_blank 링크에 rel=\"noopener noreferrer\" 없음")

        if tag == "form":
            action = a.get("action", "")
            if action.lower().startswith("http://"):
                err(where, f"폼이 http://로 전송됨: {action}")

    def handle_data(self, data):
        if self.in_inline_script and data.strip():
            err(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}",
                "인라인 <script> — CSP(script-src 'self')에서 차단됨, js/ 폴더 파일로 옮길 것",
            )

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_inline_script = False

    def _check_external(self, where, tag, url, a):
        u = url.strip().lower()
        if u.startswith("http://"):
            err(where, f"<{tag}>가 http:// 리소스를 불러옴: {url}")
        elif u.startswith(("https://", "//")):
            if "integrity" not in a:
                err(where, f"외부 <{tag}>에 SRI(integrity) 없음: {url}")
            warn(where, f"외부 도메인 리소스 사용 — vercel.json CSP에 도메인 추가 필요: {url}")


# 3. JS 위험 패턴 ------------------------------------------------------------
JS_DANGER = [
    (re.compile(r"\beval\s*\("), "eval() 사용"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function() 사용"),
    (re.compile(r"\.(innerHTML|outerHTML)\s*\+?="), "innerHTML/outerHTML 대입 — textContent 사용 권장(XSS)"),
    (re.compile(r"\binsertAdjacentHTML\s*\("), "insertAdjacentHTML() 사용(XSS)"),
    (re.compile(r"\bdocument\.write(ln)?\s*\("), "document.write() 사용"),
    (re.compile(r"\bset(Timeout|Interval)\s*\(\s*['\"`]"), "문자열을 setTimeout/setInterval에 전달"),
]


def check_js(path: Path) -> None:
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for pat, msg in JS_DANGER:
            if pat.search(line):
                err(f"{path.relative_to(ROOT)}:{i}", msg)


# 4. vercel.json 보안 헤더 ---------------------------------------------------
REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def check_vercel() -> None:
    p = ROOT / "vercel.json"
    if not p.exists():
        err("vercel.json", "없음 — 보안 헤더가 설정되지 않음")
        return
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err("vercel.json", f"JSON 문법 오류: {e}")
        return
    global_headers: dict[str, str] = {}
    for rule in cfg.get("headers", []):
        if rule.get("source") in ("/(.*)", "/:path*", "/(.*)?"):
            for h in rule.get("headers", []):
                global_headers[h["key"].lower()] = h["value"]
    for h in REQUIRED_HEADERS:
        if h not in global_headers:
            err("vercel.json", f"전체 경로(/(.*))에 `{h}` 헤더 없음")
    csp = global_headers.get("content-security-policy", "")
    directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";") if d.strip()}
    script = directives.get("script-src", directives.get("default-src", ""))
    if "'unsafe-inline'" in script or "'unsafe-eval'" in script:
        err("vercel.json", "CSP script-src에 'unsafe-inline' 또는 'unsafe-eval' 포함")
    for d in ("object-src", "base-uri", "frame-ancestors"):
        if d not in directives:
            err("vercel.json", f"CSP에 `{d}` 지시어 없음")
    if "max-age=" in global_headers.get("strict-transport-security", ""):
        age = int(re.search(r"max-age=(\d+)", global_headers["strict-transport-security"]).group(1))
        if age < 15552000:
            warn("vercel.json", "HSTS max-age가 180일 미만")


def main() -> int:
    files = tracked_files()
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if SENSITIVE.search(rel):
            err(rel, "민감 파일로 보이는 파일이 저장소에 포함됨")
        if f.suffix.lower() in (".html", ".htm") and f.exists():
            HtmlCheck(f).feed(f.read_text(encoding="utf-8", errors="replace"))
        elif f.suffix.lower() in (".js", ".mjs") and f.exists():
            check_js(f)
    check_vercel()

    for w in warnings:
        print(f"::warning::{w}")
    for e in errors:
        print(f"::error::{e}")
    print(f"\n보안 점검: 오류 {len(errors)}건, 경고 {len(warnings)}건")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
