"""Verify deployed Pages content and commit identity; never equate HTTP 200 with readiness."""
import json
import os
import re
import urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright

ARTIFACTS = Path(__file__).resolve().parent / "browser-artifacts"
BASE_URL = os.environ.get(
    "TRUSTGUARD_PAGES_BASE_URL",
    "https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2",
).rstrip("/")
EXPECTED_SHA = os.environ.get("TRUSTGUARD_EXPECTED_COMMIT_SHA", os.environ.get("GITHUB_SHA", "")).strip()
PAGES = ("dashboard.html", "dashboard_v2.html")
FORBIDDEN_MARKERS = (
    "100%",
    "Bukti Transaksi End-to-End (PayPal Sandbox)",
    "7R3064957MB0759941",
    "3HD92730V0626752B",
    "1U9063377E719994A",
    'class="status-ok">SUCCESS',
    'class="status-ok">SUKSES',
)

def probe_page(browser, filename):
    url = f"{BASE_URL}/{filename}"
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    console_errors, page_errors, network_errors = [], [], []
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: page_errors.append(str(e)))
    page.on("requestfailed", lambda r: network_errors.append(f"{r.method} {r.url}: {r.failure}"))
    page.on("response", lambda r: network_errors.append(f"HTTP {r.status}: {r.url}") if r.status >= 400 else None)
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=20000)
        status = response.status if response else 0
        page.wait_for_timeout(250)
        body = page.locator("body").inner_text(timeout=5000) if page.locator("body").count() else ""
        meta_sha = page.locator('meta[name="trustguard-build-commit"]').get_attribute("content") if page.locator('meta[name="trustguard-build-commit"]').count() else ""
        visible_sha = page.locator("#build-commit").inner_text(timeout=2000) if page.locator("#build-commit").count() else ""
        failures = []
        if status != 200: failures.append(f"HTTP_{status}")
        if not re.fullmatch(r"[0-9a-f]{40}", meta_sha or ""): failures.append("MISSING_OR_INVALID_BUILD_SHA")
        if visible_sha != meta_sha: failures.append("VISIBLE_META_VERSION_MISMATCH")
        if EXPECTED_SHA and meta_sha != EXPECTED_SHA: failures.append("UNEXPECTED_COMMIT_SHA")
        for marker in FORBIDDEN_MARKERS:
            if marker.lower() in body.lower(): failures.append("FORBIDDEN_CONTENT:" + marker)
        if "UNVERIFIED" not in body and "BELUM DIVERIFIKASI" not in body and "BELUM TERHUBUNG" not in body:
            failures.append("MISSING_UNVERIFIED_OR_UNKNOWN_STATE")
        if console_errors: failures.append("CONSOLE_ERRORS")
        if page_errors: failures.append("PAGE_ERRORS")
        if network_errors: failures.append("NETWORK_ERRORS")
        verdict = "DEPLOYMENT_VERIFIED" if not failures else "DEPLOYMENT_NOT_VERIFIED"
        print(f"LIVE_PROBE file={filename} http={status} meta_sha={meta_sha or 'MISSING'} visible_sha={visible_sha or 'MISSING'} expected_sha={EXPECTED_SHA or 'NOT_SET'} verdict={verdict} failures={';'.join(failures) or 'none'}")
        ARTIFACTS.mkdir(exist_ok=True)
        if status == 200:
            page.screenshot(path=str(ARTIFACTS / f"live-{filename.replace('.', '-')}.png"), full_page=True)
        for item in console_errors[:5]: print(f"LIVE_PROBE_CONSOLE_ERROR file={filename} detail={item}")
        for item in page_errors[:5]: print(f"LIVE_PROBE_PAGE_ERROR file={filename} detail={item}")
        for item in network_errors[:5]: print(f"LIVE_PROBE_NETWORK_ERROR file={filename} detail={item}")
        return {"file": filename, "sha": meta_sha, "failures": failures, "verdict": verdict}
    except Exception as exc:
        print(f"LIVE_PROBE file={filename} verdict=DEPLOYMENT_NOT_VERIFIED error={type(exc).__name__}: {exc}")
        return {"file": filename, "sha": "", "failures": [type(exc).__name__], "verdict": "DEPLOYMENT_NOT_VERIFIED"}
    finally:
        page.close()

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            results = [probe_page(browser, filename) for filename in PAGES]
        finally:
            browser.close()
    shas = {r["sha"] for r in results}
    consistent = len(shas) == 1 and "" not in shas
    print(f"LIVE_PROBE pair_consistent={consistent} expected_sha={EXPECTED_SHA or 'NOT_SET'}")
    if not consistent:
        print("LIVE_PROBE verdict=DEPLOYMENT_NOT_VERIFIED failures=DASHBOARD_VERSION_MISMATCH")
    try:
        request = urllib.request.Request(
            f"{BASE_URL}/build-info.json",
            headers={"Cache-Control": "no-cache", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            manifest = json.loads(response.read().decode("utf-8"))
        manifest_sha = manifest.get("frontend_commit", "")
        manifest_ok = bool(re.fullmatch(r"[0-9a-f]{40}", manifest_sha))
        if EXPECTED_SHA:
            manifest_ok = manifest_ok and manifest_sha == EXPECTED_SHA
        print(f"LIVE_PROBE manifest_sha={manifest_sha or 'MISSING'} expected_sha={EXPECTED_SHA or 'NOT_SET'} verdict={'MANIFEST_VERIFIED' if manifest_ok else 'MANIFEST_NOT_VERIFIED'}")
    except Exception as exc:
        manifest_ok = False
        print(f"LIVE_PROBE manifest_sha=MISSING verdict=MANIFEST_NOT_VERIFIED error={type(exc).__name__}: {exc}")
    # Intentionally informational in the security-test workflow. The production
    # deployment workflow has its own strict pre-deploy and post-deploy checks.
    if os.environ.get("TRUSTGUARD_PROBE_STRICT") == "1":
        failed = any(r["failures"] for r in results) or not consistent or not manifest_ok
        if failed:
            raise SystemExit("DEPLOYMENT_NOT_VERIFIED")

if __name__ == "__main__":
    main()
