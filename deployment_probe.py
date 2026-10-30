"""Informational probe of the currently published GitHub Pages site.

This is intentionally non-blocking: a missing or stale deployment must be reported,
not confused with a local browser test failure or a successful deployment.
"""
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ARTIFACTS = Path(__file__).resolve().parent / "browser-artifacts"
BASE_URL = os.environ.get(
    "TRUSTGUARD_PAGES_BASE_URL",
    "https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2",
).rstrip("/")


def probe_page(browser, filename):
    url = f"{BASE_URL}/{filename}"
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    console_errors = []
    page_errors = []
    network_errors = []
    page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    page.on("requestfailed", lambda request: network_errors.append(f"{request.method} {request.url}: {request.failure}"))
    page.on("response", lambda response: network_errors.append(f"HTTP {response.status}: {response.url}") if response.status >= 400 else None)

    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=20000)
        status = response.status if response else "NO_HTTP_RESPONSE"
        if filename == "dashboard_v2.html":
            try:
                page.wait_for_function(
                    "() => { const n = document.querySelector('#source-notice'); return n && !n.textContent.startsWith('Memuat data.'); }",
                    timeout=5000,
                )
            except Exception:
                pass
        body = page.locator("body").inner_text(timeout=5000) if page.locator("body").count() else ""
        title = page.title()
        has_unverified_notice = (
            "belum terhubung ke telemetry backend" in body.lower()
            if filename == "dashboard.html"
            else "file json statis berstatus unverified" in body.lower()
        )
        has_unsupported_100 = "100%" in body
        has_success_claim = "SUCCESS" in body.upper() or "SUCCEEDED" in body.upper()
        has_active_claim = "AKTIF" in body.upper()
        has_end_to_end_claim = "END-TO-END" in body.upper() or "LIVE E2E RUN" in body.upper()
        if status == 200 and has_unverified_notice and not has_unsupported_100 and not has_success_claim and not has_active_claim and not has_end_to_end_claim:
            verdict = "HTTP_200_EXPECTED_UNVERIFIED_NOTICE_PRESENT"
        elif status == 200:
            verdict = "HTTP_200_BUT_STALE_OR_UNEXPECTED_CONTENT"
        else:
            verdict = "DEPLOYMENT_NOT_VERIFIED"
        print(
            f"LIVE_PROBE file={filename} url={url} http_status={status} verdict={verdict} "
            f"title={title!r} unsupported_100={has_unsupported_100} success_claim={has_success_claim} "
            f"active_claim={has_active_claim} end_to_end_claim={has_end_to_end_claim} "
            f"console_errors={len(console_errors)} page_errors={len(page_errors)} network_errors={len(network_errors)}"
        )
        if response and status == 200:
            page.screenshot(path=str(ARTIFACTS / f"live-{filename.replace('.html', '')}-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(ARTIFACTS / f"live-{filename.replace('.html', '')}-mobile.png"), full_page=True)
        for item in console_errors[:5]:
            print(f"LIVE_PROBE_CONSOLE_ERROR file={filename} detail={item}")
        for item in page_errors[:5]:
            print(f"LIVE_PROBE_PAGE_ERROR file={filename} detail={item}")
        for item in network_errors[:5]:
            print(f"LIVE_PROBE_NETWORK_ERROR file={filename} detail={item}")
    except Exception as exc:
        print(f"LIVE_PROBE file={filename} url={url} verdict=DEPLOYMENT_NOT_VERIFIED error={type(exc).__name__}: {exc}")
    finally:
        page.close()


def main():
    ARTIFACTS.mkdir(exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            probe_page(browser, "dashboard.html")
            probe_page(browser, "dashboard_v2.html")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
