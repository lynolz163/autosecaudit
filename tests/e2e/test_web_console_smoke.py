from __future__ import annotations

import pytest


pytestmark = pytest.mark.e2e
playwright = pytest.importorskip("playwright.sync_api")


def test_web_console_login_and_jobs_navigation(e2e_server_url: str) -> None:
    try:
        with playwright.sync_playwright() as session:
            browser = session.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(e2e_server_url, wait_until="domcontentloaded")
            page.locator("input[name='username']").fill("admin")
            page.locator("input[name='password']").fill("AdminPass1234!")
            page.locator("button[type='submit']").click()

            page.wait_for_url("**/dashboard")
            page.locator("aside.sidebar nav button").nth(1).click()
            page.wait_for_url("**/jobs")
            page.locator("main").wait_for()

            assert "/jobs" in page.url
            browser.close()
    except Exception as exc:  # noqa: BLE001
        if "Executable doesn't exist" in str(exc) or "Please run the following command" in str(exc):
            pytest.skip("Playwright browser runtime is not installed")
        raise
