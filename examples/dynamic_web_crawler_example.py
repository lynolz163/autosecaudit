"""Example usage of DynamicWebCrawler."""

from __future__ import annotations

from autosecaudit.crawlers import DynamicWebCrawler


def main() -> None:
    """
    Run a dynamic crawl in strict in-scope mode.

    Requirements:
    - `pip install playwright`
    - `playwright install`
    """
    crawler = DynamicWebCrawler(
        allowed_domains=["example.com"],
        headless=True,
        max_pages=50,
        request_timeout_ms=12000,
    )

    result = crawler.crawl(start_url="https://example.com", max_depth=2)
    print(crawler.to_json(result))


if __name__ == "__main__":
    main()
