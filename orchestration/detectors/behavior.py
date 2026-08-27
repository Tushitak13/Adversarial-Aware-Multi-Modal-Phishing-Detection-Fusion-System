import time
from playwright.sync_api import sync_playwright


def analyze_behavior(url: str) -> dict:
    """
    Opens the given URL in a headless browser and checks for suspicious
    behavior signals. Returns output matching the detector contract:
    {"detector_name": str, "score": 0.0, "confidence": 0.0,
     "raw_features": {}, "latency_ms": 0}

    Signals checked:
      1. Redirected to a different URL than requested
      2. Navigated again on its own after load (e.g. auto-submitted form)
      3. Opened a popup/new window without any user interaction
    """
    start_time = time.time()

    suspicious_signals = []
    page_loaded_cleanly = True
    final_url = None
    popup_count = 0

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # Track navigations that happen on their own
            navigation_count = {"count": 0}

            def on_frame_navigated(frame):
                if frame == page.main_frame:
                    navigation_count["count"] += 1

            page.on("framenavigated", on_frame_navigated)

            # Track popups/new windows the page tries to open
            popups = []

            def on_popup(popup_page):
                popups.append(popup_page)

            page.on("popup", on_popup)

            try:
                page.goto(url, timeout=10000)
                final_url = page.url

                # Signal 1: redirect
                if final_url != url and final_url.rstrip("/") != url.rstrip("/"):
                    suspicious_signals.append("redirected")

                # Wait without touching anything, to catch delayed
                # behavior (auto-submit forms, delayed popups, etc.)
                nav_count_before_wait = navigation_count["count"]
                page.wait_for_timeout(2000)
                nav_count_after_wait = navigation_count["count"]

                # Signal 2: auto-navigation with no interaction from us
                if nav_count_after_wait > nav_count_before_wait:
                    suspicious_signals.append("auto_navigation_without_interaction")

                # Signal 3: unsolicited popups
                popup_count = len(popups)
                if popup_count > 0:
                    suspicious_signals.append("unsolicited_popup")
                    for popup_page in popups:
                        try:
                            popup_page.close()
                        except Exception:
                            pass

            except Exception:
                # page failed to load, blocked headless browser, timed out
                page_loaded_cleanly = False
                final_url = None

            browser.close()

    except Exception:
        # Playwright itself failed to launch/run - fail gracefully,
        # never crash the whole pipeline because of one detector
        page_loaded_cleanly = False
        final_url = None

    latency_ms = round((time.time() - start_time) * 1000)

    # Scoring: more suspicious signals = higher score, capped at 1.0
    score = min(len(suspicious_signals) * 0.35, 1.0)

    # Confidence: low if the page didn't load cleanly - we genuinely
    # don't know much about a page we couldn't observe properly
    confidence = 0.85 if page_loaded_cleanly else 0.3

    return {
        "detector_name": "behavior",
        "score": round(score, 3),
        "confidence": confidence,
        "raw_features": {
            "suspicious_signals": suspicious_signals,
            "page_loaded_cleanly": page_loaded_cleanly,
            "final_url": final_url,
            "popup_count": popup_count,
        },
        "latency_ms": latency_ms
    }


if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "https://google.com",
        "https://this-domain-does-not-exist-xyz123.com",  # tests graceful failure
        "https://wikipedia.org",
        "https://github.com",
    ]

    for url in test_urls:
        print(f"\n--- Testing: {url} ---")
        result = analyze_behavior(url)
        print(result)