import time
from playwright.sync_api import sync_playwright


def analyze_behavior(url: str) -> dict:
    """
    Opens the given URL in a headless browser and checks for suspicious
    behavior signals. Returns output matching the detector contract:
    {"detector_name": str, "score": 0.0, "confidence": 0.0,
     "raw_features": {}, "latency_ms": 0}
    """
    start_time = time.time()

    suspicious_signals = []
    page_loaded_cleanly = True
    final_url = None
    form_submitted_automatically = False

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Track if a form submission / navigation happens on its own
        navigation_count = {"count": 0}

        def on_frame_navigated(frame):
            if frame == page.main_frame:
                navigation_count["count"] += 1

        page.on("framenavigated", on_frame_navigated)

        try:
            page.goto(url, timeout=10000)
            final_url = page.url

            # Signal 1: did the URL change after loading? (redirect)
            if final_url != url and final_url.rstrip("/") != url.rstrip("/"):
                suspicious_signals.append("redirected")

            # Signal 2: does the page navigate again on its own, without
            # any click or interaction from us? (e.g. auto-submitting form)
            nav_count_before_wait = navigation_count["count"]
            page.wait_for_timeout(2000)
            nav_count_after_wait = navigation_count["count"]

            if nav_count_after_wait > nav_count_before_wait:
                form_submitted_automatically = True
                suspicious_signals.append("auto_navigation_without_interaction")

        except Exception as e:
            # page failed to load, blocked headless browser, timed out, etc.
            page_loaded_cleanly = False
            final_url = None

        browser.close()

    latency_ms = round((time.time() - start_time) * 1000)

    # Scoring: more suspicious signals = higher score
    score = min(len(suspicious_signals) * 0.4, 1.0)

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
            "form_submitted_automatically": form_submitted_automatically,
        },
        "latency_ms": latency_ms
    }


if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "https://google.com",
    ]

    for url in test_urls:
        print(f"\n--- Testing: {url} ---")
        result = analyze_behavior(url)
        print(result)
