"""
Semantic Detector (Phase 1)
---------------------------
Owner: Person 2
Backend: Groq (llama-3.3-70b-versatile) - free tier, no card, OpenAI-compatible.

Contract (must match exactly for downstream stages):
{
    "detector_name": "semantic",
    "score": 0.0,          # 0 = benign, 1 = phishing
    "confidence": 0.0,     # model's self-reported confidence 0-1
    "raw_features": {},    # signals dict, see below
    "latency_ms": 0
}

Design notes:
- Groq's free tier doesn't support a strict response_schema like Gemini does,
  so JSON reliability comes from: (1) response_format={"type":"json_object"}
  forcing valid JSON syntax, (2) the schema spelled out explicitly in the
  system prompt, (3) a defensive parser that never trusts the shape blindly.
- Falls back to score=0.5, confidence=0.0 on any failure (timeout, bad
  JSON, rate limit, API error) so one flaky call never crashes the pipeline.
- Caches by sha256(text) in a local SQLite file so repeated eval runs
  don't burn free-tier quota (30 RPM / ~1000 RPD on Llama 3.3 70B).
"""

import os
import time
import json
import sqlite3
import hashlib
from pathlib import Path

from groq import Groq
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GROQ_API_KEY")
MODEL_NAME = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

CACHE_PATH = Path(__file__).resolve().parent.parent / "cache" / "semantic_cache.db"
CACHE_PATH.parent.mkdir(exist_ok=True)

MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2  # doubles each retry: 2, 4, 8 - also absorbs 429s

FALLBACK_OUTPUT = {
    "detector_name": "semantic",
    "score": 0.5,
    "confidence": 0.0,
    "raw_features": {"error": "fallback_triggered"},
    "latency_ms": 0,
}

SYSTEM_PROMPT = """You are a phishing-language analyst. You will be given the visible text
content of a web page or message. Judge ONLY the language/wording itself — not URLs, not visual
layout, not sender metadata (other detectors in the pipeline handle those).

Score how strongly the language pattern matches phishing:
- urgency: artificial time pressure ("act now", "24 hours", "immediately")
- credential_request: asks for password, OTP, card number, login, PII
- pressure_tactics: threats, fear appeals ("account suspended", "legal action")
- brand_impersonation_tone: impersonates a known brand/authority's voice without necessarily naming a URL

Be honest about ambiguity — a low-urgency, natural-sounding message that still buries a credential
request should still flag credential_request=true even if phishing_language_score is moderate, not high.

Respond with ONLY a single JSON object, no other text, matching exactly this shape:
{
  "phishing_language_score": <float 0.0-1.0>,
  "confidence": <float 0.0-1.0>,
  "signals": {
    "urgency": <bool>,
    "credential_request": <bool>,
    "pressure_tactics": <bool>,
    "brand_impersonation_tone": <bool>
  },
  "specific_flags": [<short strings naming the exact phrases that triggered signals>]
}"""


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _init_cache():
    conn = sqlite3.connect(CACHE_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS semantic_cache (
            text_hash TEXT PRIMARY KEY,
            result_json TEXT NOT NULL
        )"""
    )
    conn.commit()
    return conn


def _get_cached(conn, key: str):
    row = conn.execute(
        "SELECT result_json FROM semantic_cache WHERE text_hash = ?", (key,)
    ).fetchone()
    return json.loads(row[0]) if row else None


def _set_cached(conn, key: str, result: dict):
    conn.execute(
        "INSERT OR REPLACE INTO semantic_cache (text_hash, result_json) VALUES (?, ?)",
        (key, json.dumps(result)),
    )
    conn.commit()


def _call_groq(client: Groq, page_text: str) -> dict:
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": page_text},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,  # low temp: consistent scoring, not creativity
    )
    return json.loads(response.choices[0].message.content)


def _validate_raw(raw: dict) -> dict:
    """Defensive parse - Groq's json_object mode guarantees valid JSON syntax,
    NOT that the model filled in every field correctly. Never trust blindly."""
    signals = raw.get("signals", {})
    return {
        "phishing_language_score": float(raw["phishing_language_score"]),
        "confidence": float(raw["confidence"]),
        "signals": {
            "urgency": bool(signals.get("urgency", False)),
            "credential_request": bool(signals.get("credential_request", False)),
            "pressure_tactics": bool(signals.get("pressure_tactics", False)),
            "brand_impersonation_tone": bool(signals.get("brand_impersonation_tone", False)),
        },
        "specific_flags": raw.get("specific_flags", []) or [],
    }


def analyze_semantic(page_text: str, use_cache: bool = True) -> dict:
    """
    Contract-matching entry point for the pipeline.
    Returns the exact detector output shape every stage expects.
    """
    start = time.time()

    if not page_text or not page_text.strip():
        return {**FALLBACK_OUTPUT, "raw_features": {"error": "empty_input"}}

    conn = _init_cache() if use_cache else None
    key = _cache_key(page_text)

    if conn:
        cached = _get_cached(conn, key)
        if cached is not None:
            conn.close()
            return cached

    if not API_KEY:
        result = {**FALLBACK_OUTPUT, "raw_features": {"error": "missing_api_key"}}
        if conn:
            conn.close()
        return result

    client = Groq(api_key=API_KEY)

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            raw = _call_groq(client, page_text)
            validated = _validate_raw(raw)

            result = {
                "detector_name": "semantic",
                "score": validated["phishing_language_score"],
                "confidence": validated["confidence"],
                "raw_features": {
                    "signals": validated["signals"],
                    "specific_flags": validated["specific_flags"],
                },
                "latency_ms": int((time.time() - start) * 1000),
            }

            if conn:
                _set_cached(conn, key, result)
                conn.close()
            return result

        except Exception as e:  # noqa: BLE001 - any failure -> retry/fallback, never crash pipeline
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_BACKOFF_SECONDS * (2 ** attempt))

    # All retries exhausted -> safe fallback
    result = {
        **FALLBACK_OUTPUT,
        "raw_features": {"error": f"api_failure: {last_error}"},
        "latency_ms": int((time.time() - start) * 1000),
    }
    if conn:
        conn.close()
    return result


if __name__ == "__main__":
    sample = (
        "Dear customer, your account has been temporarily suspended due to unusual activity. "
        "Click here within 24 hours and verify your password to restore access, or your account "
        "will be permanently deleted."
    )
    print(json.dumps(analyze_semantic(sample), indent=2))
