import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detectors.semantic_detector import analyze_semantic

PHISHING = "URGENT: Your account will be suspended in 24 hours. Click here and enter your password to avoid closure."
BENIGN = "Hi team, here's this week's product update. We shipped the new dashboard."


def test_contract_shape():
    result = analyze_semantic(PHISHING, use_cache=False)
    assert set(result.keys()) == {"detector_name", "score", "confidence", "raw_features", "latency_ms"}
    assert result["detector_name"] == "semantic"


def test_phishing_scores_higher_than_benign():
    phishing_score = analyze_semantic(PHISHING)["score"]
    benign_score = analyze_semantic(BENIGN)["score"]
    print(f"\nphishing={phishing_score}, benign={benign_score}")
    assert phishing_score > benign_score