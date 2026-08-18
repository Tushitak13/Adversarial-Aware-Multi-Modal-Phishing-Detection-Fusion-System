# Shared Contracts

This document defines the input/output formats that all modules
in the phishing detection fusion system must follow.

---

## 1. Detector Output

All four detectors must return the same structure.

```json
{
  "detector_name": "visual | semantic | url | behavior",
  "score": 0.0,
  "confidence": 0.0,
  "raw_features": {},
  "latency_ms": 0
}

{
  "pairwise_disagreement": {
    "visual_vs_semantic": 0.0,
    "visual_vs_url": 0.0,
    "visual_vs_behavior": 0.0,
    "semantic_vs_url": 0.0,
    "semantic_vs_behavior": 0.0,
    "url_vs_behavior": 0.0
  },
  "score_variance": 0.0,
  "max_disagreement_pair": [
    "visual",
    "semantic"
  ]
}

{
  "visual": {
    "reliability_score": 0.0,
    "recent_accuracy": 0.0,
    "sample_size": 0
  },
  "semantic": {
    "reliability_score": 0.0,
    "recent_accuracy": 0.0,
    "sample_size": 0
  },
  "url": {
    "reliability_score": 0.0,
    "recent_accuracy": 0.0,
    "sample_size": 0
  },
  "behavior": {
    "reliability_score": 0.0,
    "recent_accuracy": 0.0,
    "sample_size": 0
  }
}

{
  "visual": {
    "attack_likelihood": 0.0,
    "reasoning_flags": []
  },
  "semantic": {
    "attack_likelihood": 0.0,
    "reasoning_flags": []
  },
  "url": {
    "attack_likelihood": 0.0,
    "reasoning_flags": []
  },
  "behavior": {
    "attack_likelihood": 0.0,
    "reasoning_flags": []
  }
}

{
  "visual": 0.0,
  "semantic": 0.0,
  "url": 0.0,
  "behavior": 0.0
}

{
  "final_score": 0.0,
  "final_confidence": 0.0,
  "weights_used": {
    "visual": 0.0,
    "semantic": 0.0,
    "url": 0.0,
    "behavior": 0.0
  }
}

{
  "final_decision": "phishing | safe",
  "final_score": 0.0,
  "final_confidence": 0.0,
  "rationale": "human readable string"
}