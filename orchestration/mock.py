def generate_mock_detector_output(detector_name, scenario="all_agree_safe"):
    """Generate fake detector output matching the contract shape."""

    if scenario == "all_agree_safe":
        return {
            "detector_name": detector_name,
            "score": 0.1,
            "confidence": 0.9,
            "raw_features": {},
            "latency_ms": 50
        }
    elif scenario == "all_agree_phishing":
        return {
            "detector_name": detector_name,
            "score": 0.9,
            "confidence": 0.9,
            "raw_features": {},
            "latency_ms": 50
        }
    elif scenario == "genuine_disagreement":
        return {
            "detector_name": detector_name,
            "score": 0.5,
            "confidence": 0.7,
            "raw_features": {},
            "latency_ms": 50
        }
    elif scenario == "adversarial_pattern":
        return {
            "detector_name": detector_name,
            "score": 0.2,
            "confidence": 0.85,
            "raw_features": {},
            "latency_ms": 50
        }
    elif scenario == "low_confidence_everywhere":
        return {
            "detector_name": detector_name,
            "score": 0.5,
            "confidence": 0.3,
            "raw_features": {},
            "latency_ms": 200
        }
    else:
        raise ValueError(f"Unknown scenario: {scenario}")


def generate_all_detector_outputs(scenario="all_agree_safe"):
    """Generate outputs for all 4 detectors at once for a given scenario."""

    detectors = ["visual", "semantic", "url", "behavior"]

    if scenario == "genuine_disagreement":
        scores = {"visual": 0.2, "semantic": 0.8, "url": 0.3, "behavior": 0.7}
        confidences = {"visual": 0.8, "semantic": 0.8, "url": 0.75, "behavior": 0.75}
        outputs = {}
        for d in detectors:
            outputs[d] = {
                "detector_name": d,
                "score": scores[d],
                "confidence": confidences[d],
                "raw_features": {},
                "latency_ms": 50
            }
        return outputs

    elif scenario == "adversarial_pattern":
        scores = {"visual": 0.85, "semantic": 0.1, "url": 0.8, "behavior": 0.75}
        confidences = {"visual": 0.8, "semantic": 0.9, "url": 0.8, "behavior": 0.7}
        outputs = {}
        for d in detectors:
            outputs[d] = {
                "detector_name": d,
                "score": scores[d],
                "confidence": confidences[d],
                "raw_features": {},
                "latency_ms": 50
            }
        return outputs

    else:
        outputs = {}
        for d in detectors:
            outputs[d] = generate_mock_detector_output(d, scenario)
        return outputs


def generate_mock_stage1_disagreement(detector_outputs):
    """
    Stage 1 - Disagreement Matrix.
    Takes the dict from generate_all_detector_outputs() and produces
    pairwise disagreement between every pair of detectors.
    """
    scores = {name: output["score"] for name, output in detector_outputs.items()}

    detector_names = list(scores.keys())
    pairwise_disagreement = {}
    for i in range(len(detector_names)):
        for j in range(i + 1, len(detector_names)):
            name_a = detector_names[i]
            name_b = detector_names[j]
            diff = abs(scores[name_a] - scores[name_b])
            pair_key = f"{name_a}_vs_{name_b}"
            pairwise_disagreement[pair_key] = round(diff, 3)

    max_pair_key = max(pairwise_disagreement, key=pairwise_disagreement.get)
    max_pair_names = max_pair_key.split("_vs_")

    score_values = list(scores.values())
    mean_score = sum(score_values) / len(score_values)
    variance = sum((s - mean_score) ** 2 for s in score_values) / len(score_values)

    return {
        "pairwise_disagreement": pairwise_disagreement,
        "score_variance": round(variance, 4),
        "max_disagreement_pair": max_pair_names
    }


def generate_mock_stage2_reliability(detector_outputs, scenario="all_agree_safe"):
    """
    Stage 2 - Reliability Memory.
    Fakes each detector's historical reliability score (as if looked up
    from a log of past predictions).
    """
    detector_names = list(detector_outputs.keys())

    base_reliability = {
        "visual": 0.75,
        "semantic": 0.80,
        "url": 0.85,
        "behavior": 0.70
    }

    reliability_output = {}
    for name in detector_names:
        rel_score = base_reliability.get(name, 0.75)

        # Simulate memory picking up on semantic being unreliable lately
        if scenario == "adversarial_pattern" and name == "semantic":
            rel_score = 0.55

        reliability_output[name] = {
            "reliability_score": rel_score,
            "recent_accuracy": rel_score,
            "sample_count": 50
        }

    return reliability_output


def generate_mock_stage3_adversarial(detector_outputs, reliability_output, scenario="all_agree_safe"):
    """
    Stage 3 - Adversarial Attack Estimator.
    Estimates how likely it is each detector is being actively fooled
    (e.g. adversarial perturbation, evasion tricks), per detector.
    """
    detector_names = list(detector_outputs.keys())

    attack_output = {}
    for name in detector_names:
        attack_likelihood = 0.1
        reasoning_flags = []

        # Flag detectors that are confidently wrong in the adversarial scenario
        if scenario == "adversarial_pattern" and name == "semantic":
            attack_likelihood = 0.8
            reasoning_flags = [
                "high_confidence_outlier",
                "disagrees_with_majority",
                "low_recent_reliability"
            ]
        elif scenario == "genuine_disagreement":
            attack_likelihood = 0.3
            reasoning_flags = ["moderate_disagreement_with_peers"]
        elif scenario == "low_confidence_everywhere":
            attack_likelihood = 0.2
            reasoning_flags = ["low_confidence_signal"]

        attack_output[name] = {
            "attack_likelihood": attack_likelihood,
            "reasoning_flags": reasoning_flags
        }

    return attack_output


def generate_mock_stage4_trust(detector_outputs, reliability_output, attack_output):
    """
    Stage 4 - Dynamic Trust Calculator.
    Combines reliability (Stage 2) and attack likelihood (Stage 3) into
    a single trust weight per detector, between 0 and 1.
    """
    detector_names = list(detector_outputs.keys())

    trust_output = {}
    for name in detector_names:
        reliability = reliability_output[name]["reliability_score"]
        attack_likelihood = attack_output[name]["attack_likelihood"]

        # Simple formula: trust drops as attack likelihood rises,
        # scaled by how reliable the detector normally is
        trust = reliability * (1 - attack_likelihood)
        trust_output[name] = round(trust, 3)

    return trust_output


def generate_mock_stage5_conflict(detector_outputs, trust_output):
    """
    Stage 5 - Conflict Resolution Engine.
    Combines detector scores into one final score, weighted by trust.
    """
    detector_names = list(detector_outputs.keys())

    total_trust = sum(trust_output[name] for name in detector_names)
    if total_trust == 0:
        # avoid divide-by-zero if every detector is fully distrusted
        weights_used = {name: 1 / len(detector_names) for name in detector_names}
    else:
        weights_used = {
            name: round(trust_output[name] / total_trust, 3)
            for name in detector_names
        }

    final_score = sum(
        detector_outputs[name]["score"] * weights_used[name]
        for name in detector_names
    )

    # Confidence: average of detector confidences, weighted the same way
    final_confidence = sum(
        detector_outputs[name]["confidence"] * weights_used[name]
        for name in detector_names
    )

    return {
        "final_score": round(final_score, 3),
        "final_confidence": round(final_confidence, 3),
        "weights_used": weights_used
    }


def generate_mock_stage6_explanation(stage5_output, attack_output, scenario="all_agree_safe"):
    """
    Stage 6 - Decision Explanation Generator.
    Turns the final score into a decision label plus a human-readable
    rationale string.
    """
    final_score = stage5_output["final_score"]
    final_confidence = stage5_output["final_confidence"]

    if final_score >= 0.6:
        decision = "phishing"
    elif final_score <= 0.4:
        decision = "safe"
    else:
        decision = "uncertain"

    # Mention any detector flagged as a likely attack target in the rationale
    flagged = [
        name for name, info in attack_output.items()
        if info["attack_likelihood"] >= 0.5
    ]

    if flagged:
        rationale = (
            f"Final score {final_score} ({decision}). "
            f"Note: {', '.join(flagged)} detector(s) showed signs of adversarial "
            f"manipulation and were down-weighted accordingly."
        )
    else:
        rationale = (
            f"Final score {final_score} ({decision}), "
            f"with confidence {final_confidence}. No adversarial patterns detected."
        )

    return {
        "final_decision": decision,
        "final_score": final_score,
        "final_confidence": final_confidence,
        "rationale": rationale
    }


if __name__ == "__main__":
    scenario = "adversarial_pattern"

    print(f"=== Running full mock chain for scenario: {scenario} ===\n")

    detector_outputs = generate_all_detector_outputs(scenario)
    print("--- Detector outputs ---")
    for name, output in detector_outputs.items():
        print(f"{name}: {output}")

    stage1_output = generate_mock_stage1_disagreement(detector_outputs)
    print("\n--- Stage 1: Disagreement Matrix ---")
    print(stage1_output)

    stage2_output = generate_mock_stage2_reliability(detector_outputs, scenario)
    print("\n--- Stage 2: Reliability Memory ---")
    for name, output in stage2_output.items():
        print(f"{name}: {output}")

    stage3_output = generate_mock_stage3_adversarial(detector_outputs, stage2_output, scenario)
    print("\n--- Stage 3: Adversarial Attack Estimator ---")
    for name, output in stage3_output.items():
        print(f"{name}: {output}")

    stage4_output = generate_mock_stage4_trust(detector_outputs, stage2_output, stage3_output)
    print("\n--- Stage 4: Dynamic Trust Calculator ---")
    print(stage4_output)

    stage5_output = generate_mock_stage5_conflict(detector_outputs, stage4_output)
    print("\n--- Stage 5: Conflict Resolution Engine ---")
    print(stage5_output)

    stage6_output = generate_mock_stage6_explanation(stage5_output, stage3_output, scenario)
    print("\n--- Stage 6: Decision Explanation Generator ---")
    print(stage6_output)
