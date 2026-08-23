from orchestration.mock import (
    generate_all_detector_outputs,
    generate_mock_stage1_disagreement,
    generate_mock_stage2_reliability,
    generate_mock_stage3_adversarial,
    generate_mock_stage4_trust,
    generate_mock_stage5_conflict,
    generate_mock_stage6_explanation,
)


def run_pipeline(url: str, scenario: str = "all_agree_safe") -> dict:
    """
    Runs the full 6-stage phishing detection pipeline for a given URL.

    Right now, every stage is a MOCK function (fake data) because
    teammates haven't handed off their real modules yet. The 'scenario'
    argument is temporary - it lets us fake different situations for
    testing. Once real detectors/stages exist (Phase 4), this function's
    insides get swapped out, but run_pipeline(url) will still work the
    same way from the outside - that's the whole point of designing it
    this way.
    """

    # Step 1: call all 4 detectors (currently mocked)
    detector_outputs = generate_all_detector_outputs(scenario)

    # Step 2: Stage 1 - how much do the detectors disagree?
    stage1_output = generate_mock_stage1_disagreement(detector_outputs)

    # Step 3: Stage 2 - how reliable has each detector been historically?
    stage2_output = generate_mock_stage2_reliability(detector_outputs, scenario)

    # Step 4: Stage 3 - is any detector currently being attacked/fooled?
    stage3_output = generate_mock_stage3_adversarial(detector_outputs, stage2_output, scenario)

    # Step 5: Stage 4 - combine reliability + attack likelihood into trust
    stage4_output = generate_mock_stage4_trust(detector_outputs, stage2_output, stage3_output)

    # Step 6: Stage 5 - combine all detector scores into one final score,
    # weighted by trust
    stage5_output = generate_mock_stage5_conflict(detector_outputs, stage4_output)

    # Step 7: Stage 6 - turn the final score into a decision + explanation
    stage6_output = generate_mock_stage6_explanation(stage5_output, stage3_output, scenario)

    # Return the final decision, PLUS every intermediate stage's output.
    # The dashboard (Person 1's job) will want to show the intermediate
    # steps too, not just the final answer.
    return {
        "url": url,
        "final_decision": stage6_output,
        "breakdown": {
            "detector_outputs": detector_outputs,
            "stage1_disagreement": stage1_output,
            "stage2_reliability": stage2_output,
            "stage3_adversarial": stage3_output,
            "stage4_trust": stage4_output,
            "stage5_conflict": stage5_output,
        }
    }


if __name__ == "__main__":
    # Quick manual test - run this file directly to see it work end to end
    test_url = "http://example-suspicious-site.com"

    print(f"--- Running pipeline for: {test_url} (scenario: all_agree_safe) ---")
    result = run_pipeline(test_url, scenario="all_agree_safe")
    print(result["final_decision"])

    print(f"\n--- Running pipeline for: {test_url} (scenario: adversarial_pattern) ---")
    result = run_pipeline(test_url, scenario="adversarial_pattern")
    print(result["final_decision"])
