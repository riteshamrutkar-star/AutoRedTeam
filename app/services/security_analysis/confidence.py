from app.schemas.finding import ConfidenceFactors, EvidenceStrength


class ConfidenceEngine:
    """Deterministic confidence engine calculating overall score from explicit factors."""

    def calculate_confidence(
        self,
        evidence_strength: EvidenceStrength,
        behavior_consistency: float = 1.0,
        test_specificity: float = 1.0,
        expected_behavior_match: float = 1.0,
        ambiguity_penalty: float = 0.0,
    ) -> ConfidenceFactors:
        """Calculates deterministic confidence score derived from declared factors."""
        strength_weights = {
            EvidenceStrength.STRONG: 1.0,
            EvidenceStrength.MODERATE: 0.7,
            EvidenceStrength.WEAK: 0.4,
            EvidenceStrength.NONE: 0.0,
        }
        strength_score = strength_weights.get(evidence_strength, 0.0)

        # Weighted calculation
        raw_score = (
            (strength_score * 0.40)
            + (behavior_consistency * 0.25)
            + (test_specificity * 0.25)
            + (expected_behavior_match * 0.10)
        ) - ambiguity_penalty

        final_score = round(max(0.0, min(1.0, raw_score)), 2)

        return ConfidenceFactors(
            evidence_strength=evidence_strength,
            behavior_consistency=round(behavior_consistency, 2),
            test_specificity=round(test_specificity, 2),
            expected_behavior_match=round(expected_behavior_match, 2),
            ambiguity_penalty=round(ambiguity_penalty, 2),
            overall_score=final_score,
        )
