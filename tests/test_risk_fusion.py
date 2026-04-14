import unittest

from app.analyzers.risk_fusion import combine_component_scores


class RiskFusionTests(unittest.TestCase):
    def test_multiple_moderate_components_gain_corroboration_bonus(self):
        score = combine_component_scores(
            header_score=50,
            body_score=13,
            url_score=24,
            attachment_score=24,
        )

        self.assertEqual(score, 60)

    def test_single_component_keeps_original_score(self):
        score = combine_component_scores(header_score=50)

        self.assertEqual(score, 50)


if __name__ == "__main__":
    unittest.main()
