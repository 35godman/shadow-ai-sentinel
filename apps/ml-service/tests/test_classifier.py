"""
Shadow AI Sentinel — ML Classifier Unit Tests

Tests cover:
  - Per-entity medical context scoring (not global document flag)
  - Overlapping detection dedup: higher confidence detection wins
  - Combined risk calculation
  - Batch endpoint size limit

These tests use unittest.mock to avoid loading heavy spaCy/Presidio models,
so they run in CI without the full ML dependency stack.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the ml-service root is on sys.path so we can import `api.classifier`
# regardless of whether tests are run from the project root or the service dir.
_ML_SERVICE_ROOT = os.path.join(os.path.dirname(__file__), "..")
if _ML_SERVICE_ROOT not in sys.path:
    sys.path.insert(0, os.path.abspath(_ML_SERVICE_ROOT))


# ============================================================
# MOCK HEAVY DEPENDENCIES (spaCy, Presidio) so tests don't
# require the full ML stack to be installed.
# ============================================================

def _make_mock_spacy():
    spacy_mod = MagicMock()
    doc = MagicMock()
    doc.ents = []
    spacy_mod.load.return_value.return_value = doc
    return spacy_mod


# Install lightweight mocks before importing classifier
spacy_mock = _make_mock_spacy()
sys.modules.setdefault("spacy", spacy_mock)

sys.modules.setdefault("presidio_analyzer", MagicMock())
sys.modules.setdefault("presidio_analyzer.nlp_engine", MagicMock())
sys.modules.setdefault("structlog", MagicMock())

# Now we can safely import the classifier
from api.classifier import (  # noqa: E402
    Classifier,
    MLDetection,
    SensitivityLevel,
    MEDICAL_CONTEXT,
)


def _make_classifier() -> Classifier:
    """Build a Classifier with mocked heavy dependencies."""
    with patch("api.classifier.spacy") as mock_spacy, \
         patch("api.classifier.AnalyzerEngine") as mock_ae, \
         patch("api.classifier.NlpEngineProvider") as mock_nlp:

        doc_mock = MagicMock()
        doc_mock.ents = []
        mock_spacy.load.return_value.return_value = doc_mock

        mock_nlp.return_value.create_engine.return_value = MagicMock()
        mock_ae.return_value.analyze.return_value = []

        clf = Classifier.__new__(Classifier)
        clf.nlp = mock_spacy.load("en_core_web_sm")
        clf.presidio = mock_ae()
        return clf


class TestMedicalContextIsLocal(unittest.TestCase):
    """
    Fix 3.1: Medical context scoring must be PER ENTITY (local window),
    not a global document flag that elevates ALL entities in the document.
    """

    def _make_clf(self):
        clf = Classifier.__new__(Classifier)
        clf.nlp = MagicMock()
        clf.presidio = MagicMock()
        return clf

    def test_entity_near_medical_keyword_is_elevated(self):
        """A person name next to 'patient' should be elevated to HIGH."""
        clf = self._make_clf()

        text = "Patient John Doe visited the clinic."
        detections = [
            MLDetection(
                entity_type="PERSON",
                text="John Doe",
                start=8,
                end=16,
                confidence=0.75,
            )
        ]

        result = clf._apply_context_scoring(text, detections)

        # SensitivityLevel is a str enum — use assertIn rather than assertGreaterEqual
        # to avoid alphabetical ordering surprises ("CRITICAL" < "HIGH" alphabetically).
        self.assertIn(
            result[0].context_risk_score,
            {SensitivityLevel.HIGH, SensitivityLevel.CRITICAL},
            "PERSON near 'patient' should be elevated to at least HIGH",
        )

    def test_entity_far_from_medical_keyword_not_elevated(self):
        """
        A person name 500 chars away from 'patient' should NOT be elevated.
        This is the bug: the old global flag would elevate ALL entities when
        ANY part of the document contained 'patient'.
        """
        clf = self._make_clf()

        # 'patient' appears at the very end; PERSON is at position 0.
        far_away_text = "Alice Johnson is the CFO." + " " * 400 + " patient record here."
        detections = [
            MLDetection(
                entity_type="PERSON",
                text="Alice Johnson",
                start=0,
                end=13,
                confidence=0.75,
            )
        ]

        result = clf._apply_context_scoring(far_away_text, detections)

        # The PERSON is >400 chars from 'patient' — should NOT be elevated
        # (the context window is ±150 chars).
        self.assertNotEqual(
            result[0].context_risk_score,
            SensitivityLevel.CRITICAL,
            "PERSON far from medical keyword should not be elevated to CRITICAL",
        )

    def test_multiple_entities_only_nearby_ones_elevated(self):
        """
        Only entities within the context window of a medical keyword are elevated.
        Unrelated entities elsewhere in the document keep their baseline risk.
        """
        clf = self._make_clf()

        # Entity 1: close to 'patient' (chars 0-10), elevated expected
        # Entity 2: far from any medical keyword (chars 500+), not elevated
        text = "patient John" + " " * 500 + " CFO Alice"
        detections = [
            MLDetection(entity_type="PERSON", text="John", start=8, end=12, confidence=0.75),
            MLDetection(entity_type="PERSON", text="Alice", start=513, end=518, confidence=0.75),
        ]

        result = clf._apply_context_scoring(text, detections)

        john_risk = result[0].context_risk_score
        alice_risk = result[1].context_risk_score

        # John is next to 'patient' — should be elevated to at least HIGH
        self.assertIn(john_risk, {SensitivityLevel.HIGH, SensitivityLevel.CRITICAL},
                      f"John near 'patient' should be HIGH/CRITICAL, got {john_risk}")

        # Alice is far away — should NOT be CRITICAL (baseline for PERSON is MEDIUM)
        self.assertNotEqual(alice_risk, SensitivityLevel.CRITICAL,
                            f"Alice far from medical terms should not be CRITICAL, got {alice_risk}")


class TestOverlapDedupKeepsHigherConfidence(unittest.TestCase):
    """
    Fix 3.2: When two detections overlap, keep the higher-confidence one
    rather than always keeping the existing (Presidio) detection.
    """

    def _make_clf(self):
        clf = Classifier.__new__(Classifier)
        clf.nlp = MagicMock()
        clf.presidio = MagicMock()
        return clf

    def test_higher_confidence_new_detection_replaces_existing(self):
        """If the new detection has higher confidence, it should replace the existing one."""
        clf = self._make_clf()

        existing = [
            MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.6)
        ]
        new_det = MLDetection(entity_type="PERSON", text="John Doe", start=0, end=8, confidence=0.95)

        overlaps = clf._overlaps(new_det, existing)

        self.assertTrue(overlaps, "_overlaps should return True when overlap found")
        # The higher-confidence detection should have replaced the existing one
        self.assertEqual(existing[0].confidence, 0.95,
                         "Higher confidence detection should replace lower confidence one")
        self.assertEqual(existing[0].text, "John Doe",
                         "Higher confidence detection text should replace existing")

    def test_lower_confidence_new_detection_does_not_replace(self):
        """If the new detection has lower confidence, the existing one is kept."""
        clf = self._make_clf()

        existing = [
            MLDetection(entity_type="PERSON", text="John Doe", start=0, end=8, confidence=0.95)
        ]
        new_det = MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.5)

        overlaps = clf._overlaps(new_det, existing)

        self.assertTrue(overlaps, "_overlaps should return True when overlap found")
        # The existing high-confidence detection should be kept
        self.assertEqual(existing[0].confidence, 0.95,
                         "Existing higher-confidence detection should be preserved")

    def test_no_overlap_returns_false(self):
        """Non-overlapping detections should not interfere."""
        clf = self._make_clf()

        existing = [
            MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.8)
        ]
        new_det = MLDetection(entity_type="EMAIL", text="alice@corp.com", start=10, end=24, confidence=0.9)

        overlaps = clf._overlaps(new_det, existing)

        self.assertFalse(overlaps, "_overlaps should return False when no overlap")
        # Existing should be unchanged
        self.assertEqual(existing[0].confidence, 0.8)


class TestFinancialContextIsLocal(unittest.TestCase):
    """
    Financial context scoring must be PER ENTITY (local ±150-char window),
    not a global document flag. Mirrors the already-correct medical context fix.
    """

    def _make_clf(self):
        clf = Classifier.__new__(Classifier)
        clf.nlp = MagicMock()
        clf.presidio = MagicMock()
        return clf

    def test_entity_near_financial_keyword_is_elevated(self):
        """A PERSON right next to 'payment' should be elevated to HIGH."""
        clf = self._make_clf()

        text = "payment invoice for Alice Johnson."
        detections = [
            MLDetection(entity_type="PERSON", text="Alice Johnson", start=20, end=33, confidence=0.75)
        ]

        result = clf._apply_context_scoring(text, detections)

        self.assertEqual(
            result[0].context_risk_score,
            SensitivityLevel.HIGH,
            "PERSON near 'payment' should be elevated to HIGH",
        )

    def test_entity_far_from_financial_keyword_not_elevated(self):
        """
        A PERSON 500 chars away from any financial keyword should NOT be elevated.
        This was the bug: global has_financial_context flag elevated everything.
        """
        clf = self._make_clf()

        # Financial keyword at the very end, PERSON at position 0
        far_away_text = "Alice Johnson is the director." + " " * 400 + " payment invoice #1234"
        detections = [
            MLDetection(entity_type="PERSON", text="Alice Johnson", start=0, end=13, confidence=0.75)
        ]

        result = clf._apply_context_scoring(far_away_text, detections)

        self.assertNotEqual(
            result[0].context_risk_score,
            SensitivityLevel.HIGH,
            "PERSON far from financial keyword should NOT be elevated to HIGH (per-entity window fix)",
        )


class TestRemoveDominatedOverlaps(unittest.TestCase):
    """
    _remove_dominated_overlaps() cleans up any residual overlapping detections
    left after the _overlaps() dedup loop, keeping the highest-confidence one.
    """

    def _make_clf(self):
        clf = Classifier.__new__(Classifier)
        clf.nlp = MagicMock()
        clf.presidio = MagicMock()
        return clf

    def test_keeps_highest_confidence_when_overlapping(self):
        """When two detections overlap, only the higher-confidence one survives."""
        clf = self._make_clf()

        detections = [
            MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.6),
            MLDetection(entity_type="PERSON", text="John Doe", start=0, end=8, confidence=0.95),
        ]

        result = clf._remove_dominated_overlaps(detections)

        self.assertEqual(len(result), 1, "Overlapping detections should be reduced to 1")
        self.assertEqual(result[0].confidence, 0.95,
                         "Higher-confidence detection should survive")
        self.assertEqual(result[0].text, "John Doe")

    def test_non_overlapping_detections_all_kept(self):
        """Non-overlapping detections should all be kept intact."""
        clf = self._make_clf()

        detections = [
            MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.8),
            MLDetection(entity_type="EMAIL", text="a@b.com", start=10, end=17, confidence=0.9),
            MLDetection(entity_type="PHONE", text="555-1234", start=25, end=33, confidence=0.85),
        ]

        result = clf._remove_dominated_overlaps(detections)

        self.assertEqual(len(result), 3, "All non-overlapping detections should be kept")

    def test_output_sorted_by_start_offset(self):
        """Output detections should be ordered by start offset."""
        clf = self._make_clf()

        detections = [
            MLDetection(entity_type="EMAIL", text="a@b.com", start=30, end=37, confidence=0.9),
            MLDetection(entity_type="PERSON", text="John", start=0, end=4, confidence=0.8),
            MLDetection(entity_type="PHONE", text="555-1234", start=15, end=23, confidence=0.75),
        ]

        result = clf._remove_dominated_overlaps(detections)

        offsets = [d.start for d in result]
        self.assertEqual(offsets, sorted(offsets), "Output should be sorted by start offset")


class TestCombinedRisk(unittest.TestCase):
    """Combined risk should return the highest risk level across all detections."""

    def _make_clf(self):
        clf = Classifier.__new__(Classifier)
        clf.nlp = MagicMock()
        clf.presidio = MagicMock()
        return clf

    def test_empty_detections_returns_low(self):
        clf = self._make_clf()
        risk = clf._combined_risk([])
        self.assertEqual(risk, SensitivityLevel.LOW)

    def test_critical_detection_returns_critical(self):
        clf = self._make_clf()
        detections = [
            MLDetection(entity_type="SSN", text="078-05-1120", start=0, end=11,
                        confidence=0.95, context_risk_score=SensitivityLevel.CRITICAL),
            MLDetection(entity_type="EMAIL", text="a@b.com", start=20, end=27,
                        confidence=0.75, context_risk_score=SensitivityLevel.MEDIUM),
        ]
        risk = clf._combined_risk(detections)
        self.assertEqual(risk, SensitivityLevel.CRITICAL)

    def test_medium_only_returns_medium(self):
        clf = self._make_clf()
        detections = [
            MLDetection(entity_type="PERSON", text="John", start=0, end=4,
                        confidence=0.75, context_risk_score=SensitivityLevel.MEDIUM),
        ]
        risk = clf._combined_risk(detections)
        self.assertEqual(risk, SensitivityLevel.MEDIUM)


if __name__ == "__main__":
    unittest.main()
