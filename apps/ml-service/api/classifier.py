"""
Shadow AI Sentinel — ML Classifier Engine
Combines Microsoft Presidio, spaCy NER, and context-aware scoring
to detect unstructured PII that regex patterns miss.

Examples regex can't catch:
  - "John has diabetes" → PERSON + MEDICAL_CONDITION
  - "Send the contract to the Denver office" → LOCATION + CONTRACT_TERM
  - "Patient DOB is March 15 1985" → MEDICAL context + date
"""

import time
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field

import spacy
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
import structlog

logger = structlog.get_logger()


# ============================================================
# TYPES
# ============================================================

class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class MLDetection:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    source: str = "ML"
    context_risk_score: SensitivityLevel = SensitivityLevel.MEDIUM
    redacted_text: str = ""

    def __post_init__(self):
        if not self.redacted_text:
            self.redacted_text = f"[{self.entity_type}_REDACTED]"


@dataclass
class MLScanResult:
    detections: list[MLDetection] = field(default_factory=list)
    combined_risk: SensitivityLevel = SensitivityLevel.LOW
    scan_duration_ms: float = 0.0


# ============================================================
# ENTITY TYPE MAPPING
# Map Presidio/spaCy types to our internal types
# ============================================================

PRESIDIO_TO_SENTINEL = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD",
    "CRYPTO": "CREDENTIALS",
    "IBAN_CODE": "IBAN",
    "IP_ADDRESS": "IP_ADDRESS",
    "MEDICAL_LICENSE": "MEDICAL_ID",
    "US_SSN": "SSN",
    "US_BANK_NUMBER": "FINANCIAL_ACCOUNT",
    "US_DRIVER_LICENSE": "CREDENTIALS",
    "US_PASSPORT": "CREDENTIALS",
    "UK_NHS": "MEDICAL_ID",
    "NRP": "PERSON",  # Nationality/Religious/Political group
    "LOCATION": "LOCATION",
    "DATE_TIME": "DATE",  # Context-dependent
    "ORGANIZATION": "ORGANIZATION",
}

# Context keywords that elevate risk
MEDICAL_CONTEXT = {
    "patient", "diagnosis", "treatment", "prescription", "medication",
    "symptoms", "medical", "health", "doctor", "hospital", "clinical",
    "hipaa", "phi", "condition", "disease", "therapy", "surgeon",
    "nurse", "pharmacy", "dosage", "prognosis", "lab results",
}

FINANCIAL_CONTEXT = {
    "account", "routing", "wire", "transfer", "payment", "invoice",
    "salary", "compensation", "revenue", "profit", "tax", "ssn",
    "social security", "bank", "credit", "debit", "loan",
}

CODE_CONTEXT = {
    "function", "class", "import", "def ", "const ", "var ", "let ",
    "return", "async", "await", "export", "module", "require",
    "api_key", "secret", "password", "token", "bearer",
}


# ============================================================
# CLASSIFIER ENGINE
# ============================================================

class Classifier:
    """
    Multi-layer ML classifier:
    1. Presidio (rule-based NER, good baseline)
    2. spaCy NER (statistical, catches context)
    3. Context scoring (elevates risk based on surrounding text)
    """

    def __init__(self):
        logger.info("Initializing ML classifier...")
        start = time.time()

        # Initialize spaCy
        self.nlp = spacy.load("en_core_web_sm")

        # Initialize Presidio with spaCy backend
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()
        self.presidio = AnalyzerEngine(nlp_engine=nlp_engine)

        elapsed = (time.time() - start) * 1000
        logger.info("ML classifier initialized", duration_ms=f"{elapsed:.0f}")

    def scan(self, text: str, language: str = "en") -> MLScanResult:
        """Run full ML scan pipeline."""
        start = time.time()
        detections: list[MLDetection] = []

        # Layer 1: Presidio analysis
        presidio_results = self._run_presidio(text, language)
        detections.extend(presidio_results)

        # Layer 2: spaCy NER (catch entities Presidio misses)
        spacy_results = self._run_spacy(text)
        # Dedup against Presidio results
        for sd in spacy_results:
            if not self._overlaps(sd, detections):
                detections.append(sd)

        # Layer 3: Context scoring
        detections = self._apply_context_scoring(text, detections)

        # Determine combined risk
        combined_risk = self._combined_risk(detections)

        elapsed = (time.time() - start) * 1000

        return MLScanResult(
            detections=detections,
            combined_risk=combined_risk,
            scan_duration_ms=elapsed,
        )

    def _run_presidio(self, text: str, language: str) -> list[MLDetection]:
        """Run Presidio analyzer."""
        try:
            results: list[RecognizerResult] = self.presidio.analyze(
                text=text,
                language=language,
                entities=None,  # Detect all
                score_threshold=0.4,
            )
        except Exception as e:
            logger.error("Presidio analysis failed", error=str(e))
            return []

        detections = []
        for r in results:
            entity_type = PRESIDIO_TO_SENTINEL.get(r.entity_type, r.entity_type)
            detections.append(MLDetection(
                entity_type=entity_type,
                text=text[r.start:r.end],
                start=r.start,
                end=r.end,
                confidence=r.score,
                source="ML_PRESIDIO",
            ))
        return detections

    def _run_spacy(self, text: str) -> list[MLDetection]:
        """Run spaCy NER for additional entity detection."""
        try:
            doc = self.nlp(text)
        except Exception as e:
            logger.error("spaCy analysis failed", error=str(e))
            return []

        detections = []
        for ent in doc.ents:
            entity_type = self._map_spacy_label(ent.label_)
            if entity_type:
                detections.append(MLDetection(
                    entity_type=entity_type,
                    text=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.75,  # spaCy doesn't provide confidence, use baseline
                    source="ML_SPACY",
                ))
        return detections

    def _map_spacy_label(self, label: str) -> Optional[str]:
        """Map spaCy entity labels to our types."""
        mapping = {
            "PERSON": "PERSON",
            "ORG": "ORGANIZATION",
            "GPE": "LOCATION",
            "LOC": "LOCATION",
            "FAC": "LOCATION",
            "MONEY": "FINANCIAL_ACCOUNT",
            "PRODUCT": None,  # Skip
            "DATE": None,     # Context-dependent, handled in scoring
            "TIME": None,
        }
        return mapping.get(label)

    def _apply_context_scoring(self, text: str, detections: list[MLDetection]) -> list[MLDetection]:
        """
        Elevate risk based on surrounding context.
        A phone number in a support article = LOW.
        Same phone number preceded by 'patient' = HIGH.

        Context check is PER ENTITY (±150 chars around each detection) — not a global
        document-level flag. This prevents a single 'patient' mention from elevating
        ALL entities in the document, including unrelated emails and phone numbers.
        """
        text_lower = text.lower()
        # Financial and code context are document-level (they affect all entities)
        has_financial_context = any(kw in text_lower for kw in FINANCIAL_CONTEXT)
        has_code_context = any(kw in text_lower for kw in CODE_CONTEXT)

        for d in detections:
            # Per-entity context window: 150 chars around this specific detection
            ctx_start = max(0, d.start - 150)
            ctx_end = min(len(text), d.end + 150)
            context_window = text[ctx_start:ctx_end].lower()

            # Medical context check is PER ENTITY — only elevates entities
            # that actually appear near medical keywords.
            has_medical_context = any(kw in context_window for kw in MEDICAL_CONTEXT)

            # Medical context elevates PII near medical keywords
            if has_medical_context:
                if d.entity_type in ("PERSON", "PHONE", "EMAIL", "LOCATION"):
                    d.context_risk_score = SensitivityLevel.HIGH
                    d.confidence = min(d.confidence * 1.3, 1.0)
                if d.entity_type == "PERSON" and any(kw in context_window for kw in ("patient", "diagnosis", "treatment")):
                    d.context_risk_score = SensitivityLevel.CRITICAL

            # Financial context
            if has_financial_context:
                if d.entity_type in ("PERSON", "PHONE", "EMAIL"):
                    d.context_risk_score = SensitivityLevel.HIGH

            # Code context (lower risk for entities found in code)
            if has_code_context and d.entity_type in ("EMAIL", "PHONE", "IP_ADDRESS"):
                # Might be test data / examples in code
                d.confidence *= 0.7
                if d.confidence < 0.5:
                    d.context_risk_score = SensitivityLevel.LOW

            # Default risk based on entity type
            if d.context_risk_score == SensitivityLevel.MEDIUM:
                d.context_risk_score = self._default_risk(d.entity_type)

        return detections

    def _default_risk(self, entity_type: str) -> SensitivityLevel:
        """Default risk level per entity type."""
        critical = {"SSN", "CREDIT_CARD", "CREDENTIALS", "AWS_KEY", "GCP_KEY", "API_KEY"}
        high = {"MEDICAL_ID", "MEDICAL_CONDITION", "DIAGNOSIS", "MEDICATION", "FINANCIAL_ACCOUNT", "IBAN"}
        medium = {"PERSON", "PHONE", "EMAIL", "LOCATION", "ORGANIZATION", "SOURCE_CODE"}

        if entity_type in critical:
            return SensitivityLevel.CRITICAL
        if entity_type in high:
            return SensitivityLevel.HIGH
        if entity_type in medium:
            return SensitivityLevel.MEDIUM
        return SensitivityLevel.LOW

    def _combined_risk(self, detections: list[MLDetection]) -> SensitivityLevel:
        """Determine overall risk from all detections."""
        if not detections:
            return SensitivityLevel.LOW
        risks = [d.context_risk_score for d in detections]
        if SensitivityLevel.CRITICAL in risks:
            return SensitivityLevel.CRITICAL
        if SensitivityLevel.HIGH in risks:
            return SensitivityLevel.HIGH
        if SensitivityLevel.MEDIUM in risks:
            return SensitivityLevel.MEDIUM
        return SensitivityLevel.LOW

    def _overlaps(self, detection: MLDetection, existing: list[MLDetection]) -> bool:
        """
        Check if a detection overlaps with existing ones (for dedup).
        When an overlap is found, keeps the higher-confidence detection in-place
        (replacing the existing one if the new detection is better).
        Returns True when an overlap was found (caller should not append the detection).
        """
        for i, e in enumerate(existing):
            if detection.start < e.end and detection.end > e.start:
                # Overlap found: replace existing with new if new has higher confidence
                if detection.confidence > e.confidence:
                    existing[i] = detection
                return True
        return False


# Singleton instance
_classifier: Optional[Classifier] = None

def get_classifier() -> Classifier:
    global _classifier
    if _classifier is None:
        _classifier = Classifier()
    return _classifier
