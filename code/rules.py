"""Policy evaluation, intent classification, and deletion-status determination module.

Responsible for:
1. Classifying request intent: determining if request authorizes deletion or is NOT_APPLICABLE.
2. Distinguishing non-deletion actions: access requests, rectification, data portability,
   marketing opt-outs, and login/account recovery.
3. Supporting multilingual wording across English, Spanish, Portuguese, French, German,
   Italian, Dutch, Korean, Japanese, and Chinese.
4. Enforcing statutory deletion policy rules (deletion_rules.csv).
5. Providing deterministic intent decisions without hardcoded case IDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from code.models import DeletionStatus


class RequestIntent(str, Enum):
    """Categorized request intent according to official competition specification."""
    DELETION = "DELETION"
    ACCESS = "ACCESS"
    RECTIFICATION = "RECTIFICATION"
    PORTABILITY = "PORTABILITY"
    MARKETING_OPTOUT = "MARKETING_OPTOUT"
    ACCOUNT_RECOVERY = "ACCOUNT_RECOVERY"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass
class IntentResult:
    """Detailed result of request-text intent classification."""
    intent: RequestIntent
    is_deletion_authorized: bool
    confidence: float
    detected_language: str
    reasons: List[str] = field(default_factory=list)
    matched_signals: List[str] = field(default_factory=list)
    retention_exceptions: List[str] = field(default_factory=list)


# --- Deterministic Multilingual Patterns ---

# Patterns identifying specific partial retention clauses (e.g. tax records, invoices)
RETENTION_PATTERNS = [
    r"\b(?:do\s+not|don['’]?t)\s+(?:delete|remove|erase|purge)\s+(?:my\s+)?((?:(?:billing|tax|financial)\s+)?(?:invoices?|records?|data|documents?|receipts?)|order\s+history|transactions?)\b",
    r"\b(?:retain|keep|preserve|hold|save)\s+(?:my\s+)?((?:(?:billing|tax|financial)\s+)?(?:invoices?|records?|data|documents?|receipts?)|order\s+history|transactions?)\b",
    r"\b(?:except|with\s+the\s+exception\s+of)\s+(?:for\s+)?(?:my\s+)?((?:(?:billing|tax|financial)\s+)?(?:invoices?|records?|data|documents?|receipts?)|order\s+history|transactions?)\b",
]

# Explicit general refusals or negations of account/data deletion
REFUSAL_PATTERNS = [
    # English non-adjacent refusal: e.g. "do not want my account deleted", "don't want data erased"
    r"\b(?:do\s+not|don['’]?t)\s+(?:want|wish|ask|request|intend)\s+(?:(?:\w+)\s+){0,4}(?:delet(?:e|ed)|eras(?:e|ed)|remov(?:e|ed)|purged)\b",
    # English direct refusal: e.g. "do not delete", "don't remove", "not asking for deletion"
    r"\b(?:do\s+not|don['’]?t)\s+(?:delete|remove|close|erase|change)\b",
    r"\bnot\s+(?:asking\s+for|requesting|seeking)\s+(?:a\s+)?(?:deletion|erasure|removal)\b",
    r"\bnot\s+a\s+request\s+to\s+(?:erase|delete|remove|close)\b",
    r"\bwithout\s+(?:removing|deleting|erasing)\b",
    r"\bleave\s+(?:the\s+account|my\s+profile|my\s+account)\s+(?:active|as\s+it\s+is|in\s+place|open)\b",
    r"\bkeep\s+(?:the\s+account|my\s+account|the\s+profile)\s+(?:as\s+it\s+is|active|open)\b",
    r"\b(?:still\s+use|want\s+to\s+continue\s+using)\b",
    r"\bmarketing\s+lists?\s+only\b",
    r"\bpromotional\s+emails?\s+only\b",
    # Multilingual explicit refusals
    r"\bno\s+(?:estoy\s+pidiendo|quiero|deseo)\s+(?:la\s+eliminaci[oó]n|que\s+se\s+elimine|que\s+se\s+borre)\b",
    r"\bdejar\s+la\s+cuenta\s+activa\b",
    r"\bne\s+supprimez\s+pas\b",
    r"\bnicht\s+(?:l[oö]schen|loeschen)\b",
    r"\bkonto\s+aktiv\s+lassen\b",
    r"\bnon\s+(?:cancellare|eliminare)\b",
    r"\blasciar\s+(?:il\s+conto|l['’]account)\s+attivo\b",
    r"\bn[aã]o\s+(?:excluir|apagar)\b",
    r"\bdeixar\s+a\s+conta\s+ativa\b",
]

# Backward-compatibility alias for previous imports
NEGATION_PATTERNS = REFUSAL_PATTERNS

# Historical mentions of deletion (past tense or prior completed events, not an instruction to delete)
HISTORICAL_PATTERNS = [
    r"\b(?:was|were|got|is|had\s+been|has\s+been)\s+(?:already\s+)?(?:delet(?:ed)?|eras(?:ed)?|purged|closed|cancel(?:led)?)\b",
    r"\b(?:account|profile|data)\s+(?:was|got)\s+deleted\b",
    r"\b(?:deleted|closed|cancelled)\s+(?:last\s+(?:year|month|week)|in\s+\d{4}|previously|already|ago)\b",
    r"\b(?:fue|ha\s+sido|estaba)\s+(?:eliminad[oa]|borrad[oa]|cerrad[oa])\b",
    r"\b(?:a\s+[eé]t[eé]|avait\s+[eé]t[eé]|est)\s+(?:supprim[eé]|effac[eé]|ferm[eé])\b",
    r"\b(?:wurde|war)\s+(?:gel[oö]scht|geloescht|geschlossen)\b",
]

# Regex patterns indicating explicit affirmative deletion intent
DEL_PATTERNS = [
    # English
    r"\b(?:account[\s-])?delet(?:e|ed|ion|ing|ions)?\b",
    r"\beras(?:e|ed|ure|ing)?\b",
    r"\bremov(?:e|ed|al|ing)?\b",
    r"\bpurg(?:e|ed|ing)?\b",
    r"\btombstone\b",
    r"\b(?:clos(?:e|ed|ing)|cancel(?:led|ing)?)\s+(?:this\s+|my\s+|the\s+)?account\b",
    # Spanish (infinitive, imperative, subjunctive, past participle, noun)
    r"\b(?:eliminar|elimine|eliminen|eliminad[oa]|eliminaci[oó]n|borrar|borre|borren|borrado|suprimir|suprima|supriman|supresi[oó]n)\b",
    r"\b(?:cerrar|cierre|cierren|cancelar|cancele|cancelen)\s+(?:la\s+|esta\s+)?cuenta\b",
    # Portuguese (infinitive, imperative, subjunctive, past participle, noun)
    r"\b(?:excluir|exclua|excluam|exclu[ií]d[oa]|exclus[aã]o|apagar|apague|apaguem|apagado|eliminar|elimine|elimina)\b",
    r"\b(?:fechar|feche|fechem|cancelar|cancele|cancelem)\s+(?:a\s+|esta\s+)?conta\b",
    # French (infinitive, imperative, noun)
    r"\b(?:supprimer|supprimez|supprim[eé]|suppression|effacer|effacez|effacement)\b",
    r"\bfermer\s+(?:le\s+|ce\s+)?compte\b",
    # German (umlaut and transliterated loeschen, past participle, noun)
    r"\b(?:l[oö]schen|loeschen|gel[oö]scht|geloescht|l[oö]schung|loeschung|entfernen|entfernt|entfernung)\b",
    r"\bkonto\s+(?:schlie[sß]en|l[oö]schen|loeschen)\b",
    # Italian
    r"\b(?:cancellare|cancelli|cancellate|cancellat[oa]|cancellazione|eliminare|elimini|eliminate|eliminat[oa]|eliminazione|rimuovere|rimozione)\b",
    r"\bchiudere\s+(?:il\s+|questo\s+)?account\b",
    # Dutch
    r"\b(?:verwijderen|verwijderd|verwijdering|wissen)\b",
    # Asian characters
    r"삭제|제거|탈퇴|해지",   # Korean
    r"削除|消去|退会",         # Japanese
    r"删除|注销|抹掉",         # Chinese
]

# Specific Non-Deletion Intent Patterns
ACCESS_PATTERNS = [
    r"\b(?:send\s+me\s+a\s+copy|copy\s+of\s+my|copy\s+of\s+last\s+year|download\s+my|export\s+my|access\s+to\s+my\s+data)\b",
    r"\b(?:receive|get|provide|obtain)\s+(?:a\s+)?copy\s+of\s+(?:all\s+)?(?:my\s+)?data\b",
    r"\bwhat\s+personal\s+(?:information|data)\s+you\s+hold\b",
    r"\binformation\s+request\b",
    r"\bcopia\s+de\s+(?:mis\s+datos|las\s+facturas)\b",
    r"\bcopie\s+de\s+mes\s+donn[eé]es\b",
    r"\bkopie\s+meiner\s+daten\b",
]

RECTIFICATION_PATTERNS = [
    r"\b(?:misspelled|spelling\s+is\s+wrong|correct\s+it|correct\s+the\s+spelling)\b",
    r"\b(?:out\s+of\s+date|replace\s+it\s+with\s+the\s+new\s+one)\b",
    r"\b(?:change|update)\s+(?:the\s+|my\s+)?(?:email(?:\s+address)?|mobile|phone|number|address|name|surname)\b",
    r"\bactualizar\s+(?:mis\s+datos|el\s+correo|el\s+tel[eé]fono)\b",
    r"\bcorriger\s+(?:mon\s+nom|mes\s+informations)\b",
    r"\bmeine\s+daten\s+aktualisieren\b",
]

PORTABILITY_PATTERNS = [
    r"\b(?:portable\s+format|data\s+portability|formato\s+portable|format\s+portable)\b",
    r"\bexport\s+(?:my\s+)?(?:personal\s+)?data\s+in\s+(?:json|csv|xml|machine-readable)\s+format\b",
]

MARKETING_OPTOUT_PATTERNS = [
    r"\b(?:stop\s+the\s+promotional\s+emails|stop\s+promotional\s+emails|unsubscribe|opt[\s-]out\s+of\s+marketing)\b",
    r"\bremove\s+me\s+from\s+marketing\b",
    r"\bdarse\s+de\s+baja\b",
    r"\bd[eé]sabonner\b",
    r"\bvom\s+newsletter\s+abmelden\b",
]

RECOVERY_PATTERNS = [
    r"\b(?:resetting\s+the\s+login|reset\s+password|can[\'’]t\s+access\s+my\s+profile|cannot\s+access\s+my\s+profile|trouble\s+logging\s+in|help\s+me\s+reset\s+my\s+password)\b",
    r"\bforgot\s+(?:my\s+)?password\b",
    r"\bhelp\s+me\s+create\s+(?:a\s+)?new\b",
    r"\brecuperar\s+(?:acceso|cuenta|contrase[nñ]a)\b",
    r"\br[eé]cup[eé]rer\s+mon\s+compte\b",
    r"\bpasswort\s+zur[uü]cksetzen\b",
]


def detect_language(text: str) -> str:
    """Detect request language using representative character sets and keywords."""
    if re.search(r'[\uac00-\ud7af]', text):
        return "Korean"
    elif re.search(r'[\u3040-\u30ff]', text):
        return "Japanese"
    elif re.search(r'[\u4e00-\u9fff]', text):
        return "Chinese"
    elif re.search(r'\b(?:conta|exclus[aã]o|excluir|exclua|excluam|apagar|apague|solicito\s+a\s+exclus)\b', text, re.I):
        return "Portuguese"
    elif re.search(r'\b(?:cuenta|eliminaci[oó]n|eliminar|elimine|eliminen|borrar|borre|solicito\s+la\s+eliminac)\b', text, re.I):
        return "Spanish"
    elif re.search(r'\b(?:suppression|supprimer|supprimez|compte|veuillez|donn[eé]es|merci)\b', text, re.I):
        return "French"
    elif re.search(r'\b(?:bitte|l[oö]schen|loeschen|konto|daten|entfernen)\b', text, re.I):
        return "German"
    elif re.search(r'\b(?:cancellare|cancelli|eliminazione|profilo|grazie)\b', text, re.I):
        return "Italian"
    elif re.search(r'\b(?:verwijderen|verwijdering|alstublieft|geheugen|gegevens)\b', text, re.I):
        return "Dutch"
    return "English"


class DeletionIntentClassifier:
    """Deterministic classifier evaluating whether request authorizes personal data deletion."""

    def classify(self, request_text: Optional[str]) -> IntentResult:
        """Classify user request text into official intent categories."""
        if not request_text or not isinstance(request_text, str) or not request_text.strip():
            return IntentResult(
                intent=RequestIntent.AMBIGUOUS,
                is_deletion_authorized=False,
                confidence=0.0,
                detected_language="Unknown",
                reasons=["Empty or invalid request text"],
            )

        clean_text = request_text.strip()
        lang = detect_language(clean_text)

        # 1. Detect Retention Exceptions (partial / scoped retention clauses)
        retention_spans: List[Tuple[int, int]] = []
        retention_exceptions: List[str] = []
        for pat in RETENTION_PATTERNS:
            for m in re.finditer(pat, clean_text, re.IGNORECASE):
                retention_spans.append(m.span())
                if m.groups() and m.group(1):
                    retention_exceptions.append(m.group(1).strip())
                else:
                    retention_exceptions.append(m.group(0).strip())

        # 2. Detect Refusal Spans (general explicit refusals of account/data deletion)
        refusal_spans: List[Tuple[int, int]] = []
        refusal_signals: List[str] = []
        for pat in REFUSAL_PATTERNS:
            for m in re.finditer(pat, clean_text, re.IGNORECASE):
                span = m.span()
                # Do not treat a scoped retention clause as an account-wide refusal
                is_sub_retention = any(r_start <= span[0] and span[1] <= r_end for r_start, r_end in retention_spans)
                if not is_sub_retention:
                    refusal_spans.append(span)
                    refusal_signals.append(m.group(0))

        # 3. Detect Historical Spans (past observations, not current instructions)
        historical_spans: List[Tuple[int, int]] = []
        historical_signals: List[str] = []
        for pat in HISTORICAL_PATTERNS:
            for m in re.finditer(pat, clean_text, re.IGNORECASE):
                historical_spans.append(m.span())
                historical_signals.append(m.group(0))

        # 4. Detect Affirmative Deletion Signals
        # Matches must NOT be enclosed in refusal, historical, or retention spans
        del_signals: List[str] = []
        for pat in DEL_PATTERNS:
            for m in re.finditer(pat, clean_text, re.IGNORECASE):
                m_start, m_end = m.span()
                in_refusal = any(r_start <= m_start and m_end <= r_end for r_start, r_end in refusal_spans)
                in_historical = any(h_start <= m_start and m_end <= h_end for h_start, h_end in historical_spans)
                in_retention = any(ret_start <= m_start and m_end <= ret_end for ret_start, ret_end in retention_spans)
                if not (in_refusal or in_historical or in_retention):
                    del_signals.append(m.group(0))

        # 5. Detect Non-Deletion Specific Categories
        access_matches = [m.group(0) for pat in ACCESS_PATTERNS if (m := re.search(pat, clean_text, re.I))]
        rect_matches = [m.group(0) for pat in RECTIFICATION_PATTERNS if (m := re.search(pat, clean_text, re.I))]
        port_matches = [m.group(0) for pat in PORTABILITY_PATTERNS if (m := re.search(pat, clean_text, re.I))]
        opt_matches = [m.group(0) for pat in MARKETING_OPTOUT_PATTERNS if (m := re.search(pat, clean_text, re.I))]
        recov_matches = [m.group(0) for pat in RECOVERY_PATTERNS if (m := re.search(pat, clean_text, re.I))]

        # --- Decision Hierarchy ---

        # Case A: Deletion explicitly refused / negated
        if refusal_signals:
            reasons = [f"Explicit refusal of deletion identified: '{refusal_signals[0]}'"]
            if port_matches:
                return IntentResult(RequestIntent.PORTABILITY, False, 1.0, lang, reasons + ["Portability requested"], refusal_signals + port_matches, retention_exceptions)
            if access_matches:
                return IntentResult(RequestIntent.ACCESS, False, 1.0, lang, reasons + ["Access requested"], refusal_signals + access_matches, retention_exceptions)
            if rect_matches:
                return IntentResult(RequestIntent.RECTIFICATION, False, 1.0, lang, reasons + ["Rectification requested"], refusal_signals + rect_matches, retention_exceptions)
            if opt_matches:
                return IntentResult(RequestIntent.MARKETING_OPTOUT, False, 1.0, lang, reasons + ["Marketing opt-out requested"], refusal_signals + opt_matches, retention_exceptions)
            if recov_matches:
                return IntentResult(RequestIntent.ACCOUNT_RECOVERY, False, 1.0, lang, reasons + ["Account recovery requested"], refusal_signals + recov_matches, retention_exceptions)
            return IntentResult(RequestIntent.AMBIGUOUS, False, 0.9, lang, reasons, refusal_signals, retention_exceptions)

        # Case B: Explicit affirmative deletion requested (with or without retention exceptions)
        if del_signals:
            reasons = [f"Explicit affirmative deletion requested via signal '{del_signals[0]}'"]
            if retention_exceptions:
                reasons.append(f"Retention exceptions preserved: {retention_exceptions}")
            return IntentResult(
                intent=RequestIntent.DELETION,
                is_deletion_authorized=True,
                confidence=1.0,
                detected_language=lang,
                reasons=reasons,
                matched_signals=del_signals,
                retention_exceptions=retention_exceptions,
            )

        # Case C: Only historical deletion mentioned (no affirmative deletion instruction)
        if historical_signals:
            reasons = [f"Historical mention of deletion: '{historical_signals[0]}' (not an affirmative instruction)"]
            if recov_matches:
                return IntentResult(RequestIntent.ACCOUNT_RECOVERY, False, 0.95, lang, reasons + ["Account recovery requested"], historical_signals + recov_matches, retention_exceptions)
            if access_matches:
                return IntentResult(RequestIntent.ACCESS, False, 0.95, lang, reasons + ["Access requested"], historical_signals + access_matches, retention_exceptions)
            if rect_matches:
                return IntentResult(RequestIntent.RECTIFICATION, False, 0.95, lang, reasons + ["Rectification requested"], historical_signals + rect_matches, retention_exceptions)
            return IntentResult(RequestIntent.AMBIGUOUS, False, 0.8, lang, reasons, historical_signals, retention_exceptions)

        # Case D: Specific non-deletion requests
        if port_matches:
            return IntentResult(RequestIntent.PORTABILITY, False, 0.95, lang, ["Data portability requested without deletion"], port_matches, retention_exceptions)
        if access_matches:
            return IntentResult(RequestIntent.ACCESS, False, 0.95, lang, ["Information / copy access requested without deletion"], access_matches, retention_exceptions)
        if rect_matches:
            return IntentResult(RequestIntent.RECTIFICATION, False, 0.95, lang, ["Data correction / update requested without deletion"], rect_matches, retention_exceptions)
        if opt_matches:
            return IntentResult(RequestIntent.MARKETING_OPTOUT, False, 0.95, lang, ["Marketing opt-out requested without deletion"], opt_matches, retention_exceptions)
        if recov_matches:
            return IntentResult(RequestIntent.ACCOUNT_RECOVERY, False, 0.95, lang, ["Account recovery / login assistance requested without deletion"], recov_matches, retention_exceptions)

        # Case E: Ambiguous wording
        return IntentResult(
            intent=RequestIntent.AMBIGUOUS,
            is_deletion_authorized=False,
            confidence=0.5,
            detected_language=lang,
            reasons=["Ambiguous request text: contains neither deletion nor recognized non-deletion signals"],
            retention_exceptions=retention_exceptions,
        )


@dataclass
class DeletionRule:
    """A policy rule loaded from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


class PolicyEngine:
    """Evaluates deletion policy and rules across customer resources."""

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules_path = rules_path
        self.rules: Dict[str, DeletionRule] = {}
        self.classifier = DeletionIntentClassifier()
        if self.rules_path and self.rules_path.is_file():
            self._load_rules()

    def _load_rules(self) -> None:
        df = pd.read_csv(self.rules_path)
        for _, row in df.iterrows():
            rule = DeletionRule(
                rule_id=str(row["rule_id"]),
                data_category=str(row["data_category"]),
                condition=str(row["condition"]),
                required_action=str(row["required_action"]),
            )
            self.rules[rule.rule_id] = rule

    def classify_intent(self, request_text: str) -> IntentResult:
        """Classify user request intent."""
        return self.classifier.classify(request_text)

    def is_deletion_authorized(self, request_text: str) -> bool:
        """Determine whether request text authorizes deletion."""
        result = self.classifier.classify(request_text)
        return result.is_deletion_authorized
