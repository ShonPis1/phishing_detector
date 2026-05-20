"""
Phishing Message Detection System
detector.py — Core detection engine

Criteria weights:
  HIGH = 3 points
  MED  = 2 points
  LOW  = 1 point

Risk levels:
  0       → CLEAN
  1–2     → SUSPICIOUS (Low)
  3–5     → SUSPICIOUS (Medium)
  6+      → PHISHING (High)
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Match:
    criterion: str
    level: str      # HIGH / MED / LOW
    points: int
    evidence: str   # the snippet that triggered the rule


@dataclass
class DetectionResult:
    result: str          # PHISHING / SUSPICIOUS / CLEAN
    risk_level: str       # High / Medium / Low / None
    score: int
    matches: List[Match] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=" * 52,
            f"  RESULT    : {self.result}",
            f"  RISK LEVEL : {self.risk_level}",
            f"  SCORE      : {self.score}",
            "=" * 52,
        ]
        if self.matches:
            lines.append("  TRIGGERED CRITERIA:")
            for m in self.matches:
                lines.append(f"    [{m.level:4s} +{m.points}]  {m.criterion}")
                lines.append(f"             → \"{m.evidence[:80]}\"")
        else:
            lines.append("  No suspicious patterns detected.")
        lines.append("=" * 52)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Keyword lists
# ---------------------------------------------------------------------------

URGENT_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires?\b",
    r"\bwithin 24 hours?\b", r"\bwithin \d+ hours?\b", r"\bdeadline\b",
    r"\bלאלתר\b", r"\bמיידי(?:ת)?\b", r"\bדחוף\b", r"\bתוך 24 שעות\b",
    r"\bחשבונך יינעל\b", r"\bפעולה נדרשת\b",
]

SUSPICIOUS_URL_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP-based URL
    r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.link)/\S+",  # URL shorteners
    r"[a-z0-9\-]+(?:0|1|3|4|@)[a-z0-9\-]+\.[a-z]{2,}",  # typosquatting (digit/@ in domain)
    r"(?:[a-z]+\.){3,}[a-z]{2,}",                        # excessive subdomains
    r"https?://[^\s]*-(?:secure|login|verify|update|account)[^\s]*",  # suspicious path keywords
    r"https?://[^\s]*(?:paypal|amazon|google|microsoft|apple|bank)[^\s]*\.[a-z]{2,}(?!\.[a-z])",
]

CREDENTIAL_KEYWORDS = [
    r"\bpassword\b", r"\bpin\b", r"\bcredit card\b", r"\bcard number\b",
    r"\bcvv\b", r"\bssn\b", r"\bsocial security\b", r"\bbank account\b",
    r"\bverify your (?:account|identity|information|details)\b",
    r"\benter your (?:details|credentials|information|password|pin)\b",
    r"\bסיסמ[הא]\b", r"\bפרטי כרטיס\b", r"\bמספר תעודת זהות\b",
    r"\bקוד אימות\b", r"\bOTP\b",
]

SPOOFED_SENDER_PATTERNS = [
    # email address where display name contains a known brand but domain doesn't match
    r"(?:paypal|amazon|google|microsoft|apple|facebook|instagram|bank)\s*[<(][^>)]*@(?!paypal\.com|amazon\.com|google\.com|microsoft\.com|apple\.com|facebook\.com|instagram\.com)",
    r"@[a-z0-9\-]*(?:paypa1|amaz0n|g00gle|micros0ft|app1e)[a-z0-9\-]*\.",
]

REWARD_KEYWORDS = [
    r"\byou(?:'ve| have) won\b", r"\bcongratulations?\b", r"\bprize\b",
    r"\bgift card\b", r"\bclaim your\b", r"\bfree (?:iphone|gift|reward|money|cash)\b",
    r"\b\$\s*\d{3,}\b",   # large dollar amounts
    r"\bזכית\b", r"\bפרס\b", r"\bכרטיס מתנה\b", r"\bחינם\b",
]

FEAR_KEYWORDS = [
    r"\blegal action\b", r"\blawsuit\b", r"\bpolice\b", r"\barrest\b",
    r"\bsuspended?\b", r"\bblocked?\b", r"\bterminated?\b",
    r"\bfailure to (?:comply|verify|respond)\b",
    r"\bחסום\b", r"\bהושעה\b", r"\bתביעה משפטית\b", r"\bמשטרה\b",
]

IMPERSONATION_KEYWORDS = [
    r"\b(?:paypal|amazon|google|microsoft|apple|facebook|instagram)\b",
    r"\b(?:bank of america|chase|wells fargo|citibank|barclays)\b",
    r"\b(?:irs|fbi|interpol|government|federal)\b",
    r"\b(?:בנק לאומי|בנק הפועלים|דיסקונט|מזרחי טפחות)\b",
    r"\b(?:רשות המסים|ביטוח לאומי|משרד הפנים)\b",
    r"\bsecurity team\b", r"\bsupport team\b", r"\bcustomer service\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear (?:customer|user|client|account holder|member|valued customer)\b",
    r"\bhello (?:customer|user|client)\b",
    r"\bשלום (?:לקוח|משתמש|חבר)\b",
    r"\bלקוח יקר\b",
]

GRAMMAR_ERROR_PATTERNS = [
    r"\b\w+ed\s+\w+ed\b",           # double past tense
    r"\bis\s+been\b",               # "is been"
    r"\bare\s+been\b",
    r"\bplease\s+to\s+\w+\b",       # "please to click"
    r"\byour\s+account\s+is\s+(?:compromized|comprimised|suspendid|deactiveted)\b",
    r"\bcompromized\b", r"\bcompromised\b",  # common misspellings
    r"\bverfiy\b", r"\bverifiy\b", r"\bverrify\b",
    r"\bimmidiately\b", r"\burgant\b",
]

EXCESSIVE_CAPS_THRESHOLD = 0.35  # >35% uppercase letters = suspicious
EXCESSIVE_EXCLAMATION_COUNT = 3   # 3+ exclamation marks


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _find_first(patterns: List[str], text: str, flags=re.IGNORECASE) -> str:
    """Return the first matching snippet, or empty string."""
    for pat in patterns:
        m = re.search(pat, text, flags)
        if m:
            start = max(0, m.start() - 15)
            end = min(len(text), m.end() + 15)
            return text[start:end].strip()
    return ""


def _check_excessive_caps(text: str) -> str:
    """Return evidence string if excessive caps/exclamation detected."""
    letters = [c for c in text if c.isalpha()]
    exclamations = text.count("!")
    if letters and (sum(1 for c in letters if c.isupper()) / len(letters)) > EXCESSIVE_CAPS_THRESHOLD:
        upper_words = [w for w in text.split() if w.isupper() and len(w) > 2]
        return " ".join(upper_words[:5]) if upper_words else "HIGH CAPS RATIO"
    if exclamations >= EXCESSIVE_EXCLAMATION_COUNT:
        idx = text.find("!")
        return text[max(0, idx-20):idx+20].strip()
    return ""


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class PhishingDetector:

    def analyze(self, text: str) -> DetectionResult:
        matches: List[Match] = []

        # --- HIGH criteria ---

        evidence = _find_first(URGENT_KEYWORDS, text)
        if evidence:
            matches.append(Match("Urgent language", "HIGH", 3, evidence))

        evidence = _find_first(SUSPICIOUS_URL_PATTERNS, text)
        if evidence:
            matches.append(Match("Suspicious URL", "HIGH", 3, evidence))

        evidence = _find_first(CREDENTIAL_KEYWORDS, text)
        if evidence:
            matches.append(Match("Credential request", "HIGH", 3, evidence))

        evidence = _find_first(SPOOFED_SENDER_PATTERNS, text)
        if evidence:
            matches.append(Match("Spoofed sender domain", "HIGH", 3, evidence))

        # --- MED criteria ---

        evidence = _find_first(REWARD_KEYWORDS, text)
        if evidence:
            matches.append(Match("Reward / prize", "MED", 2, evidence))

        evidence = _find_first(FEAR_KEYWORDS, text)
        if evidence:
            matches.append(Match("Threat / fear", "MED", 2, evidence))

        evidence = _find_first(IMPERSONATION_KEYWORDS, text)
        if evidence:
            matches.append(Match("Impersonation", "MED", 2, evidence))

        evidence = _find_first(GENERIC_GREETING_PATTERNS, text)
        if evidence:
            matches.append(Match("Generic greeting", "MED", 2, evidence))

        # --- LOW criteria ---

        evidence = _find_first(GRAMMAR_ERROR_PATTERNS, text)
        if evidence:
            matches.append(Match("Grammar / spelling errors", "LOW", 1, evidence))

        evidence = _check_excessive_caps(text)
        if evidence:
            matches.append(Match("Excessive CAPS / exclamation", "LOW", 1, evidence))

        # --- Score & classify ---
        score = sum(m.points for m in matches)

        if score == 0:
            result, risk_level = "CLEAN", "None"
        elif score <= 2:
            result, risk_level = "SUSPICIOUS", "Low"
        elif score <= 5:
            result, risk_level = "SUSPICIOUS", "Medium"
        else:
            result, risk_level = "PHISHING", "High"

        return DetectionResult(result=result, risk_level=risk_level,
                               score=score, matches=matches)
