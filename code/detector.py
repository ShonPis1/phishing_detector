"""
The core detection engine (detector.py) scans the input text
against 10 criteria

Score → Risk level:
  0          →  CLEAN
  1–2        →  SUSPICIOUS  (Low)
  3–5        →  SUSPICIOUS  (Medium)
  6+         →  PHISHING    (High)
"""

import re
import urllib.request
import urllib.parse
import json

# ----------- pyspellchecker ------------
try:
    from spellchecker import SpellChecker
    _spell = SpellChecker()
    SPELLCHECK_AVAILABLE = True
except ImportError:
    SPELLCHECK_AVAILABLE = False


# ----- PhishTank URL check - checks URLs in the message against PhishTank's known phishing database
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"


def _check_phishtank(url: str) -> bool:
    """Return True if PhishTank confirms this URL is a known phishing site."""
    try:
        data = urllib.parse.urlencode({
            "url": url,
            "format": "json",
            "app_key": ""
        }).encode()
        req = urllib.request.Request(
            PHISHTANK_API, data=data,
            headers={"User-Agent": "phishing-detector/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            return result.get("results", {}).get("in_database", False) and \
                   result.get("results", {}).get("valid", False)
    except Exception:
        return False  # offline or API unavailable


def _extract_urls(text: str) -> list:
    """Extract all URLs from the text."""
    return re.findall(r"https?://[^\s]+", text, re.IGNORECASE)


def _check_spelling(text: str) -> str:
    """
    Use pyspellchecker to find misspelled words
    Returns a snippet with the misspelled words or empty string if none found
    Skips short words, numbers, and Hebrew text
    """
    if not SPELLCHECK_AVAILABLE:
        return ""
    # Only check English words (skip Hebrew, numbers, short words)
    words = re.findall(r"[a-zA-Z]{4,}", text)
    if not words:
        return ""
    misspelled = _spell.unknown(words)
    # Filter out words that are likely proper nouns (capitalized) or technical terms
    misspelled = {w for w in misspelled if w.islower()}
    if misspelled:
        return "Misspelled: " + ", ".join(list(misspelled)[:5])
    return ""


# ------------------------ Data structures -------------------------
class Match:
    def __init__(self, criterion, level, points, evidence):
        self.criterion = criterion
        self.level = level        # HIGH / MED / LOW
        self.points = points
        self.evidence = evidence  # the snippet that triggered the rule


class DetectionResult:
    def __init__(self, result, risk_level, score, matches=None):
        self.result = result
        self.risk_level = risk_level
        self.score = score
        self.matches = matches if matches is not None else []

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


# ------------------------------ Keyword lists ----------------------------
URGENT_KEYWORDS = [
    # English
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires?\b",
    r"\bwithin 24 hours?\b", r"\bwithin \d+ hours?\b", r"\bdeadline\b",
    r"\baction required\b", r"\byour account (?:will be|has been) (?:suspended|locked|blocked|terminated)\b",
    r"\blast chance\b", r"\bresponse required\b", r"\btime(?:\s+is)?\s+running out\b",
    r"\bdo not ignore\b", r"\bfinal (?:notice|warning|reminder)\b",
    r"\bimportant notice\b", r"\bcritical alert\b", r"\bsecurity alert\b",
    r"\byour (?:account|access) (?:expires?|will expire)\b",
    # Hebrew
    r"לאלתר", r"מיידי(?:ת)?", r"דחוף", r"תוך 24 שעות",
    r"חשבונך יינעל", r"פעולה נדרשת", r"הודעה דחופה",
    r"נדרשת פעולה", r"חשבונך הושעה", r"חשבונך יחסם",
    r"אזהרה אחרונה", r"התראה אחרונה",
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
    # English
    r"\bpassword\b", r"\bpin\b", r"\bcredit card\b", r"\bcard number\b",
    r"\bcvv\b", r"\bssn\b", r"\bsocial security\b", r"\bbank account\b",
    r"\bverify your (?:account|identity|information|details)\b",
    r"\benter your (?:details|credentials|information|password|pin)\b",
    r"\bconfirm your (?:identity|details|information|account)\b",
    r"\bupdate your (?:details|information|payment|billing)\b",
    r"\bprovide your (?:details|credentials|information)\b",
    r"\baccount (?:number|details|credentials)\b",
    r"\bexpiration date\b", r"\bexpiry date\b",
    r"\bdate of birth\b", r"\bpassport number\b",
    r"\bsecurity (?:code|question|answer)\b",
    r"\bone.?time.?(?:password|code|pin)\b", r"\bOTP\b",
    r"\bverification code\b", r"\bauthentication code\b",
    # Hebrew
    r"סיסמ[הא]", r"פרטי כרטיס", r"מספר תעודת זהות",
    r"קוד אימות", r"קוד חד פעמי", r"פרטי חשבון",
    r"מספר כרטיס", r"תאריך תפוגה", r"הזן את פרטיך",
    r"אמת את זהותך", r"עדכן את פרטיך",
]

SPOOFED_SENDER_PATTERNS = [
    # email address where display name contains a known brand but domain doesn't match
    r"(?:paypal|amazon|google|microsoft|apple|facebook|instagram|bank)\s*[<(][^>)]*@(?!paypal\.com|amazon\.com|google\.com|microsoft\.com|apple\.com|facebook\.com|instagram\.com)",
    r"@[a-z0-9\-]*(?:paypa1|amaz0n|g00gle|micros0ft|app1e)[a-z0-9\-]*\.",
]

REWARD_KEYWORDS = [
    # English
    r"\byou(?:'ve| have) won\b", r"\bcongratulations?\b", r"\bprize\b",
    r"\bgift card\b", r"\bclaim your\b", r"\bfree (?:iphone|gift|reward|money|cash|shipping)\b",
    r"\b\$\s*\d{3,}\b",
    r"\byou(?:'ve| have) been selected\b", r"\byou(?:'ve| have) been chosen\b",
    r"\blucky (?:winner|draw)\b", r"\bspecial (?:offer|reward|bonus)\b",
    r"\bcash (?:prize|reward|back)\b", r"\bno strings attached\b",
    r"\b100%\s*free\b", r"\bguaranteed\b", r"\brisk.?free\b",
    r"\bact before\b", r"\blimited (?:time|offer)\b",
    r"\bclaim (?:now|today|immediately)\b",
    # Hebrew
    r"זכית", r"פרס", r"כרטיס מתנה", r"חינם",
    r"נבחרת", r"הגרלה", r"מבצע מיוחד", r"קבל עכשיו",
]

FEAR_KEYWORDS = [
    # English
    r"\blegal action\b", r"\blawsuit\b", r"\bpolice\b", r"\barrest\b",
    r"\bsuspended?\b", r"\bblocked?\b", r"\bterminated?\b",
    r"\bfailure to (?:comply|verify|respond)\b",
    r"\bprosecution\b", r"\bcriminal (?:charges?|complaint)\b",
    r"\bdebt collector\b", r"\bcollection agency\b",
    r"\baccount (?:closed|disabled|deactivated)\b",
    r"\bunauthorized (?:access|activity|transaction)\b",
    r"\byour (?:data|information) (?:has been|was) (?:compromised|stolen|leaked)\b",
    # Hebrew
    r"חסום", r"הושעה", r"תביעה משפטית", r"משטרה",
    r"עיקול", r"הליך משפטי", r"חוב", r"גבייה",
    r"חשבונך נחסם", r"פעילות חשודה", r"גישה בלתי מורשית",
]

IMPERSONATION_KEYWORDS = [
    # Major tech & finance (English \b works fine)
    r"\b(?:paypal|amazon|google|microsoft|apple|facebook|instagram|netflix|spotify)\b",
    r"\b(?:bank of america|chase|wells fargo|citibank|barclays|hsbc|santander)\b",
    r"\b(?:irs|fbi|interpol|government|federal|homeland security)\b",
    r"\b(?:dhl|fedex|ups|usps|royal mail)\b",
    r"\b(?:whatsapp|telegram|twitter|linkedin|dropbox|adobe)\b",
    r"\bsecurity team\b", r"\bsupport team\b", r"\bcustomer service\b",
    r"\btech support\b", r"\bhelp desk\b", r"\bfraud department\b",
    # Israeli institutions (no \b for Hebrew)
    r"בנק לאומי", r"בנק הפועלים", r"דיסקונט", r"מזרחי טפחות",
    r"בנק יהב", r"בנק אוצר החייל", r"מרכנתיל",
    r"רשות המסים", r"ביטוח לאומי", r"משרד הפנים",
    r"משרד האוצר", r"רשות האוכלוסין", r"המוסד לביטוח לאומי",
    r"בזק", r"הוט", r"סלקום", r"פרטנר", r"019",
]

GENERIC_GREETING_PATTERNS = [
    # English
    r"\bdear (?:customer|user|client|account holder|member|valued customer|subscriber)\b",
    r"\bhello (?:customer|user|client|there)\b",
    r"\bto whom it may concern\b",
    r"\bgreetings?\b",
    # Hebrew
    r"שלום (?:לקוח|משתמש|חבר|מנוי)",
    r"לקוח יקר",
    r"משתמש יקר",
    r"לכבוד הלקוח",
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


# ------------ Helper functions ----------------------

def _find_first(patterns: list, text: str, flags=re.IGNORECASE) -> str:
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


class PhishingDetector:
    def analyze(self, text: str) -> DetectionResult:
        matches = []

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
