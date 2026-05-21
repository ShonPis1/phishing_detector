# Phishing Message Detection System

A multi-layer classifier that analyzes text messages (SMS / email / chat) and detects phishing attempts.

## How It Works

The system uses **three detection layers**:

### Layer 1 — Rule-based regex (offline)
Scans the text against keyword lists grouped by severity:

| Level | Points | Criteria |
|-------|--------|----------|
| HIGH  | 3 | Urgent language, Suspicious URL, Credential request, Spoofed sender |
| MED   | 2 | Reward/prize, Threat/fear, Impersonation, Generic greeting |
| LOW   | 1 | Grammar errors (regex), Spelling errors (spellchecker), Excessive CAPS |

### Layer 2 — Spellchecker (offline)
Uses `pyspellchecker` to detect misspelled English words - a common sign of phishing messages written by non-native speakers or auto-generated text

### Layer 3 — PhishTank URL check (online, optional)
Extracts all URLs from the message and checks each one against [PhishTank](https://www.phishtank.com/), a public database of confirmed phishing URLs. If a URL is confirmed, it adds 3 points (HIGH). Falls back if there is no internet connection.

---

### Risk Score → Verdict

| Score | Result | Risk Level |
|-------|--------|------------|
| 0 | CLEAN | None |
| 1–2 | SUSPICIOUS | Low |
| 3–5 | SUSPICIOUS | Medium |
| 6+ | PHISHING | High |

A message is classified as **PHISHING** (score ≥ 6) only when multiple criteria fire together - no single signal is enough on its own

---

## Requirements

- Python 3.8 or higher
- `pyspellchecker` for spelling detection (optional but recommended)

```bash
pip install pyspellchecker
```

If not installed, the system still works - the spellcheck criterion is skipped

---

## Installation

```bash
git clone https://github.com/<YOUR_USERNAME>/phishing-detector.git
cd phishing-detector
pip install pyspellchecker
```

---

## Usage

### Interactive mode (type or paste a message)
```bash
cd code
python main.py
```

### Analyze a message directly
```bash
python main.py -m "Your account will be suspended. Verify at http://paypa1.com"
```

### Analyze a text file
```bash
python main.py -f ../examples/en_high_paypal.txt
```

### Run all demo examples (17 messages)
```bash
python main.py --demo
```

---

## Example Output

```
====================================================
  RESULT     : PHISHING
  RISK LEVEL : High
  SCORE      : 16
====================================================
  TRIGGERED CRITERIA:
    [HIGH +3]  Urgent language
               → "your account will be suspended immediately"
    [HIGH +3]  Suspicious URL
               → "http://paypa1-secure.com/login"
    [HIGH +3]  Credential request
               → "Enter your password and credit card"
    [MED  +2]  Impersonation
               → "your PayPal account"
    [LOW  +1]  Spelling errors (spellchecker)
               → "Misspelled: recieve, credntials"
====================================================
```

---

## Project Structure

```
phishing-detector/
├── code/
│   ├── main.py          # CLI entry point
│   └── detector.py      # Detection engine (regex + spellcheck + PhishTank)
├── examples/            # 17 test messages (English + Hebrew)
├── docs/
│   └── phishing_research.docx
└── README.md
```

---

## Limitations

The current system has known limitations that are inherent to rule-based detection:

- **Keyword lists are finite** — there are thousands of companies that could be impersonated; the lists cover the most common ones but cannot be exhaustive.
- **AI-generated phishing text** — attackers increasingly use LLMs to write grammatically perfect messages with no spelling errors, bypassing both the regex and spellcheck layers.
- **No behavioral analysis** — the system analyzes text only; it cannot inspect actual URLs, attachments, or sender metadata.
- **PhishTank coverage** — only URLs already reported and confirmed by the community are flagged; new phishing URLs will be missed until reported.

---

## Future Improvements

| Improvement | Description |
|-------------|-------------|
| **Domain reputation API** | Integrate Google Safe Browsing or VirusTotal to check URLs against broader threat intelligence databases |
| **ML classifier** | Use a pre-trained transformer model (e.g. from HuggingFace) fine-tuned on phishing datasets for semantic understanding beyond keyword matching |
| **Sender analysis** | Parse email headers to detect domain spoofing, SPF/DKIM failures |
| **Multilingual spellcheck** | Extend spellcheck to Hebrew and other languages |
| **Real-time URL scanning** | Follow redirects and inspect the final destination page |
| **Feedback loop** | Allow users to report false positives/negatives to improve the model over time |
