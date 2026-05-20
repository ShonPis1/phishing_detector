# Phishing Message Detection System

A rule-based classifier that analyzes text messages (SMS / email / chat) and detects phishing attempts.

## How It Works

The system scans the input text against **10 detection criteria** grouped by severity:

| Level | Points | Criteria |
|-------|--------|----------|
| HIGH  | 3 | Urgent language, Suspicious URL, Credential request, Spoofed sender |
| MED   | 2 | Reward/prize, Threat/fear, Impersonation, Generic greeting |
| LOW   | 1 | Grammar errors, Excessive CAPS/exclamation |

### Risk Score → Verdict

| Score | Verdict | Risk Level |
|-------|---------|------------|
| 0 | CLEAN | None |
| 1–2 | SUSPICIOUS | Low |
| 3–5 | SUSPICIOUS | Medium |
| 6+ | PHISHING | High |

A message is classified as **PHISHING** (score ≥ 6) only when multiple criteria fire together — no single signal is enough on its own.

For each match the system reports the **exact snippet** from the message that triggered the rule.

---

## Requirements

- Python 3.8 or higher
- No external dependencies — uses only the Python standard library

---

## Installation

```bash
git clone https://github.com/<YOUR_USERNAME>/phishing-detector.git
cd phishing-detector
```

No `pip install` needed.

---

## Usage

### Interactive mode (type or paste a message)
```bash
python main.py
```

### Analyze a message directly
```bash
python main.py -m "Your account will be suspended. Verify at http://paypa1.com"
```

### Analyze a text file
```bash
python main.py -f examples/example_high.txt
```

### Run built-in demo (5 examples)
```bash
python main.py --demo
```

---

## Example Output

```
====================================================
  RESULT    : PHISHING
  RISK LEVEL : High
  SCORE      : 9
====================================================
  TRIGGERED CRITERIA:
    [HIGH +3]  Urgent language
               → "your account will be suspended immediately"
    [HIGH +3]  Suspicious URL
               → "http://paypa1-secure.com/login"
    [HIGH +3]  Credential request
               → "Enter your password and credit card"
====================================================
```

---

## Project Structure

```
phishing-detector/
├── main.py              # CLI entry point
├── src/
│   └── detector.py      # Detection engine + criteria
├── examples/
│   ├── example_high.txt
│   ├── example_medium.txt
│   ├── example_low.txt
│   ├── example_clean.txt
│   └── example_hebrew.txt
├── docs/
│   └── research.md      # Research document
└── README.md
```
