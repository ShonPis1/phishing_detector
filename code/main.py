#!/usr/bin/env python3
# This line called shebang line, it tells the operating system to use python3 to run this file
# on linux/ mac it allows running the file directly with ./main.py instead of python3 main.py
# on Windows it does nothing but it kept as a standard convention -____- delete this documentation before sending the code
"""
Phishing Message Detection System - main.py (entry point)

A rule-based classifier that analyzes any text message
(SMS, email, chat) and determines whether it is a
phishing attempt
"""

import argparse
import sys
import os
from detector import PhishingDetector

BANNER = """

╔══════════════════════════════════════════════════╗
║     PHISHING MESSAGE DETECTION SYSTEM            ║
║     Rule-based classifier · HIGH/MED/LOW         ║
╚══════════════════════════════════════════════════╝
"""

DEMO_FILES = [
    # English - High risk
    ("EN · High  · PayPal phishing",          "en_high_paypal.txt"),
    ("EN · High  · Bank + legal threat",      "en_high_bank.txt"),
    ("EN · High  · Microsoft credential",     "en_high_microsoft.txt"),
    ("EN · High  · IRS scam",                 "en_high_irs.txt"),
    # English - Medium risk
    ("EN · Med   · Prize scam",               "en_medium_prize.txt"),
    ("EN · Med   · Account threat",           "en_medium_threat.txt"),
    ("EN · Med   · Google impersonation",     "en_medium_impersonation.txt"),
    # English - Low risk
    ("EN · Low   · Excessive CAPS",           "en_low_caps.txt"),
    ("EN · Low   · Grammar errors",           "en_low_grammar.txt"),
    # English - Clean
    ("EN · Clean · Casual message",           "en_clean_1.txt"),
    ("EN · Clean · Appointment reminder",     "en_clean_2.txt"),
    # Hebrew - High risk
    ("HE · High  · Bank phishing",            "he_high_bank.txt"),
    ("HE · High  · Tax authority scam",       "he_high_tax.txt"),
    ("HE · High  · Insurance phishing",       "he_high_insurance.txt"),
    # Hebrew - Medium risk
    ("HE · Med   · Prize scam",               "he_medium_prize.txt"),
    ("HE · Med   · Account threat",           "he_medium_threat.txt"),
    # Hebrew - Clean
    ("HE · Clean · Casual message",           "he_clean.txt"),
]


def get_examples_dir() -> str:
    """Return the path to the examples/ directory relative to this file"""
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "..", "examples")


def load_example(filename: str) -> str:
    """Loads a message from the examples directory."""
    path = os.path.join(get_examples_dir(), filename)
    if not os.path.exists(path):
        return f"[File not found: {filename}]"
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def run_demo(detector: PhishingDetector):
    """Run all demo examples loaded from the examples/ directory."""
    total = len(DEMO_FILES)
    score_distribution = {"High": 0, "Medium": 0, "Low": 0, "None": 0}

    print(f"\n{'━' * 52}")
    print(f"  DEMO MODE — {total} example messages")
    print(f"{'━' * 52}")

    for i, (label, filename) in enumerate(DEMO_FILES, 1):
        msg = load_example(filename)
        result = detector.analyze(msg)
        score_distribution[result.risk_level] += 1

        print(f"\n[{i}/{total}] {label}  ({filename})")
        preview = msg[:90].replace("\n", " ") + ("..." if len(msg) > 90 else "")
        print(f'  Message: "{preview}"')
        print(result.summary())

    # Score distribution summary
    print(f"\n{'━' * 52}")
    print("  SCORE DISTRIBUTION ACROSS ALL EXAMPLES")
    print(f"{'━' * 52}")
    for level in ["High", "Medium", "Low", "None"]:
        bar = "█" * score_distribution[level]
        print(f"  {level:<8} : {bar} ({score_distribution[level]})")
    print(f"{'━' * 52}\n")


def run_interactive(detector: PhishingDetector):
    print(BANNER)
    print("Paste or type a message to analyze.")
    print("Press ENTER twice when done. Type 'quit' to exit.\n")

    while True:
        print("─" * 52)
        print("Enter message:")
        lines = []
        try:
            while True:
                line = input()
                if line.strip().lower() == "quit":
                    print("Goodbye.")
                    sys.exit(0)
                if line == "" and lines:
                    break
                lines.append(line)
        except EOFError:
            sys.exit(0)

        text = "\n".join(lines).strip()
        if not text:
            continue

        result = detector.analyze(text)
        print()
        print(result.summary())
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--message", help="Analyze a single message string")
    parser.add_argument("-f", "--file",    help="Analyze message from a text file")
    parser.add_argument("--demo", action="store_true", help="Run built in demo examples")
    args = parser.parse_args()

    detector = PhishingDetector()

    if args.demo:
        print(BANNER)
        run_demo(detector)

    elif args.message:
        print(BANNER)
        result = detector.analyze(args.message)
        print(result.summary())

    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: file '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
        print(BANNER)
        print(f"Analyzing file: {args.file}\n")
        result = detector.analyze(text)
        print(result.summary())

    else:
        run_interactive(detector)


if __name__ == "__main__":
    main()
