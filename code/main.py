#!/usr/bin/env python3
"""
Phishing Message Detection System
main.py — CLI entry point

Usage:
    python main.py                  # interactive mode
    python main.py -f message.txt   # analyze a text file
    python main.py -m "your text"   # analyze inline message
    python main.py --demo           # run built-in demo examples
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from detector import PhishingDetector

BANNER = """
╔══════════════════════════════════════════════════╗
║     PHISHING MESSAGE DETECTION SYSTEM  v1.0      ║
║     Rule-based classifier · HIGH/MED/LOW         ║
╚══════════════════════════════════════════════════╝
"""

DEMO_MESSAGES = [
    (
        "High-risk phishing (PayPal)",
        "Dear Customer, your PayPal account has been suspended. "
        "Verify your details immediately at http://paypa1-secure.com/login "
        "or your account will be terminated within 24 hours. "
        "Enter your password and credit card to restore access."
    ),
    (
        "Medium-risk suspicious (prize scam)",
        "Congratulations! You have won a $500 Amazon gift card. "
        "Click here to claim your prize: https://bit.ly/win500now"
    ),
    (
        "Low-risk (generic greeting only)",
        "Dear valued customer, we wanted to update you about our new service terms. "
        "Please review them at your convenience on our official website."
    ),
    (
        "Clean message",
        "Hey, are we still meeting tomorrow at 10am? "
        "Let me know if you need to reschedule."
    ),
    (
        "Hebrew phishing (SMS)",
        "שלום לקוח יקר, חשבונך יינעל תוך 24 שעות. "
        "אנא הזן את סיסמתך ומספר תעודת זהות בקישור: "
        "http://192.168.1.55/bank/verify"
    ),
]


def run_demo(detector: PhishingDetector):
    print("\n" + "━" * 52)
    print("  DEMO MODE — 5 example messages")
    print("━" * 52)
    for i, (label, msg) in enumerate(DEMO_MESSAGES, 1):
        print(f"\n[{i}/5] {label}")
        preview = msg[:90] + ("..." if len(msg) > 90 else "")
        print(f'  Message: "{preview}"')
        result = detector.analyze(msg)
        print(result.summary())


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
    parser = argparse.ArgumentParser(
        description="Phishing Message Detection System"
    )
    parser.add_argument("-m", "--message", help="Analyze a single message string")
    parser.add_argument("-f", "--file",    help="Analyze message from a text file")
    parser.add_argument("--demo", action="store_true", help="Run built-in demo examples")
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
