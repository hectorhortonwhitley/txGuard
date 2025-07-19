import json
import sys
import re
from pathlib import Path

PATTERN_FILE = Path(__file__).parent / "patterns.json"


def load_patterns():
    with open(PATTERN_FILE) as f:
        return json.load(f)


def analyze_transaction(tx_path):
    with open(tx_path) as f:
        tx = json.load(f)

    patterns = load_patterns()
    warnings = []

    # Проверка на нулевой адрес
    if tx.get("to", "").lower() == "0x0000000000000000000000000000000000000000":
        warnings.append("🚨 Sending to zero address!")

    # Подозрительный газ
    gas = int(tx.get("gas", "0x0"), 16)
    if gas > 10_000_000:
        warnings.append(f"⚠️ Unusually high gas limit: {gas}")

    # Анализ данных
    data = tx.get("data", "")
    for pattern in patterns.get("malicious_patterns", []):
        if re.search(pattern["regex"], data, re.IGNORECASE):
            warnings.append(f"🔴 Matched malicious pattern: {pattern['description']}")

    if not warnings:
        print("✅ Transaction appears clean.")
    else:
        print("⚠️ Suspicious transaction detected:")
        for w in warnings:
            print("  -", w)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <tx_json_file>")
    else:
        analyze_transaction(sys.argv[1])
