"""
Run every test file (no capture, no admin rights needed).

Run:  python tests/run_all.py
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ["test_parser.py", "test_capture.py", "test_analyzer.py"]

failed = []
total = 0
for name in FILES:
    result = subprocess.run([sys.executable, os.path.join(HERE, name)], capture_output=True, text=True)
    passed = result.stdout.count("[PASS]")
    total += passed
    status = "ok" if result.returncode == 0 else "FAILED"
    print(f"{name:<20} {passed:3} checks passed  {status}")
    if result.returncode != 0:
        failed.append(name)
        print(result.stdout + result.stderr)

print(f"\n{total} checks passed" + (f"; FAILED: {', '.join(failed)}" if failed else ", all test files OK"))
sys.exit(1 if failed else 0)
