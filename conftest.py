import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT, "src")

for p in [ROOT, SRC_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)
