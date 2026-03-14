# This file ensures pytest can resolve the src module from the project root.

import os
import sys

ROOT = os.path.dirname(__file__)
SRC_DIR = os.path.join(ROOT, "src")

# Ensure the project root and src directory are on sys.path for imports.
for p in (ROOT, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)
