from __future__ import annotations

import os
from pathlib import Path

PROFILE_FAST = ["virustotal", "dnsdumpster", "ctlogs", "netcraft", "c99"]
PROFILE_BRUTE = ["bruteforce"]
PROFILE_MIXED = PROFILE_FAST + PROFILE_BRUTE

PROFILES = {
    "fast": PROFILE_FAST,
    "brute": PROFILE_BRUTE,
    "mixed": PROFILE_MIXED,
}


def load_dotenv(path: str | Path = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
