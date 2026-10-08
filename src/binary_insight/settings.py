"""Configuration shared by CLI, UI, and tracing."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(os.getenv("BINARY_STUDIO_HOME", str(Path.cwd()))).expanduser().resolve()
load_dotenv(ROOT / ".env")
WEB = ROOT / "web" if (ROOT / "web").is_dir() else Path(__file__).parent / "web"
PRICING = ROOT / "config" / "pricing.json"
if not PRICING.exists():
    PRICING = Path(__file__).parent / "pricing.json"


def positive_float(name: str, default: float) -> float:
    value = float(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value
