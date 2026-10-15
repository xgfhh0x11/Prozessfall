"""Path resolution for transition-era scripts.

Reads config.toml from project root. Top-level scripts import directly;
prokaryotes/ subdir scripts add parent to sys.path first.

Will be replaced by Tauri app data dir resolution in Phase 1+ (daemon).
"""

try:
    import tomllib  # stdlib, Python 3.11+
except ImportError:
    import tomli as tomllib  # 3.10 fallback

from pathlib import Path

_HERE = Path(__file__).resolve().parent

with open(_HERE / "config.toml", "rb") as f:
    _cfg = tomllib.load(f)

PROZESSFALL_DB = Path(_cfg["paths"]["prozessfall_db"])
PROKARYOTES_DB = Path(_cfg["paths"]["prokaryotes_db"])
PROKARYOTES_BIN = Path(_cfg["paths"]["prokaryotes_bin"])
