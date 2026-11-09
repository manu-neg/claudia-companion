"""Test support: an empty TOML config file that passes the C16 checks.

Tests point `PDASH_CONFIG` at it instead of at a missing path, because a
named-but-missing config file makes every service refuse to start (I6).
"""

from __future__ import annotations

import os
from pathlib import Path


def write_empty_config(directory: Path) -> Path:
    """Write an empty 0600 `config.toml` in a fresh 0700 dir under `directory`; return it.

    Passes `verify_config` when the tests run as root (as CI does); all
    settings then come from field defaults and explicit env/kwargs.
    """
    conf_dir = directory / "empty-config"
    conf_dir.mkdir(mode=0o700)
    config = conf_dir / "config.toml"
    config.write_text("")
    os.chmod(config, 0o600)
    return config
