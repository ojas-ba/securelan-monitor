"""
Simulation mode is intentionally disabled for this hardware-only build.
This file exists only to preserve the expected project structure.
"""


def disabled() -> None:
    raise RuntimeError("Simulation mode is disabled. Use hardware mode only.")
