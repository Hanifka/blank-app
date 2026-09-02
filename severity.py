"""
Single source of truth for Wazuh rule severity.

The app table and the network graph used to classify levels differently, so a
level 4 rule showed as green in the graph and yellow in the table. Everything
now reads from here.
"""

from typing import Dict, List, Tuple

# (label, inclusive min level, inclusive max level, colour, glyph)
SEVERITY_BANDS: List[Tuple[str, int, int, str, str]] = [
    ("Critical", 10, 16, "#ef4444", "🔴"),
    ("High", 7, 9, "#f97316", "🟠"),
    ("Medium", 4, 6, "#eab308", "🟡"),
    ("Low", 1, 3, "#22c55e", "🟢"),
    ("Ignored", 0, 0, "#64748b", "⚪"),
]

SEVERITY_ORDER: List[str] = ["Critical", "High", "Medium", "Low", "Ignored"]

_BY_LABEL: Dict[str, Tuple[str, int, int, str, str]] = {
    band[0]: band for band in SEVERITY_BANDS
}


def get_severity_level(level: int) -> str:
    """Map a Wazuh rule level (0-16) to a severity label."""
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "Ignored"
    for label, low, high, _colour, _glyph in SEVERITY_BANDS:
        if low <= level <= high:
            return label
    return "Critical" if level > 16 else "Ignored"


def get_severity_color(level: int) -> str:
    """Hex colour for a Wazuh rule level."""
    return _BY_LABEL[get_severity_level(level)][3]


def get_severity_glyph(level: int) -> str:
    """Emoji marker for a Wazuh rule level."""
    return _BY_LABEL[get_severity_level(level)][4]


def color_for_label(label: str) -> str:
    """Hex colour for a severity label."""
    return _BY_LABEL.get(label, _BY_LABEL["Ignored"])[3]


def band_range(label: str) -> str:
    """Human readable level range for a severity label, e.g. '10-16'."""
    band = _BY_LABEL.get(label)
    if not band:
        return ""
    _, low, high, _c, _g = band
    return str(low) if low == high else f"{low}-{high}"


def node_size(level: int) -> float:
    """Marker size that grows with severity so hot rules read first."""
    try:
        level = max(0, min(16, int(level)))
    except (TypeError, ValueError):
        level = 0
    return 14.0 + level * 1.6
