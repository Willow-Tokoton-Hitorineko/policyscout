"""Validate region identifiers before searches or filesystem writes."""
import re

def validate_region(value):
    if not isinstance(value, str) or not re.fullmatch(r"[\w ·（）()-]{1,80}", value) or not value.strip():
        raise ValueError("Region must be a plain city/province name")
    return value
