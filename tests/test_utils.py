import os
import sys

# Ensure repo root is on path so tests can import finder
ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from finder import norm, likely_roll_field


def test_norm_basic():
    assert norm("  HAll  TICKET\t") == "hall ticket"
    assert norm("Àccênts  ") == "àccênts"


def test_likely_roll_field_scores():
    # name that looks like a roll field should score higher than a generic name
    score_roll = likely_roll_field("rollno", "text", "", "")
    score_name = likely_roll_field("name", "text", "", "")
    assert score_roll > score_name
