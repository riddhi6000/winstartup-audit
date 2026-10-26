import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PAGE = (PROJECT_ROOT / "static" / "index.html").read_text(encoding="utf-8")


def test_server_placeholders_each_appear_exactly_once():
    assert PAGE.count("__WINAUDIT_TOKEN__") == 1
    assert PAGE.count("__CSP_NONCE__") == 1


def test_page_loads_nothing_from_outside_and_has_no_inline_handlers():
    assert not re.search(r"<link\b", PAGE)
    assert not re.search(r"<script[^>]*\bsrc=", PAGE)
    assert not re.search(r"https?://", PAGE)
    assert not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", PAGE, re.IGNORECASE)


def test_the_only_script_carries_the_nonce():
    scripts = re.findall(r"<script\b[^>]*>", PAGE)

    assert scripts == ['<script nonce="__CSP_NONCE__">']


def test_table_is_labelled_for_screen_readers():
    assert "<caption" in PAGE
    assert PAGE.count('scope="col"') == 7
    assert "<main>" in PAGE
    assert 'aria-live="polite"' in PAGE


def test_every_form_control_has_a_label():
    controls = ["attentionOnly", "sourceFilter", "verificationFilter", "searchBox"]
    for control in controls:
        assert f'id="{control}"' in PAGE
    assert PAGE.count("<label") >= len(controls)


def test_filters_and_sortable_columns_exist():
    assert 'data-key="score"' in PAGE
    assert 'data-key="source"' in PAGE
    assert 'data-key="name"' in PAGE
    assert 'id="attentionOnly" checked' in PAGE  # the default view hides unflagged rows


def test_keyboard_focus_is_visible():
    assert ":focus-visible" in PAGE


def test_page_has_no_colour_only_statuses():
    # statuses are always written out (NEW, CHANGED, "not verified", the score itself)
    for text in ("NEW", "CHANGED", "not verified", "partly verified"):
        assert text in PAGE
