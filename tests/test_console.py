"""Tests for console security: quote escaping and option key validation."""

from __future__ import annotations

import pytest

from msf_harness.mcp.rpc.console import _quote_val, validate_option_key


class TestQuoteVal:
    def test_simple_value_unquoted(self):
        assert _quote_val("RHOSTS") == "RHOSTS"

    def test_value_with_spaces_quoted(self):
        assert _quote_val("hello world") == '"hello world"'

    def test_embedded_quote_escaped(self):
        result = _quote_val('say "hello"')
        assert result == '"say \\"hello\\""'

    def test_embedded_backslash_escaped(self):
        result = _quote_val("path\\to\\file")
        assert result == '"path\\\\to\\\\file"'

    def test_bool_true(self):
        assert _quote_val(True) == "true"

    def test_bool_false(self):
        assert _quote_val(False) == "false"

    def test_integer_passthrough(self):
        assert _quote_val(4444) == "4444"


class TestOptionKeyValidation:
    def test_valid_keys(self):
        for key in ["RHOSTS", "LPORT", "AutoCheck", "PAYLOAD", "TARGET_0"]:
            validate_option_key(key)

    def test_invalid_key_with_spaces(self):
        with pytest.raises(ValueError, match="Invalid option key"):
            validate_option_key("BAD KEY")

    def test_invalid_key_with_semicolon(self):
        with pytest.raises(ValueError, match="Invalid option key"):
            validate_option_key("KEY;DROP")

    def test_invalid_key_starts_with_digit(self):
        with pytest.raises(ValueError, match="Invalid option key"):
            validate_option_key("0INVALID")

    def test_empty_key(self):
        with pytest.raises(ValueError, match="Invalid option key"):
            validate_option_key("")


class TestInjectionPrevention:
    """Tests for MSF console command injection prevention."""

    def test_newline_in_value_escaped(self) -> None:
        result = _quote_val("value\ninjected")
        assert result == '"value\ninjected"'

    def test_null_byte_in_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid option key"):
            validate_option_key("KEY\x00DROP")

    def test_semicolon_in_value_safe(self) -> None:
        assert _quote_val("value;cmd") == '"value;cmd"'
