"""Tests for RPC execute helpers."""

from msf_harness.mcp.rpc.execute import _coerce_option, _payload_needs_lhost


def test_coerce_integer_options():
    assert _coerce_option("THREADS", "10") == 10
    assert _coerce_option("RPORT", "9021") == 9021
    assert _coerce_option("RHOSTS", "10.0.0.1") == "10.0.0.1"


def test_payload_needs_lhost():
    assert _payload_needs_lhost("generic/shell_reverse_tcp") is True
    assert _payload_needs_lhost("cmd/linux/http/x86/shell/reverse_tcp") is True
    assert _payload_needs_lhost("cmd/unix/bind_perl") is False
