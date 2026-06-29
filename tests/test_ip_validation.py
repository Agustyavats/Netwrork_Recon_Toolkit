"""Tests for host validation."""

import pytest

from utils.validators import is_private_ip, validate_target


class TestValidateTarget:
    def test_valid_ipv4(self):
        result = validate_target("8.8.8.8")
        assert result["valid"] is True
        assert result["type"] == "ipv4"
        assert result["target"] == "8.8.8.8"

    def test_valid_ipv6(self):
        result = validate_target("2001:4860:4860::8888")
        assert result["valid"] is True
        assert result["type"] == "ipv6"

    def test_valid_domain(self):
        result = validate_target("example.com")
        assert result["valid"] is True
        assert result["type"] == "domain"
        assert result["target"] == "example.com"

    def test_domain_strips_trailing_dot(self):
        result = validate_target("example.com.")
        assert result["valid"] is True
        assert result["target"] == "example.com"

    def test_invalid_input(self):
        result = validate_target("not a valid target!!!")
        assert result["valid"] is False
        assert result["error"] is not None

    def test_empty_input(self):
        result = validate_target("")
        assert result["valid"] is False

    def test_none_input(self):
        result = validate_target(None)
        assert result["valid"] is False


class TestIsPrivateIP:
    def test_private_ip(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_invalid_ip(self):
        assert is_private_ip("invalid") is False
