"""Tests for DNS lookup module."""

from unittest.mock import MagicMock, patch

import dns.resolver

from dns_lookup import lookup_dns, reverse_dns


class TestLookupDNS:
    @patch("dns_lookup.dns.resolver.Resolver")
    def test_successful_a_record(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_rr = MagicMock()
        mock_rr.__str__ = MagicMock(return_value="93.184.216.34")

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return [mock_rr]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        result = lookup_dns("example.com")

        assert result["success"] is True
        assert "93.184.216.34" in result["records"]["A"]

    @patch("dns_lookup.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = lookup_dns("nonexistent.invalid")

        assert result["success"] is False
        assert len(result["errors"]) > 0


class TestReverseDNS:
    @patch("dns_lookup.dns.resolver.Resolver")
    def test_successful_reverse(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve_address.return_value = ["dns.google."]

        result = reverse_dns("8.8.8.8")

        assert result["success"] is True
        assert result["hostname"] == "dns.google"

    @patch("dns_lookup.dns.resolver.Resolver")
    def test_no_reverse_record(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve_address.side_effect = dns.resolver.NXDOMAIN()

        result = reverse_dns("8.8.8.8")

        assert result["success"] is False
        assert result["hostname"] is None
