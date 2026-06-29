"""Tests for HTTP header retrieval."""

from unittest.mock import MagicMock, patch

from http_headers import SECURITY_HEADERS, get_http_headers


class TestHTTPHeaders:
    @patch("http_headers.requests.get")
    def test_successful_header_fetch(self, mock_get):
        mock_response = MagicMock()
        mock_response.url = "https://example.com"
        mock_response.headers = {
            "Server": "nginx",
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
        }
        mock_get.return_value = mock_response

        result = get_http_headers("example.com")

        assert result["success"] is True
        assert result["headers"]["Server"] == "nginx"
        assert result["headers"]["Content-Type"] == "text/html"
        assert result["headers"]["Content-Security-Policy"] == "Not set"

    @patch("http_headers.requests.get")
    def test_connection_failure(self, mock_get):
        import requests

        mock_get.side_effect = requests.exceptions.ConnectionError()

        result = get_http_headers("unreachable.invalid")

        assert result["success"] is False
        assert result["error"] is not None

    def test_security_headers_list(self):
        assert "Server" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS
        assert len(SECURITY_HEADERS) == 7
