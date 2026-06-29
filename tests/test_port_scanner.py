"""Tests for port scanner module."""

from unittest.mock import MagicMock, patch

from port_scanner import COMMON_PORTS, _scan_with_socket, scan_ports


class TestPortScanner:
    @patch("port_scanner._nmap_available", return_value=False)
    @patch("port_scanner._scan_with_socket")
    def test_fallback_to_socket(self, mock_socket_scan, mock_nmap_check):
        mock_socket_scan.return_value = {
            "success": True,
            "method": "socket",
            "ports": [{"port": 80, "state": "open", "service": "http"}],
            "error": None,
        }

        result = scan_ports("127.0.0.1")

        assert result["success"] is True
        assert result["method"] == "socket"
        mock_socket_scan.assert_called_once_with("127.0.0.1")

    @patch("port_scanner.socket.socket")
    def test_socket_scan_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        with patch("port_scanner._nmap_available", return_value=False):
            result = _scan_with_socket("127.0.0.1", timeout=0.1)

        assert result["success"] is True
        open_ports = [p for p in result["ports"] if p["state"] == "open"]
        assert len(open_ports) > 0

    def test_common_ports_defined(self):
        assert 22 in COMMON_PORTS
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert len(COMMON_PORTS) == 16
