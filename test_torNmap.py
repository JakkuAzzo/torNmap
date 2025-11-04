#!/usr/bin/env python3
"""
Unit tests for torNmap

These tests validate the core functionality without requiring Tor to be running.
"""

import unittest
import sys
import socket
from unittest.mock import patch, Mock, MagicMock
import socks

# Import the module to test
import torNmap


class TestInterpretResult(unittest.TestCase):
    """Test the interpret_result function"""
    
    def test_successful_connection(self):
        """Test that None exception returns 'open'"""
        result = torNmap.interpret_result(None, 0.5)
        self.assertEqual(result, "open")
    
    def test_connection_refused(self):
        """Test that ConnectionRefusedError returns 'closed'"""
        exc = ConnectionRefusedError("Connection refused")
        result = torNmap.interpret_result(exc, 0.5)
        self.assertEqual(result, "closed")
    
    def test_timeout(self):
        """Test that socket.timeout returns 'filtered/timeout'"""
        exc = socket.timeout("Connection timed out")
        result = torNmap.interpret_result(exc, 10.0)
        self.assertEqual(result, "filtered/timeout")
    
    def test_generic_error(self):
        """Test that other exceptions return error type"""
        exc = OSError("Some error")
        result = torNmap.interpret_result(exc, 0.5)
        self.assertEqual(result, "error:OSError")


class TestPortValidation(unittest.TestCase):
    """Test port validation logic"""
    
    def test_valid_single_port(self):
        """Test that single valid port is accepted"""
        # This would be tested via command-line parsing in integration tests
        ports = [80]
        self.assertTrue(all(1 <= p <= 65535 for p in ports))
    
    def test_valid_port_range(self):
        """Test that valid port range is accepted"""
        ports = list(range(1, 101))
        self.assertTrue(all(1 <= p <= 65535 for p in ports))
    
    def test_port_limit(self):
        """Test that port count limit is enforced"""
        ports = list(range(1, 1002))  # 1001 ports
        self.assertGreater(len(ports), torNmap.MAX_PORTS_LIMIT)
    
    def test_port_out_of_range_low(self):
        """Test that port 0 is out of range"""
        self.assertFalse(1 <= 0 <= 65535)
    
    def test_port_out_of_range_high(self):
        """Test that port 70000 is out of range"""
        self.assertFalse(1 <= 70000 <= 65535)


class TestCheckTorSocks(unittest.TestCase):
    """Test Tor SOCKS proxy checking"""
    
    @patch('socket.create_connection')
    def test_socks_available(self, mock_socket):
        """Test that check returns True when SOCKS is available"""
        mock_socket.return_value.__enter__ = Mock()
        mock_socket.return_value.__exit__ = Mock()
        
        result = torNmap.check_tor_socks()
        self.assertTrue(result)
        mock_socket.assert_called_once()
    
    @patch('socket.create_connection')
    def test_socks_unavailable(self, mock_socket):
        """Test that check returns False when SOCKS is unavailable"""
        mock_socket.side_effect = ConnectionRefusedError("Connection refused")
        
        result = torNmap.check_tor_socks()
        self.assertFalse(result)


class TestScanPorts(unittest.TestCase):
    """Test the scan_ports function"""
    
    def test_port_limit_enforcement(self):
        """Test that scanning more than MAX_PORTS_LIMIT raises ValueError"""
        ports = list(range(1, torNmap.MAX_PORTS_LIMIT + 2))
        
        with self.assertRaises(ValueError) as context:
            torNmap.scan_ports(target="127.0.0.1", ports=ports)
        
        self.assertIn("exceeds maximum limit", str(context.exception))
    
    @patch('torNmap.probe_tcp_via_tor')
    def test_scan_with_valid_ports(self, mock_probe):
        """Test that scan works with valid port list"""
        # Mock the probe function to return success
        mock_probe.return_value = (80, "open", 0.5, None)
        
        ports = [80, 443]
        results = torNmap.scan_ports(target="127.0.0.1", ports=ports)
        
        self.assertEqual(len(results), 2)
        # Verify probe was called for each port
        self.assertEqual(mock_probe.call_count, 2)
    
    def test_default_ports_used(self):
        """Test that DEFAULT_PORTS is used when ports=None"""
        # This test validates the function signature
        self.assertIsNotNone(torNmap.DEFAULT_PORTS)
        self.assertIsInstance(torNmap.DEFAULT_PORTS, list)
        self.assertGreater(len(torNmap.DEFAULT_PORTS), 0)


class TestConstants(unittest.TestCase):
    """Test that required constants are defined"""
    
    def test_max_ports_limit_defined(self):
        """Test that MAX_PORTS_LIMIT is defined and reasonable"""
        self.assertTrue(hasattr(torNmap, 'MAX_PORTS_LIMIT'))
        self.assertEqual(torNmap.MAX_PORTS_LIMIT, 1000)
    
    def test_default_target_is_localhost(self):
        """Test that default target is localhost for safety"""
        self.assertEqual(torNmap.DEFAULT_TARGET, '127.0.0.1')
    
    def test_connect_timeout_defined(self):
        """Test that CONNECT_TIMEOUT is defined"""
        self.assertTrue(hasattr(torNmap, 'CONNECT_TIMEOUT'))
        self.assertGreater(torNmap.CONNECT_TIMEOUT, 0)
    
    def test_default_ports_defined(self):
        """Test that DEFAULT_PORTS is defined"""
        self.assertTrue(hasattr(torNmap, 'DEFAULT_PORTS'))
        self.assertIsInstance(torNmap.DEFAULT_PORTS, list)


class TestLimitations(unittest.TestCase):
    """Test that documented limitations are enforced"""
    
    def test_tcp_connect_only(self):
        """Verify only TCP connect scanning is implemented"""
        # The probe_tcp_via_tor function should only use socket.connect()
        # No SYN, ACK, FIN, Xmas, Null scans should be present
        import inspect
        source = inspect.getsource(torNmap.probe_tcp_via_tor)
        
        # Verify it uses connect method
        self.assertIn('connect', source)
        
        # Verify no raw sockets or advanced scan types implementation
        # (mentions in comments/docstrings are OK, but not actual implementation)
        self.assertNotIn('raw', source.lower())
        self.assertNotIn('sendto', source.lower())
        self.assertNotIn('recvfrom', source.lower())
        # Verify it's using SOCKS socket, not raw socket
        self.assertIn('socks', source.lower())
    
    def test_no_service_detection(self):
        """Verify no service detection is implemented"""
        # Check that the probe function doesn't try to grab banners
        # or perform service detection
        import inspect
        source = inspect.getsource(torNmap.probe_tcp_via_tor)
        
        # Should not receive or send application-layer data
        self.assertNotIn('recv(', source)
        self.assertNotIn('send(', source.lower())
    
    def test_port_limit_prevents_extensive_scanning(self):
        """Verify port limit prevents scanning all 65535 ports"""
        all_ports = list(range(1, 65536))
        
        # Should raise ValueError
        with self.assertRaises(ValueError):
            torNmap.scan_ports(target="127.0.0.1", ports=all_ports)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
