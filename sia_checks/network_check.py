#!/usr/bin/env python3
"""
CyberArk SIA Network Connectivity Checker for Linux
Tests network connectivity and HTTPS validation for CyberArk SaaS endpoints
Detects potential packet inspection, encryption, or termination by third parties.
"""

import argparse
import json
import logging
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Check for required dependencies
REQUIRED_PACKAGES = {
    'requests': 'python3-requests',
    'urllib3': 'python3-urllib3'
}

MISSING_PACKAGES = []

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
except ImportError:
    MISSING_PACKAGES.extend(['requests', 'urllib3'])

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# Color codes for console output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class NetworkChecker:
    def __init__(self, config_path: str = "config.json", log_path: str = "endpoint_test.log"):
        self.config_path = config_path
        self.log_path = log_path
        self.logger = self._setup_logging()
        
        # Known corporate/NGFW certificate authorities and patterns
        self.corporate_cas = [
            "BlueCoat", "Zscaler", "Forcepoint", "McAfee", "Symantec Web Security",
            "Corporate", "Proxy", "Firewall", "Gateway", "Palo Alto", "Fortinet",
            "SonicWall", "Check Point", "Cisco", "Barracuda", "WatchGuard",
            "Sophos", "Trend Micro", "Websense", "ContentKeeper", "Lightspeed"
        ]
        
        # Known inspection tool headers (more specific patterns to avoid false positives)
        self.inspection_headers = {
            "X-Zscaler-": "Zscaler",
            "X-BlueCoat-": "BlueCoat", 
            "X-Forcepoint-": "Forcepoint",
            "X-McAfee-": "McAfee",
            "X-Sophos-": "Sophos",
            "X-Fortinet-": "Fortinet",
            "X-SonicWall-": "SonicWall",
            "X-Palo-Alto-": "Palo Alto",
            "X-Check-Point-": "Check Point",
            "X-Websense-": "Websense",
            "X-Cisco-": "Cisco",
            "X-Proxy-Connection": "Generic Proxy",
            "X-Corporate-": "Corporate Proxy"
            # Removed "X-Forwarded-" and "Via" as they have legitimate uses
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging to both file and console"""
        logger = logging.getLogger('network_checker')
        logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(self.log_path)
        file_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger

    def log_message(self, message: str, level: str = "INFO"):
        """Write message to log and console with color coding"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Console output with colors
        color_map = {
            "ERROR": Colors.RED,
            "WARN": Colors.YELLOW,
            "PASS": Colors.GREEN,
            "FAIL": Colors.RED,
            "INFO": Colors.WHITE
        }
        
        color = color_map.get(level, Colors.WHITE)
        print(f"{color}{log_entry}{Colors.ENDC}")
        
        # Log to file
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.log(log_level, message)

    def test_tcp_connection(self, hostname: str, port: int = 443, timeout: int = 5) -> bool:
        """Test TCP connectivity to hostname:port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.log_message(f"TCP test error for {hostname}:{port}: {str(e)}", "INFO")
            return False

    def get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Get SSL certificate information for hostname"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                cert = ssock.getpeercert()
                
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'serialNumber': cert.get('serialNumber', ''),
                    'notBefore': cert.get('notBefore', ''),
                    'notAfter': cert.get('notAfter', ''),
                    'version': cert.get('version', ''),
                    'subjectAltName': cert.get('subjectAltName', [])
                }
        except Exception as e:
            self.log_message(f"Certificate retrieval failed for {hostname}: {str(e)}", "INFO")
            return None

    def analyze_certificate(self, hostname: str, cert_info: Dict) -> Tuple[bool, str, List[str]]:
        """Analyze certificate for signs of interception"""
        details = []
        inspection_detected = False
        inspection_tool = "None"
        
        if not cert_info:
            return False, "None", []
        
        # Check issuer for corporate CAs
        issuer_org = cert_info.get('issuer', {}).get('organizationName', '')
        issuer_cn = cert_info.get('issuer', {}).get('commonName', '')
        subject_org = cert_info.get('subject', {}).get('organizationName', '')
        
        full_issuer = f"{issuer_org} {issuer_cn}".strip()
        
        for ca in self.corporate_cas:
            if ca.lower() in full_issuer.lower() or ca.lower() in subject_org.lower():
                inspection_detected = True
                inspection_tool = ca
                details.append(f"Certificate issued by corporate CA: {full_issuer}")
                self.log_message(f"DETECTION: Certificate replacement by {ca} detected", "WARN")
                break
        
        # Removed the overly restrictive AWS/CyberArk specific certificate checks
        # These were causing false positives by expecting specific certificate patterns
        # that may vary based on CDN configuration, certificate rotation, etc.
        
        return inspection_detected, inspection_tool, details

    def analyze_http_headers(self, hostname: str) -> Tuple[bool, str, List[str]]:
        """Analyze HTTP headers for inspection tool signatures"""
        details = []
        inspection_detected = False
        inspection_tool = "None"
        
        try:
            session = requests.Session()
            session.verify = False  # Allow invalid certificates for header analysis
            
            # Set a reasonable timeout
            response = session.head(f"https://{hostname}", timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Check for known inspection tool headers (only specific corporate security tools)
            for header_name, header_value in headers.items():
                for pattern, tool in self.inspection_headers.items():
                    if pattern.lower() in header_name.lower():
                        inspection_detected = True
                        inspection_tool = tool
                        details.append(f"Suspicious header detected: {header_name}")
                        self.log_message(f"DETECTION: Inspection tool header found: {header_name}", "WARN")
                        break
                
                if inspection_detected:
                    break
                    
        except Exception as e:
            self.log_message(f"Header analysis failed for {hostname}: {str(e)}", "INFO")
        
        return inspection_detected, inspection_tool, details

    def analyze_tls_handshake(self, hostname: str, port: int = 443) -> Tuple[bool, List[str]]:
        """Analyze TLS handshake timing for inspection indicators"""
        details = []
        inspection_detected = False
        
        try:
            context = ssl.create_default_context()
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                handshake_time = (time.time() - start_time) * 1000  # Convert to ms
                
                self.log_message(f"TLS handshake time: {handshake_time:.2f}ms", "INFO")
                
                # Only flag extremely slow handshakes (increased threshold)
                if handshake_time > 5000:  # Increased from 2000ms to 5000ms
                    inspection_detected = True
                    details.append(f"Unusually long TLS handshake: {handshake_time:.2f}ms")
                    self.log_message("DETECTION: Extremely slow TLS handshake suggests inspection", "WARN")
                
        except Exception as e:
            self.log_message(f"TLS analysis failed for {hostname}: {str(e)}", "INFO")
        
        return inspection_detected, details

    def analyze_connection_timing(self, hostname: str, port: int = 443, attempts: int = 3) -> Tuple[bool, List[str]]:
        """Analyze connection timing consistency"""
        details = []
        inspection_detected = False
        connection_times = []
        
        for i in range(attempts):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((hostname, port))
                connection_time = (time.time() - start_time) * 1000
                connection_times.append(connection_time)
                sock.close()
                time.sleep(0.1)  # Brief pause between attempts
            except Exception:
                self.log_message(f"Connection attempt {i+1} failed for {hostname}", "INFO")
        
        if len(connection_times) > 1:
            avg_time = sum(connection_times) / len(connection_times)
            max_time = max(connection_times)
            min_time = min(connection_times)
            
            self.log_message(f"Average connection time: {avg_time:.2f}ms", "INFO")
            
            # Only flag very inconsistent connection times (increased threshold)
            if max_time - min_time > 1000:  # Increased from 500ms to 1000ms
                inspection_detected = True
                details.append("Very inconsistent connection times suggest network inspection")
                self.log_message("DETECTION: Very inconsistent connection times", "WARN")
        
        return inspection_detected, details

    def test_packet_inspection(self, hostname: str, port: int = 443) -> Dict:
        """Comprehensive packet inspection detection"""
        inspection_result = {
            'CertificateReplacement': False,
            'SuspiciousHeaders': False,
            'TLSFingerprint': False,
            'NetworkInterception': False,
            'InspectionTool': "None",
            'Details': []
        }
        
        try:
            # Method 1: Certificate Analysis
            self.log_message(f"Analyzing SSL certificate for {hostname}", "INFO")
            cert_info = self.get_ssl_certificate(hostname, port)
            cert_inspection, cert_tool, cert_details = self.analyze_certificate(hostname, cert_info)
            
            if cert_inspection:
                inspection_result['CertificateReplacement'] = True
                inspection_result['NetworkInterception'] = True
                inspection_result['InspectionTool'] = cert_tool
                inspection_result['Details'].extend(cert_details)
            
            # Method 2: HTTP Header Analysis
            self.log_message(f"Analyzing HTTP headers for {hostname}", "INFO")
            header_inspection, header_tool, header_details = self.analyze_http_headers(hostname)
            
            if header_inspection:
                inspection_result['SuspiciousHeaders'] = True
                inspection_result['NetworkInterception'] = True
                if inspection_result['InspectionTool'] == "None":
                    inspection_result['InspectionTool'] = header_tool
                inspection_result['Details'].extend(header_details)
            
            # Method 3: TLS Handshake Analysis
            self.log_message(f"Analyzing TLS handshake for {hostname}", "INFO")
            tls_inspection, tls_details = self.analyze_tls_handshake(hostname, port)
            
            if tls_inspection:
                inspection_result['TLSFingerprint'] = True
                inspection_result['NetworkInterception'] = True
                inspection_result['Details'].extend(tls_details)
            
            # Method 4: Connection Timing Analysis
            self.log_message(f"Performing network path analysis for {hostname}", "INFO")
            timing_inspection, timing_details = self.analyze_connection_timing(hostname, port)
            
            if timing_inspection:
                inspection_result['NetworkInterception'] = True
                inspection_result['Details'].extend(timing_details)
                
        except Exception as e:
            self.log_message(f"Packet inspection analysis failed for {hostname}: {str(e)}", "WARN")
        
        return inspection_result

    def test_network_endpoint(self, url: str) -> Dict:
        """Test endpoint with comprehensive packet inspection detection"""
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        result = {
            'Endpoint': url,
            'TCPConnectivity': False,
            'PacketInspectionDetected': False,
            'InspectionTool': "None",
            'Status': "FAIL",
            'FailureReason': "",
            'InspectionDetails': []
        }
        
        self.log_message(f"Testing endpoint: {url}", "INFO")
        
        # Test TCP connectivity
        result['TCPConnectivity'] = self.test_tcp_connection(hostname, 443)
        
        if not result['TCPConnectivity']:
            result['FailureReason'] = "TCP port 443 not reachable"
            self.log_message(f"TCP connectivity failed for {hostname}", "FAIL")
            return result
        
        self.log_message(f"TCP connectivity successful for {hostname}", "PASS")
        
        # Perform comprehensive packet inspection detection
        inspection_result = self.test_packet_inspection(hostname)
        
        if inspection_result['NetworkInterception']:
            result['PacketInspectionDetected'] = True
            result['InspectionTool'] = inspection_result['InspectionTool']
            result['InspectionDetails'] = inspection_result['Details']
            result['Status'] = "FAIL"
            result['FailureReason'] = f"Network packet inspection detected by {inspection_result['InspectionTool']}"
            self.log_message(f"PACKET INSPECTION DETECTED for {hostname} by {inspection_result['InspectionTool']}", "FAIL")
        else:
            result['Status'] = "PASS"
            self.log_message(f"No packet inspection detected for {hostname}", "PASS")
        
        return result

    def load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            required_keys = ['tenant_name', 'aws_region']
            for key in required_keys:
                if key not in config:
                    raise ValueError(f"Missing required configuration key: {key}")
            
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {str(e)}")

    def print_results_table(self, results: List[Dict]):
        """Print results in a formatted table"""
        print()
        self.log_message("=== NETWORK ENDPOINT TEST RESULTS ===", "INFO")
        
        # Calculate column widths
        headers = ["Endpoint", "Status", "TCP", "PacketInspection", "InspectionTool", "FailureReason"]
        widths = [len(h) for h in headers]
        
        for result in results:
            widths[0] = max(widths[0], len(result['Endpoint']))
            widths[1] = max(widths[1], len(result['Status']))
            widths[2] = max(widths[2], len("Pass" if result['TCPConnectivity'] else "Fail"))
            widths[3] = max(widths[3], len("DETECTED" if result['PacketInspectionDetected'] else "None"))
            widths[4] = max(widths[4], len(result['InspectionTool']))
            widths[5] = max(widths[5], len(result['FailureReason']))
        
        # Print header
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
        print(header_line)
        print("-" * len(header_line))
        
        # Print data rows
        for result in results:
            row_data = [
                result['Endpoint'].ljust(widths[0]),
                result['Status'].ljust(widths[1]),
                ("Pass" if result['TCPConnectivity'] else "Fail").ljust(widths[2]),
                ("DETECTED" if result['PacketInspectionDetected'] else "None").ljust(widths[3]),
                result['InspectionTool'].ljust(widths[4]),
                result['FailureReason'].ljust(widths[5])
            ]
            print(" | ".join(row_data))

    def run_tests(self) -> int:
        """Main test execution function"""
        try:
            self.log_message("Starting endpoint connectivity tests", "INFO")
            self.log_message(f"Log file: {self.log_path}", "INFO")
            
            # Load configuration
            config = self.load_config()
            self.log_message(f"Configuration loaded from {self.config_path}", "INFO")
            self.log_message(f"Tenant Name: {config['tenant_name']}", "INFO")
            self.log_message(f"AWS Region: {config['aws_region']}", "INFO")
            
            # Define endpoints to test
            endpoints = [
                "https://s3.amazonaws.com",
                f"https://s3.{config['aws_region']}.amazonaws.com",
                f"https://{config['tenant_name']}.cyberark.cloud",
                f"https://a2m4b3cupk8nzj-ats.iot.{config['aws_region']}.amazonaws.com"
            ]
            
            # Test all endpoints
            results = []
            for endpoint in endpoints:
                test_result = self.test_network_endpoint(endpoint)
                results.append(test_result)
                time.sleep(0.5)  # Brief pause between tests
            
            # Display results
            self.print_results_table(results)
            
            # Summary
            pass_count = len([r for r in results if r['Status'] == 'PASS'])
            fail_count = len([r for r in results if r['Status'] == 'FAIL'])
            inspection_count = len([r for r in results if r['PacketInspectionDetected']])
            
            self.log_message("=== SUMMARY ===", "INFO")
            self.log_message(f"Total Endpoints: {len(results)}", "INFO")
            self.log_message(f"Passed: {pass_count}", "INFO")
            self.log_message(f"Failed: {fail_count}", "INFO")
            self.log_message(f"Packet Inspection Detected: {inspection_count}", "INFO")
            
            if inspection_count > 0:
                self.log_message(f"WARNING: Network packet inspection detected on {inspection_count} endpoint(s)", "WARN")
                self.log_message("Your network traffic may be monitored by corporate security tools", "WARN")
            
            if fail_count > 0:
                self.log_message("Some endpoints failed validation. Check logs for details.", "WARN")
                return 1
            else:
                self.log_message("All endpoints passed connectivity tests with no packet inspection detected.", "PASS")
                return 0
                
        except Exception as e:
            self.log_message(f"Script execution failed: {str(e)}", "ERROR")
            return 1

def check_dependencies():
    """Check for required Python packages"""
    if MISSING_PACKAGES:
        print(f"{Colors.RED}ERROR: Missing required Python packages{Colors.ENDC}")
        print(f"{Colors.YELLOW}Missing packages: {', '.join(MISSING_PACKAGES)}{Colors.ENDC}")
        print(f"{Colors.WHITE}Please install the missing packages:{Colors.ENDC}")
        
        # Provide installation commands for different package managers
        print(f"\n{Colors.BOLD}Ubuntu/Debian:{Colors.ENDC}")
        for package in MISSING_PACKAGES:
            if package in REQUIRED_PACKAGES:
                print(f"  sudo apt-get install {REQUIRED_PACKAGES[package]}")
        
        print(f"\n{Colors.BOLD}RHEL/CentOS/Amazon Linux:{Colors.ENDC}")
        for package in MISSING_PACKAGES:
            if package in REQUIRED_PACKAGES:
                rhel_package = REQUIRED_PACKAGES[package].replace('python3-', 'python3-')
                print(f"  sudo yum install {rhel_package}")
        
        print(f"\n{Colors.BOLD}Using pip:{Colors.ENDC}")
        pip_packages = [p for p in MISSING_PACKAGES if p not in ['urllib3']]  # urllib3 comes with requests
        if pip_packages:
            print(f"  pip3 install {' '.join(pip_packages)}")
        
        return False
    return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Tests network connectivity and HTTPS validation for CyberArk SaaS endpoints'
    )
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Path to JSON configuration file (default: config.json)'
    )
    parser.add_argument(
        '--log', '-l',
        default='endpoint_test.log',
        help='Path to log file (default: endpoint_test.log)'
    )
    
    args = parser.parse_args()
    
    # Check dependencies before running
    if not check_dependencies():
        sys.exit(1)
    
    # Run the network tests
    checker = NetworkChecker(args.config, args.log)
    exit_code = checker.run_tests()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()