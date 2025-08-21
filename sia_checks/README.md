# CyberArk Secure Infrastructure Access (SIA) Network Connectivity Checker

This PowerShell script validates network connectivity to the CyberArk SaaS platform and ensures proper network configuration according to CyberArk Secure Infrastructure Access documentation. The script tests connectivity to required endpoints and detects potential issues with packet inspection, SSL termination, or other network security tools that may interfere with CyberArk SIA functionality.

## What It Does

The script performs comprehensive network validation for CyberArk SaaS connectivity by:

- **Testing TCP Connectivity**: Validates that required ports (443) are accessible to CyberArk endpoints
- **Detecting Packet Inspection**: Identifies corporate firewalls, proxy servers, or network security tools that may interfere with encrypted communication
- **SSL Certificate Analysis**: Checks for certificate replacement or manipulation by network security devices
- **Network Path Validation**: Analyzes connection patterns to detect potential traffic interception
- **Compliance Verification**: Ensures network configuration aligns with CyberArk SIA requirements

### Tested Endpoints

The script validates connectivity to the following CyberArk and AWS services:

1. **AWS S3 Global**: `https://s3.amazonaws.com`
2. **AWS S3 Regional**: `https://s3.[region].amazonaws.com`
3. **CyberArk Tenant**: `https://[tenant-name].cyberark.cloud`
4. **AWS IoT Core**: `https://a2m4b3cupk8nzj-ats.iot.[region].amazonaws.com`

### Packet Inspection Detection

The script employs multiple detection methods to identify network interference:

- **Certificate Authority Analysis**: Detects corporate/proxy certificates from known security vendors
- **HTTP Header Inspection**: Identifies headers injected by network security tools
- **TLS Handshake Timing**: Analyzes connection patterns for inspection indicators
- **Connection Consistency**: Tests for network path manipulation

Supported detection for these network security tools:
- Zscaler
- BlueCoat/Symantec
- Forcepoint
- McAfee Web Gateway
- Palo Alto Networks
- Fortinet
- SonicWall
- Check Point
- Cisco
- Sophos
- And many others

## Prerequisites

- **PowerShell 5.1 or higher**
- **Network connectivity** to internet endpoints
- **Administrator privileges** (recommended for comprehensive testing)

## Configuration

### config.json Setup

Before running the script, configure the `config.json` file with your CyberArk environment details:

```json
{
    "tenant_name": "your-tenant-name",
    "aws_region": "us-east-1"
}
```

#### Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `tenant_name` | Your CyberArk SaaS tenant name (the subdomain in your CyberArk URL) | `"mycompany"` for `mycompany.cyberark.cloud` |
| `aws_region` | AWS region where your CyberArk SaaS tenant is hosted | `"us-east-1"`, `"eu-west-1"`, `"ap-southeast-2"` |

#### Finding Your Configuration Values

**Tenant Name:**
- Look at your CyberArk login URL: `https://[TENANT-NAME].cyberark.cloud`
- The tenant name is the subdomain before `.cyberark.cloud`

**AWS Region:**
- This is typically provided by CyberArk during tenant provisioning
- Common regions: `us-east-1` (N. Virginia), `us-west-2` (Oregon), `eu-west-1` (Ireland)
- Contact your CyberArk administrator if unsure

## Usage

### Basic Usage

```powershell
.\NetworkCheck.ps1
```

### Advanced Usage

```powershell
# Use custom configuration file
.\NetworkCheck.ps1 -ConfigPath "production-config.json"

# Specify custom log file location
.\NetworkCheck.ps1 -LogPath "C:\Logs\cyberark-connectivity.log"

# Use both custom config and log paths
.\NetworkCheck.ps1 -ConfigPath "prod-config.json" -LogPath "prod-test.log"
```

### Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `-ConfigPath` | Path to JSON configuration file | `config.json` | No |
| `-LogPath` | Path to output log file | `endpoint_test.log` | No |

## Output and Results

### Console Output

The script provides real-time feedback with color-coded messages:
- 🟢 **Green**: Successful connections and passed tests
- 🟡 **Yellow**: Warnings and detected issues
- 🔴 **Red**: Failures and critical problems
- ⚪ **White**: Informational messages

### Results Table

After testing, the script displays a comprehensive results table:

```
Endpoint                                               Status TCP  PacketInspection InspectionTool FailureReason
--------                                               ------ ---  ---------------- -------------- -------------
https://s3.amazonaws.com                              PASS   Pass None             None          
https://s3.us-east-1.amazonaws.com                    PASS   Pass None             None          
https://mycompany.cyberark.cloud                      PASS   Pass None             None          
https://a2m4b3cupk8nzj-ats.iot.us-east-1.amazonaws.com PASS   Pass None             None          
```

### Log File

All test results are logged to the specified log file with timestamps for audit and troubleshooting purposes.

## Interpreting Results

### Success Indicators
- ✅ **Status: PASS** - Endpoint is reachable with no interference detected
- ✅ **TCP: Pass** - Port 443 is accessible
- ✅ **PacketInspection: None** - No network interference detected

### Failure Indicators
- ❌ **Status: FAIL** - Connectivity or security issue detected
- ❌ **TCP: Fail** - Port 443 is blocked or unreachable
- ❌ **PacketInspection: DETECTED** - Network security tool interference found

### Common Issues and Solutions

#### Port Blocking
**Symptom**: `TCP: Fail`
**Solution**: Work with network administrators to open port 443 for the listed endpoints

#### Packet Inspection Detection
**Symptom**: `PacketInspection: DETECTED`
**Solution**: Configure network security tools to bypass inspection for CyberArk endpoints

#### Certificate Replacement
**Symptom**: Certificate-related warnings in logs
**Solution**: Add CyberArk domains to security tool bypass lists

## Troubleshooting

### Common Error Messages

1. **"Configuration file not found"**
   - Ensure `config.json` exists in the script directory
   - Verify the path if using `-ConfigPath` parameter

2. **"TCP port 443 not reachable"**
   - Check firewall rules
   - Verify internet connectivity
   - Confirm DNS resolution for endpoints

3. **"Network packet inspection detected"**
   - Review corporate security policies
   - Configure security tools to bypass CyberArk traffic
   - Consult with network security team

### Debug Mode

For additional troubleshooting information, examine the log file for detailed connection attempts and error messages.

## Security Considerations

- The script does not transmit sensitive data
- All tests use standard HTTPS connectivity checks
- Certificate information is analyzed locally
- No authentication credentials are required or stored

## Support

For CyberArk SIA-specific network requirements, consult:
- CyberArk Secure Infrastructure Access documentation
- CyberArk Support Portal
- Your organization's CyberArk administrator

## Exit Codes

- **0**: All tests passed successfully
- **1**: One or more tests failed or packet inspection detected

## Version Requirements

- PowerShell 5.1+ (specified in script header)
- Windows PowerShell or PowerShell Core
- .NET Framework (for SSL/TLS operations)

---

*This script is designed to validate CyberArk SaaS connectivity requirements. Ensure you have appropriate permissions to run network tests in your environment.*