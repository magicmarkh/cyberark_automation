#Requires -Version 5.1

<#
.SYNOPSIS
    Tests network connectivity and HTTPS validation for specified endpoints
.DESCRIPTION
    This script tests connectivity to AWS S3, CyberArk Cloud, and AWS IoT endpoints
    while detecting potential packet inspection, encryption, or termination by third parties.
.PARAMETER ConfigPath
    Path to the JSON configuration file (default: config.json)
.PARAMETER LogPath
    Path to the log file (default: endpoint_test.log)
.EXAMPLE
    .\Test-NetworkEndpoints.ps1
.EXAMPLE
    .\Test-NetworkEndpoints.ps1 -ConfigPath "custom-config.json" -LogPath "custom.log"
#>

param(
    [string]$ConfigPath = "config.json",
    [string]$LogPath = "endpoint_test.log"
)

# Function to write to log and console
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with color coding
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "PASS"  { Write-Host $logEntry -ForegroundColor Green }
        "FAIL"  { Write-Host $logEntry -ForegroundColor Red }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry
}

# Function to test TCP connectivity
function Test-TCPConnection {
    param(
        [string]$Hostname,
        [int]$Port,
        [int]$TimeoutMs = 5000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)
        $timeoutTask = [System.Threading.Tasks.Task]::Delay($TimeoutMs)
        
        $completedTask = [System.Threading.Tasks.Task]::WaitAny(@($connectTask, $timeoutTask))
        
        if ($completedTask -eq 0 -and $connectTask.IsCompletedSuccessfully) {
            $tcpClient.Close()
            return $true
        } else {
            $tcpClient.Close()
            return $false
        }
    }
    catch {
        return $false
    }
}

# Function to detect packet inspection through multiple methods
function Test-PacketInspection {
    param(
        [string]$Hostname,
        [int]$Port = 443
    )
    
    $inspectionResult = @{
        CertificateReplacement = $false
        SuspiciousHeaders = $false
        TLSFingerprint = $false
        NetworkInterception = $false
        InspectionTool = "None"
        Details = @()
    }
    
    try {
        # Method 1: Certificate Analysis - Check for corporate/proxy certificates
        Write-LogMessage "Analyzing SSL certificate for $Hostname" "INFO"
        $certInfo = Get-SSLCertificate -Hostname $Hostname
        
        if ($certInfo) {
            # Known corporate/NGFW certificate authorities and patterns
            $corporateCAs = @(
                "BlueCoat", "Zscaler", "Forcepoint", "McAfee", "Symantec Web Security",
                "Corporate", "Proxy", "Firewall", "Gateway", "Palo Alto", "Fortinet",
                "SonicWall", "Check Point", "Cisco", "Barracuda", "WatchGuard",
                "Sophos", "Trend Micro", "Websense", "ContentKeeper", "Lightspeed"
            )
            
            foreach ($ca in $corporateCAs) {
                if ($certInfo.Issuer -match $ca -or $certInfo.Subject -match $ca) {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.InspectionTool = $ca
                    $inspectionResult.Details += "Certificate issued by: $($certInfo.Issuer)"
                    Write-LogMessage "DETECTION: Certificate replacement by $ca detected" "WARN"
                    break
                }
            }
            
            # Check for non-standard certificate chains that might indicate interception
            if ($Hostname -match "amazonaws\.com") {
                $expectedIssuers = @("Amazon", "DigiCert", "Symantec", "VeriSign", "GlobalSign")
                $validIssuer = $false
                foreach ($issuer in $expectedIssuers) {
                    if ($certInfo.Issuer -match $issuer) {
                        $validIssuer = $true
                        break
                    }
                }
                if (-not $validIssuer) {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.Details += "Non-AWS certificate for AWS endpoint: $($certInfo.Issuer)"
                }
            }
            elseif ($Hostname -match "cyberark\.cloud") {
                if ($certInfo.Subject -notmatch "cyberark\.cloud" -and $certInfo.Subject -notmatch "\*\.cyberark\.cloud") {
                    $inspectionResult.CertificateReplacement = $true
                    $inspectionResult.NetworkInterception = $true
                    $inspectionResult.Details += "Non-CyberArk certificate for CyberArk endpoint"
                }
            }
        }
        
        # Method 2: HTTP Header Analysis - Check for inspection tool headers
        Write-LogMessage "Analyzing HTTP headers for $Hostname" "INFO"
        try {
            $headers = @{}
            $webRequest = [System.Net.WebRequest]::Create("https://$Hostname")
            $webRequest.Method = "HEAD"
            $webRequest.Timeout = 10000
            
            # Allow certificate errors for header analysis
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            
            try {
                $response = $webRequest.GetResponse()
                $headers = $response.Headers
                $response.Close()
            }
            catch {
                # Even if request fails, we might get headers in the exception
                if ($_.Exception.Response) {
                    $headers = $_.Exception.Response.Headers
                }
            }
            
            # Check for known inspection tool headers
            $inspectionHeaders = @{
                "X-Zscaler-" = "Zscaler"
                "X-BlueCoat-" = "BlueCoat"
                "X-Forcepoint-" = "Forcepoint"
                "X-McAfee-" = "McAfee"
                "X-Sophos-" = "Sophos"
                "X-Fortinet-" = "Fortinet"
                "X-SonicWall-" = "SonicWall"
                "X-Palo-Alto-" = "Palo Alto"
                "X-Check-Point-" = "Check Point"
                "X-Websense-" = "Websense"
                "X-Cisco-" = "Cisco"
                "X-Proxy-" = "Generic Proxy"
                "X-Forwarded-" = "Proxy/Load Balancer"
                "Via" = "Proxy"
            }
            
            foreach ($header in $headers.AllKeys) {
                foreach ($pattern in $inspectionHeaders.Keys) {
                    if ($header -match $pattern) {
                        $inspectionResult.SuspiciousHeaders = $true
                        $inspectionResult.NetworkInterception = $true
                        $inspectionResult.InspectionTool = $inspectionHeaders[$pattern]
                        $inspectionResult.Details += "Suspicious header detected: $header"
                        Write-LogMessage "DETECTION: Inspection tool header found: $header" "WARN"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Header analysis failed for $Hostname`: $($_.Exception.Message)" "INFO"
        }
        
        # Method 3: TLS Handshake Analysis - Check for modified TLS patterns
        Write-LogMessage "Analyzing TLS handshake for $Hostname" "INFO"
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect($Hostname, $Port)
            
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
            
            # Capture TLS negotiation details
            $startTime = Get-Date
            $sslStream.AuthenticateAsClient($Hostname)
            $handshakeTime = (Get-Date) - $startTime
            
            # Check for unusually long handshake times (possible inspection)
            if ($handshakeTime.TotalMilliseconds -gt 2000) {
                $inspectionResult.TLSFingerprint = $true
                $inspectionResult.NetworkInterception = $true
                $inspectionResult.Details += "Unusually long TLS handshake: $($handshakeTime.TotalMilliseconds)ms"
                Write-LogMessage "DETECTION: Slow TLS handshake suggests inspection" "WARN"
            }
            
            # Check TLS version and cipher suite
            $tlsVersion = $sslStream.SslProtocol
            Write-LogMessage "TLS Protocol: $tlsVersion" "INFO"
            
            $sslStream.Close()
            $tcpClient.Close()
        }
        catch {
            Write-LogMessage "TLS analysis failed for $Hostname`: $($_.Exception.Message)" "INFO"
        }
        
        # Method 4: Network Path Analysis - Multiple connection attempts
        Write-LogMessage "Performing network path analysis for $Hostname" "INFO"
        $connectionTimes = @()
        
        for ($i = 1; $i -le 3; $i++) {
            try {
                $startTime = Get-Date
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($Hostname, $Port)
                $connectionTime = (Get-Date) - $startTime
                $connectionTimes += $connectionTime.TotalMilliseconds
                $tcpClient.Close()
                Start-Sleep -Milliseconds 100
            }
            catch {
                Write-LogMessage "Connection attempt $i failed for $Hostname" "INFO"
            }
        }
        
        if ($connectionTimes.Count -gt 0) {
            $avgConnectionTime = ($connectionTimes | Measure-Object -Average).Average
            $maxConnectionTime = ($connectionTimes | Measure-Object -Maximum).Maximum
            
            # Check for inconsistent connection times (possible inspection)
            if ($maxConnectionTime - ($connectionTimes | Measure-Object -Minimum).Minimum -gt 500) {
                $inspectionResult.NetworkInterception = $true
                $inspectionResult.Details += "Inconsistent connection times suggest network inspection"
                Write-LogMessage "DETECTION: Inconsistent connection times" "WARN"
            }
            
            Write-LogMessage "Average connection time: $([math]::Round($avgConnectionTime, 2))ms" "INFO"
        }
        
    }
    catch {
        Write-LogMessage "Packet inspection analysis failed for $Hostname`: $($_.Exception.Message)" "WARN"
    }
    finally {
        # Reset certificate validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
    
    return $inspectionResult
}

# Function to get SSL certificate information (simplified)
function Get-SSLCertificate {
    param(
        [string]$Hostname,
        [int]$Port = 443
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Hostname, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
        $sslStream.AuthenticateAsClient($Hostname)
        
        $cert = $sslStream.RemoteCertificate
        $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
        
        $sslStream.Close()
        $tcpClient.Close()
        
        return @{
            Subject = $x509Cert.Subject
            Issuer = $x509Cert.Issuer
            Thumbprint = $x509Cert.Thumbprint
            NotBefore = $x509Cert.NotBefore
            NotAfter = $x509Cert.NotAfter
            HasPrivateKey = $x509Cert.HasPrivateKey
        }
    }
    catch {
        return $null
    }
}

# Function to test endpoint with enhanced packet inspection detection
function Test-NetworkEndpoint {
    param(
        [string]$Url
    )
    
    $hostname = ([System.Uri]$Url).Host
    $result = @{
        Endpoint = $Url
        TCPConnectivity = $false
        PacketInspectionDetected = $false
        InspectionTool = "None"
        Status = "FAIL"
        FailureReason = ""
        InspectionDetails = @()
    }
    
    Write-LogMessage "Testing endpoint: $Url" "INFO"
    
    # Test TCP connectivity using Test-NetConnection (more reliable)
    try {
        $tcpTest = Test-NetConnection -ComputerName $hostname -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        $result.TCPConnectivity = $tcpTest
    }
    catch {
        # Fallback to custom TCP test
        $result.TCPConnectivity = Test-TCPConnection -Hostname $hostname -Port 443
    }
    
    if (-not $result.TCPConnectivity) {
        $result.FailureReason = "TCP port 443 not reachable"
        Write-LogMessage "TCP connectivity failed for $hostname" "FAIL"
        return $result
    }
    
    Write-LogMessage "TCP connectivity successful for $hostname" "PASS"
    
    # Perform comprehensive packet inspection detection
    $inspectionResult = Test-PacketInspection -Hostname $hostname
    
    if ($inspectionResult.NetworkInterception) {
        $result.PacketInspectionDetected = $true
        $result.InspectionTool = $inspectionResult.InspectionTool
        $result.InspectionDetails = $inspectionResult.Details
        $result.Status = "FAIL"
        $result.FailureReason = "Network packet inspection detected by $($inspectionResult.InspectionTool)"
        Write-LogMessage "PACKET INSPECTION DETECTED for $hostname by $($inspectionResult.InspectionTool)" "FAIL"
    } else {
        $result.Status = "PASS"
        Write-LogMessage "No packet inspection detected for $hostname" "PASS"
    }
    
    return $result
}

# Main script execution
try {
    Write-LogMessage "Starting endpoint connectivity tests" "INFO"
    Write-LogMessage "Log file: $LogPath" "INFO"
    
    # Load configuration
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }
    
    $config = Get-Content $ConfigPath | ConvertFrom-Json
    Write-LogMessage "Configuration loaded from $ConfigPath" "INFO"
    Write-LogMessage "Tenant Name: $($config.tenant_name)" "INFO"
    Write-LogMessage "AWS Region: $($config.aws_region)" "INFO"
    
    # Define endpoints to test
    $endpoints = @(
        "https://s3.amazonaws.com",
        "https://s3.$($config.aws_region).amazonaws.com",
        "https://$($config.tenant_name).cyberark.cloud",
        "https://a2m4b3cupk8nzj-ats.iot.$($config.aws_region).amazonaws.com"
    )
    
    # Test all endpoints
    $results = @()
    foreach ($endpoint in $endpoints) {
        $testResult = Test-NetworkEndpoint -Url $endpoint
        $results += $testResult
        Start-Sleep -Milliseconds 500  # Brief pause between tests
    }
    
    # Display results table
    Write-Host "`n" -NoNewline
    Write-LogMessage "=== NETWORK ENDPOINT TEST RESULTS ===" "INFO"
    
    $tableData = $results | Select-Object @{
        Name = "Endpoint"
        Expression = { $_.Endpoint }
    }, @{
        Name = "Status" 
        Expression = { $_.Status }
    }, @{
        Name = "TCP"
        Expression = { if ($_.TCPConnectivity) { "Pass" } else { "Fail" } }
    }, @{
        Name = "PacketInspection"
        Expression = { if ($_.PacketInspectionDetected) { "DETECTED" } else { "None" } }
    }, @{
        Name = "InspectionTool"
        Expression = { $_.InspectionTool }
    }, @{
        Name = "FailureReason"
        Expression = { $_.FailureReason }
    }
    
    $tableData | Format-Table -AutoSize
    
    # Summary
    $passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $inspectionCount = ($results | Where-Object { $_.PacketInspectionDetected -eq $true }).Count
    
    Write-LogMessage "=== SUMMARY ===" "INFO"
    Write-LogMessage "Total Endpoints: $($results.Count)" "INFO"
    Write-LogMessage "Passed: $passCount" "INFO"
    Write-LogMessage "Failed: $failCount" "INFO"
    Write-LogMessage "Packet Inspection Detected: $inspectionCount" "INFO"
    
    if ($inspectionCount -gt 0) {
        Write-LogMessage "WARNING: Network packet inspection detected on $inspectionCount endpoint(s)" "WARN"
        Write-LogMessage "Your network traffic may be monitored by corporate security tools" "WARN"
    }
    
    if ($failCount -gt 0) {
        Write-LogMessage "Some endpoints failed validation. Check logs for details." "WARN"
        exit 1
    } else {
        Write-LogMessage "All endpoints passed connectivity tests with no packet inspection detected." "PASS"
        exit 0
    }
}
catch {
    Write-LogMessage "Script execution failed: $($_.Exception.Message)" "ERROR"
    Write-LogMessage $_.ScriptStackTrace "ERROR"
    exit 1
}