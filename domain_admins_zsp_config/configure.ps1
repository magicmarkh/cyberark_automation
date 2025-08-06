 #Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = ".\delegation-config.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

Import-Module ActiveDirectory -ErrorAction Stop

class DelegationConfig {
    [string]$OUDistinguishedName
    [string]$ServiceAccountSamAccountName
    [string]$GroupName
    [string]$DomainDN
    [string]$DomainAdminsGroup
    [string]$EnterpriseAdminsGroup
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor White }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
}

function Get-ConfigurationFromFile {
    param([string]$FilePath)
    
    try {
        if (Test-Path $FilePath) {
            $configData = Get-Content $FilePath | ConvertFrom-Json
            Write-Log "Configuration loaded from file: $FilePath" -Level Success
            
            $config = [DelegationConfig]::new()
            $config.OUDistinguishedName = $configData.OUDistinguishedName
            $config.ServiceAccountSamAccountName = $configData.ServiceAccountSamAccountName
            $config.GroupName = $configData.GroupName
            $config.DomainDN = $configData.DomainDN
            $config.DomainAdminsGroup = $configData.DomainAdminsGroup
            $config.EnterpriseAdminsGroup = $configData.EnterpriseAdminsGroup
            
            return $config
        } else {
            Write-Log "Configuration file not found: $FilePath" -Level Error
            return $null
        }
    } catch {
        Write-Log "Error reading configuration file: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Find-ADGroupSafely {
    param([string]$GroupName)
    
    try {
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
        Write-Log "Found group by exact match: $($group.Name)" -Level Success
        return $group
    } catch {
        Write-Log "Exact match failed, searching by filter..." -Level Warning
        
        $groups = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
        
        if ($groups -and $groups.Count -gt 0) {
            $group = $groups[0]
            Write-Log "Found group by filter: $($group.Name)" -Level Success
            return $group
        } else {
            Write-Log "Group not found: $GroupName" -Level Error
            return $null
        }
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level Info
    
    $allChecksPass = $true
    
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "This script must be run as Administrator" -Level Error
        $allChecksPass = $false
    } else {
        Write-Log "Administrator privileges confirmed" -Level Success
    }
    
    $dsaclsPath = Get-Command dsacls.exe -ErrorAction SilentlyContinue
    if (-not $dsaclsPath) {
        Write-Log "DSACLS.exe not found. Ensure RSAT tools are installed." -Level Error
        $allChecksPass = $false
    } else {
        Write-Log "DSACLS.exe found at: $($dsaclsPath.Source)" -Level Success
    }
    
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Log "Connected to domain: $($domain.DNSRoot)" -Level Success
    } catch {
        Write-Log "Cannot connect to Active Directory domain" -Level Error
        $allChecksPass = $false
    }
    
    return $allChecksPass
}

function Test-ADObjects {
    param([DelegationConfig]$Config)
    
    Write-Log "Validating Active Directory objects..." -Level Info
    
    try {
        $ou = Get-ADOrganizationalUnit -Identity $Config.OUDistinguishedName -ErrorAction Stop
        Write-Log "OU validated: $($ou.Name)" -Level Success
        
        $parentOU = $Config.OUDistinguishedName -replace '^OU=[^,]+,', ''
        $parentOUObj = Get-ADOrganizationalUnit -Identity $parentOU -ErrorAction Stop
        Write-Log "Parent OU validated: $($parentOUObj.Name)" -Level Success
        
        $serviceAccount = Get-ADUser -Identity $Config.ServiceAccountSamAccountName -ErrorAction Stop
        Write-Log "Service Account validated: $($serviceAccount.Name)" -Level Success
        
        $group = Find-ADGroupSafely -GroupName $Config.GroupName
        if (-not $group) {
            return $false
        }
        Write-Log "Group validated: $($group.Name)" -Level Success
        
        $domainAdmins = Get-ADGroup -Identity $Config.DomainAdminsGroup -ErrorAction Stop
        Write-Log "Domain Admins group validated: $($domainAdmins.Name)" -Level Success
        
        $enterpriseAdmins = Get-ADGroup -Identity $Config.EnterpriseAdminsGroup -ErrorAction Stop
        Write-Log "Enterprise Admins group validated: $($enterpriseAdmins.Name)" -Level Success
        
        return $true
        
    } catch {
        Write-Log "Object validation failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-OUDelegation {
    param(
        [DelegationConfig]$Config,
        [switch]$WhatIfMode
    )
    
    Write-Log "Setting OU delegation permissions..." -Level Info
    
    try {
        $domain = Get-ADDomain
        $domainNetBIOS = $domain.NetBIOSName
        $ouPath = $Config.OUDistinguishedName
        $serviceAccount = $Config.ServiceAccountSamAccountName
        $parentOU = $ouPath -replace '^OU=[^,]+,', ''
        
        Write-Log "Domain NetBIOS: $domainNetBIOS" -Level Info
        Write-Log "Target OU: $ouPath" -Level Info
        Write-Log "Parent OU: $parentOU" -Level Info
        
        $commands = @(
            @{ Target = $parentOU; Rights = "CCDC"; Inheritance = "/I:T"; Description = "Create/Delete Child on Parent OU with inheritance" },
            @{ Target = $ouPath; Rights = "CCDC"; Inheritance = "/I:T"; Description = "Create/Delete Child on Target OU with inheritance" }
        )
        
        foreach ($cmd in $commands) {
            if ($WhatIfMode) {
                Write-Log "[WHATIF] $($cmd.Description)" -Level Info
                Write-Log "[WHATIF] Would execute: dsacls $($cmd.Target) /G $domainNetBIOS\$serviceAccount`:$($cmd.Rights);user $($cmd.Inheritance)" -Level Info
            } else {
                Write-Log $cmd.Description -Level Info
                $result = & dsacls $cmd.Target /G "$domainNetBIOS\$serviceAccount`:$($cmd.Rights);user" $cmd.Inheritance 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Successfully applied: $($cmd.Description)" -Level Success
                } else {
                    Write-Log "Failed to apply: $($cmd.Description) - $result" -Level Error
                }
            }
        }
        
        if (-not $WhatIfMode) {
            Write-Log "Full Control on User objects in Target OU" -Level Info
            $result = & dsacls $ouPath /G "$domainNetBIOS\$serviceAccount`:GA;;user" /I:S 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Successfully applied: Full Control on User objects" -Level Success
            } else {
                Write-Log "Failed to apply Full Control - $result" -Level Warning
            }
        }
        
        return $true
        
    } catch {
        Write-Log "Error setting OU delegation: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Set-GroupPermissions {
    param(
        [DelegationConfig]$Config,
        [switch]$WhatIfMode
    )
    
    Write-Log "Setting group membership permissions..." -Level Info
    
    try {
        $group = Find-ADGroupSafely -GroupName $Config.GroupName
        if (-not $group) {
            Write-Log "Cannot find group: $($Config.GroupName)" -Level Error
            return $false
        }
        
        $serviceAccount = Get-ADUser -Identity $Config.ServiceAccountSamAccountName
        $domainAdmins = Get-ADGroup -Identity $Config.DomainAdminsGroup
        
        Write-Log "Group: $($group.Name)" -Level Info
        Write-Log "Group DN: $($group.DistinguishedName)" -Level Info
        
        if ($WhatIfMode) {
            Write-Log "[WHATIF] Would remove all Domain Admins ACEs from group" -Level Info
            Write-Log "[WHATIF] Would add service account permissions to group" -Level Info
            Write-Log "[WHATIF] Would add Domain Admins DENY rule to group" -Level Info
            return $true
        }
        
        $groupACL = Get-Acl -Path "AD:\$($group.DistinguishedName)"
        Write-Log "Original ACEs: $($groupACL.Access.Count)" -Level Info
        
        $domainAdminACEs = $groupACL.Access | Where-Object { 
            $_.IdentityReference.Value -like "*Domain Admins*" -or
            $_.IdentityReference.Value -eq $domainAdmins.SID.Value
        }
        
        Write-Log "Found $($domainAdminACEs.Count) Domain Admins ACEs to remove" -Level Info
        
        foreach ($ace in $domainAdminACEs) {
            $groupACL.RemoveAccessRule($ace) | Out-Null
            Write-Log "Removed: $($ace.AccessControlType) - $($ace.ActiveDirectoryRights)" -Level Warning
        }
        
        $serviceAccountACEs = $groupACL.Access | Where-Object { 
            $_.IdentityReference.Value -like "*$($Config.ServiceAccountSamAccountName)*" -or
            $_.IdentityReference.Value -eq $serviceAccount.SID.Value
        }
        
        if ($serviceAccountACEs.Count -eq 0) {
            Write-Log "Adding service account permissions..." -Level Info
            
            $domain = Get-ADDomain
            $domainNetBIOS = $domain.NetBIOSName
            $result = & dsacls $group.DistinguishedName /G "$domainNetBIOS\$($Config.ServiceAccountSamAccountName)`:RPWP" 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                Write-Log "DSACLS failed, using PowerShell method..." -Level Warning
                
                $serviceAccountAllowACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $serviceAccount.SID,
                    ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty),
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                
                $groupACL.SetAccessRule($serviceAccountAllowACE)
            }
        } else {
            Write-Log "Service account already has $($serviceAccountACEs.Count) ACE(s)" -Level Info
        }
        
        Write-Log "Adding Domain Admins DENY rule..." -Level Info
        $denyAllACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainAdmins.SID,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        
        $groupACL.SetAccessRule($denyAllACE)
        Set-Acl -Path "AD:\$($group.DistinguishedName)" -AclObject $groupACL
        
        Write-Log "Group permissions applied successfully" -Level Success
        
        $newACL = Get-Acl -Path "AD:\$($group.DistinguishedName)"
        $denyRules = $newACL.Access | Where-Object { $_.AccessControlType -eq "Deny" }
        
        if ($denyRules.Count -gt 0) {
            Write-Log "Verification: $($denyRules.Count) DENY rule(s) confirmed" -Level Success
        } else {
            Write-Log "Warning: No DENY rules found after application" -Level Warning
        }
        
        return $true
        
    } catch {
        Write-Log "Error setting group permissions: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Invoke-PermissionVerification {
    param([DelegationConfig]$Config)
    
    Write-Log "Verifying applied permissions..." -Level Info
    
    try {
        $serviceAccount = Get-ADUser -Identity $Config.ServiceAccountSamAccountName
        $group = Find-ADGroupSafely -GroupName $Config.GroupName
        if (-not $group) {
            Write-Log "Cannot find group for verification" -Level Error
            return
        }
        
        $domainAdmins = Get-ADGroup -Identity $Config.DomainAdminsGroup
        
        Write-Log "Service Account SID: $($serviceAccount.SID)" -Level Info
        
        # Check for any DENY rules that might be blocking user creation
        Write-Log "Checking for DENY rules on OU..." -Level Info
        $ouACL = Get-Acl -Path "AD:\$($Config.OUDistinguishedName)"
        $denyRules = $ouACL.Access | Where-Object { $_.AccessControlType -eq "Deny" }
        
        if ($denyRules.Count -gt 0) {
            Write-Log "Found $($denyRules.Count) DENY rule(s) on OU:" -Level Warning
            $denyRules | ForEach-Object {
                Write-Log "  DENY: $($_.IdentityReference) - $($_.ActiveDirectoryRights)" -Level Warning
            }
        } else {
            Write-Log "No DENY rules found on OU" -Level Success
        }
        
        # Check parent OU for DENY rules too
        $parentOU = $Config.OUDistinguishedName -replace '^OU=[^,]+,', ''
        $parentOUACL = Get-Acl -Path "AD:\$parentOU"
        $parentDenyRules = $parentOUACL.Access | Where-Object { $_.AccessControlType -eq "Deny" }
        
        if ($parentDenyRules.Count -gt 0) {
            Write-Log "Found $($parentDenyRules.Count) DENY rule(s) on Parent OU:" -Level Warning
            $parentDenyRules | ForEach-Object {
                Write-Log "  DENY: $($_.IdentityReference) - $($_.ActiveDirectoryRights)" -Level Warning
            }
        } else {
            Write-Log "No DENY rules found on Parent OU" -Level Success
        }
        
        if ($ouServiceACEs) {
            Write-Log "OU permissions verified: Found $($ouServiceACEs.Count) ACE(s) for service account" -Level Success
            
            $hasCreate = $ouServiceACEs | Where-Object { $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild }
            $hasDelete = $ouServiceACEs | Where-Object { $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild }
            $hasGenericAll = $ouServiceACEs | Where-Object { $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
            
            if ($hasCreate) { Write-Log "  ✓ Service account has CreateChild permission" -Level Success }
            if ($hasDelete) { Write-Log "  ✓ Service account has DeleteChild permission" -Level Success }
            if ($hasGenericAll) { Write-Log "  ✓ Service account has GenericAll permission" -Level Success }
        } else {
            Write-Log "Warning: No OU permissions found for service account" -Level Warning
        }
        
        $groupACL = Get-Acl -Path "AD:\$($group.DistinguishedName)"
        $groupServiceACEs = $groupACL.Access | Where-Object { 
            $_.IdentityReference.Value -like "*$($Config.ServiceAccountSamAccountName)*" -or 
            $_.IdentityReference.Value -eq $serviceAccount.SID.Value
        }
        
        if ($groupServiceACEs) {
            Write-Log "Group permissions verified: Found $($groupServiceACEs.Count) ACE(s) for service account" -Level Success
        } else {
            Write-Log "Warning: No group permissions found for service account" -Level Warning
        }
        
        $domainAdminsDenyACEs = $groupACL.Access | Where-Object { 
            ($_.IdentityReference.Value -like "*Domain Admins*" -or $_.IdentityReference.Value -eq $domainAdmins.SID.Value) -and 
            $_.AccessControlType -eq "Deny" 
        }
        
        if ($domainAdminsDenyACEs) {
            Write-Log "Domain Admins deny rule verified: Found $($domainAdminsDenyACEs.Count) DENY ACE(s)" -Level Success
        } else {
            Write-Log "Warning: Domain Admins deny rule not found" -Level Warning
        }
        
    } catch {
        Write-Log "Error during permission verification: $($_.Exception.Message)" -Level Error
    }
}

function Export-ConfigurationSample {
    $sampleConfig = @{
        OUDistinguishedName = "OU=ServiceAccounts,OU=Administration,DC=contoso,DC=com"
        ServiceAccountSamAccountName = "svc-automation"
        GroupName = "ServiceAccountManagers"
        DomainDN = "DC=contoso,DC=com"
        DomainAdminsGroup = "Domain Admins"
        EnterpriseAdminsGroup = "Enterprise Admins"
    }
    
    $samplePath = ".\delegation-config-sample.json"
    $sampleConfig | ConvertTo-Json -Depth 3 | Out-File -FilePath $samplePath -Encoding UTF8
    Write-Log "Sample configuration file created: $samplePath" -Level Info
}

function Main {
    Write-Log "Starting AD Delegation Script (Clean Version)" -Level Info
    Write-Log "=============================================" -Level Info
    
    try {
        if (-not (Test-Prerequisites)) {
            Write-Log "Prerequisite checks failed. Cannot continue." -Level Error
            return
        }
        
        $config = Get-ConfigurationFromFile -FilePath $ConfigFile
        if (-not $config) {
            Write-Log "Failed to load configuration. Exporting sample configuration file." -Level Error
            Export-ConfigurationSample
            Write-Log "Please configure delegation-config-sample.json with your environment details and rename to delegation-config.json" -Level Info
            return
        }
        
        if (-not (Test-ADObjects -Config $config)) {
            Write-Log "AD object validation failed. Please check your configuration." -Level Error
            return
        }
        
        Write-Log "Configuration:" -Level Info
        Write-Log "  OU: $($config.OUDistinguishedName)" -Level Info
        Write-Log "  Service Account: $($config.ServiceAccountSamAccountName)" -Level Info
        Write-Log "  Group: $($config.GroupName)" -Level Info
        Write-Log "  Domain: $($config.DomainDN)" -Level Info
        
        if ($WhatIf) {
            Write-Log "RUNNING IN WHATIF MODE - NO CHANGES WILL BE MADE" -Level Warning
        } else {
            $proceed = Read-Host "Do you want to proceed with applying the delegation? (y/N)"
            if ($proceed -ne 'y' -and $proceed -ne 'Y') {
                Write-Log "Operation cancelled by user." -Level Info
                return
            }
        }
        
        $ouSuccess = Set-OUDelegation -Config $config -WhatIfMode:$WhatIf
        $groupSuccess = Set-GroupPermissions -Config $config -WhatIfMode:$WhatIf
        
        if (-not $WhatIf) {
            Start-Sleep -Seconds 2
            Invoke-PermissionVerification -Config $config
        }
        
        Write-Log "=============================================" -Level Info
        if ($ouSuccess -and $groupSuccess) {
            Write-Log "AD Delegation completed successfully!" -Level Success
        } else {
            Write-Log "Some operations encountered issues. Check the log above." -Level Warning
        }
        
        Write-Log "Summary of Applied Permissions:" -Level Info
        Write-Log "• Service account can create, delete, and manage users in target and parent OUs" -Level Info
        Write-Log "• Service account can modify membership of the specified group" -Level Info
        Write-Log "• Domain Admins are forcibly removed and denied group membership modification" -Level Info
        Write-Log "• Enterprise Admins retain group membership modification rights" -Level Info
        
    } catch {
        Write-Log "Script execution failed: $($_.Exception.Message)" -Level Error
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    }
}

Main 
