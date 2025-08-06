# Active Directory Delegation Script for Ephemeral Domain Admins

A PowerShell script for securely delegating Active Directory permissions to support ephemeral domain admin use cases with CyberArk Secure Infrastructure Access.

## Overview

This script automates the delegation of specific Active Directory permissions to enable a service account to create temporary user accounts and manage membership of privileged groups. It's designed to support ephemeral domain admin scenarios where temporary privileged access is granted through automated account provisioning.

## Purpose

The script addresses the need for automated, temporary privileged access by:

- **Enabling ephemeral account creation** for just-in-time privileged access
- **Supporting CyberArk Secure Infrastructure Access** integration
- **Preventing privilege escalation** by blocking unauthorized group membership modifications
- **Maintaining security controls** while enabling automation

## Functionality

### What the Script Does

1. **Service Account Delegation**
   - Grants the specified service account permissions to create user accounts in the target OU
   - Enables the service account to delete temporary accounts when access expires
   - Provides full control over user objects for account management

2. **Group Membership Management**
   - Allows the service account to add/remove members from the specified security group
   - Typically used to grant temporary domain admin privileges

3. **Security Controls**
   - **Blocks Domain Admins** from managing the target group's membership to prevent insider threats
   - **Preserves Enterprise Admins** access for emergency management and maintenance
   - Uses inheritance protection to ensure permissions persist across reboots

4. **Inheritance and Persistence**
   - Applies permissions to both target OU and parent OU for proper inheritance
   - Uses DSACLS for reliable permission application
   - Implements persistence mechanisms to survive domain controller restarts

## Requirements

- **PowerShell 5.1 or higher**
- **Active Directory PowerShell Module**
- **Administrator privileges** on the domain controller or RSAT-enabled machine
- **Domain Admin or Enterprise Admin** permissions to delegate authority
- **DSACLS.exe** (included with Windows Server/RSAT)

## Configuration

The script uses a JSON configuration file to define the delegation parameters:

```json
{
    "OUDistinguishedName": "OU=EphemeralAccounts,OU=Administration,DC=contoso,DC=com",
    "ServiceAccountSamAccountName": "svc-cyberark-automation",
    "GroupName": "Ephemeral-Domain-Admins",
    "DomainDN": "DC=contoso,DC=com",
    "DomainAdminsGroup": "Domain Admins",
    "EnterpriseAdminsGroup": "Enterprise Admins"
}
```

### Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `OUDistinguishedName` | Target OU where ephemeral accounts will be created | `"OU=EphemeralAccounts,OU=IT,DC=contoso,DC=com"` |
| `ServiceAccountSamAccountName` | Service account that will perform automation tasks | `"svc-cyberark-automation"` |
| `GroupName` | Security group for ephemeral privileged access | `"Ephemeral-Domain-Admins"` |
| `DomainDN` | Domain distinguished name | `"DC=contoso,DC=com"` |
| `DomainAdminsGroup` | Domain Admins group name (usually "Domain Admins") | `"Domain Admins"` |
| `EnterpriseAdminsGroup` | Enterprise Admins group name | `"Enterprise Admins"` |

## Usage

### Basic Usage

```powershell
# Test the configuration without making changes
.\Set-ADDelegation.ps1 -ConfigFile "delegation-config.json" -WhatIf

# Apply the delegation
.\Set-ADDelegation.ps1 -ConfigFile "delegation-config.json"
```

### Advanced Usage

```powershell
# Use default configuration file name
.\Set-ADDelegation.ps1

# Specify custom configuration file
.\Set-ADDelegation.ps1 -ConfigFile "C:\Scripts\my-delegation-config.json"
```

## Security Model

### Permissions Granted

**Service Account Permissions:**
- **Create Child** permissions on target OU (for user creation)
- **Delete Child** permissions on target OU (for account cleanup)
- **Full Control** over user objects (for account management)
- **Write Property** permissions on target group (for membership management)

### Security Restrictions

**Domain Admins Group:**
- **Explicitly denied** all permissions on the target group
- Cannot add persistent members to ephemeral admin groups
- Prevents insider threats and unauthorized privilege escalation

**Enterprise Admins Group:**
- **Retains full access** for emergency management
- Can override restrictions if needed for maintenance
- Provides break-glass access for security teams

## Use Cases

### CyberArk Secure Infrastructure Access

This script is specifically designed to support CyberArk SIA deployments where:

1. **Ephemeral Accounts** are created on-demand for privileged access
2. **Just-in-Time Access** is granted through temporary group membership
3. **Automated Cleanup** removes accounts after access expires
4. **Audit Trails** track all privileged access through CyberArk logging

### Typical Workflow

1. User requests privileged access through CyberArk
2. CyberArk service account creates temporary domain user
3. Service account adds user to ephemeral admin group
4. User performs required administrative tasks
5. After expiration, service account removes user from group and deletes account

## Troubleshooting

### Common Issues

**"Access Denied" when creating users:**
- Verify service account has proper OU delegation
- Check for conflicting DENY permissions
- Ensure parent OU permissions are correctly applied

**Group membership changes blocked:**
- Confirm Domain Admins DENY rule is applied
- Verify service account has WriteProperty permissions on group
- Check for Group Policy interference

**Permissions don't persist after reboot:**
- Script includes inheritance protection mechanisms
- Verify ACL inheritance is properly configured
- Check domain controller replication status

### Verification Commands

```powershell
# Check service account permissions on OU
$ou = "OU=EphemeralAccounts,DC=contoso,DC=com"
$svcAccount = "svc-cyberark-automation"
Get-Acl "AD:\$ou" | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -like "*$svcAccount*" }

# Verify group permissions
$group = "Ephemeral-Domain-Admins"
Get-ADGroup $group | Get-Acl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -eq "Deny" }
```

## Best Practices

1. **Test Thoroughly** - Always use `-WhatIf` parameter before applying changes
2. **Monitor Permissions** - Regularly verify delegation remains intact
3. **Document Changes** - Keep records of all permission modifications  
4. **Regular Reviews** - Audit ephemeral account usage and cleanup
5. **Backup ACLs** - Export ACLs before making changes for rollback capability

## Security Considerations

- **Principle of Least Privilege** - Service account only receives minimum required permissions
- **Time-Limited Access** - Implement account expiration policies
- **Monitoring and Alerting** - Log all privileged account creation/deletion
- **Regular Audits** - Review group membership and permission usage
- **Change Management** - Follow organization's change control processes

## Support

For issues related to:
- **CyberArk Integration** - Consult CyberArk documentation and support
- **Active Directory** - Verify domain controller health and replication
- **PowerShell Errors** - Check execution policy and module availability
- **Permission Issues** - Validate account privileges and Group Policy settings

## Contributing

When contributing to this project:
1. Test all changes in a lab environment first
2. Ensure PowerShell syntax is validated
3. Update documentation for any new parameters or functionality
4. Follow security best practices for privilege delegation

## License

This script is provided as-is for educational and operational purposes. Test thoroughly before using in production environments.