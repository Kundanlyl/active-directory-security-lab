# Remediation Plan

## Identity and access control

- Remove unnecessary `GenericAll`, `GenericWrite`, `WriteDACL`, and `WriteOwner` permissions.
- Review delegated rights on users, groups, computers, organizational units, and containers.
- Separate privileged accounts from standard daily-use accounts.
- Restrict membership in Domain Admins, Enterprise Admins, and other Tier Zero groups.
- Audit nested groups and inherited permissions for unexpected routes to privilege.
- Prefer group-managed service accounts where appropriate and use long, unique service-account secrets.

## Credential protection

- Eliminate password reuse and enforce long, unique passwords.
- Reduce or disable NTLM where application compatibility permits.
- Enable protections for LSASS and Windows Defender Credential Guard on supported systems.
- Restrict administrative logons across tiers to reduce credential exposure.
- Use Windows LAPS for unique local administrator passwords.

## Monitoring

- Centralize Windows Security, Sysmon, PowerShell, and directory-service logs.
- Alert on changes to privileged group membership and sensitive ACLs.
- Investigate unusual Kerberos service-ticket patterns and legacy authentication use.
- Monitor endpoint-protection blocks and repeated attempts to access LSASS.
- Baseline legitimate administrative tools and investigate deviations from normal parent-child process behavior.

## Network and endpoint controls

- Segment domain controllers and administrative systems from ordinary client networks.
- Restrict SMB, WinRM, RDP, and other management protocols to approved sources.
- Keep Windows, endpoint-protection signatures, and administrative tools patched.
- Use application control to limit unauthorized executables and scripts.
- Validate controls through repeatable tests and retain evidence of both blocked and detected activity.

## Prioritization

| Priority | Action | Reason |
| --- | --- | --- |
| Critical | Remove direct paths to Tier Zero and privileged groups | Reduces the most damaging identity risks first |
| High | Protect privileged credentials and restrict administrative logons | Limits credential theft and lateral movement |
| High | Centralize directory and endpoint telemetry | Makes identity abuse visible and investigable |
| Medium | Reduce legacy authentication and harden remote services | Shrinks common credential-abuse paths |
| Ongoing | Re-run graph collection and validate detections | Confirms that remediation remains effective |

