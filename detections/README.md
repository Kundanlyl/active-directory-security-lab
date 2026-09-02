# Detection Engineering Notes

These starter hunts translate the lab's attack-path and credential-risk findings into practical SIEM logic. Field names vary by collector and data model, so each query should be validated against the local schema before being promoted to an alert.

## 1. Privileged group membership changes

Windows events 4728, 4732, and 4756 record members added to global, local, and universal security groups.

### Elastic KQL

```text
event.code:("4728" or "4732" or "4756") and
winlog.event_data.TargetUserName:("Domain Admins" or "Enterprise Admins" or "Administrators")
```

### Splunk SPL

```text
index=windows EventCode IN (4728,4732,4756)
| search TargetUserName IN ("Domain Admins","Enterprise Admins","Administrators")
| table _time host SubjectUserName MemberName TargetUserName EventCode
```

**Triage:** Confirm the change request, actor account, source host, affected member, and whether the action occurred through an approved administrative path.

## 2. Sensitive directory-object modification

Event 5136 can expose changes to Active Directory objects when Directory Service Changes auditing is configured.

### Elastic KQL

```text
event.code:"5136" and
winlog.event_data.AttributeLDAPDisplayName:("nTSecurityDescriptor" or "member")
```

### Splunk SPL

```text
index=windows EventCode=5136
| search AttributeLDAPDisplayName IN ("nTSecurityDescriptor","member")
| table _time host SubjectUserName ObjectDN AttributeLDAPDisplayName OperationType
```

**Triage:** Review the object distinguished name, before/after value if collected, effective permissions, and proximity to Tier Zero assets.

## 3. RC4 Kerberos service tickets

RC4-encrypted service-ticket requests can be relevant to Kerberoasting investigations, although legacy systems can create legitimate events.

### Elastic KQL

```text
event.code:"4769" and winlog.event_data.TicketEncryptionType:"0x17"
```

### Splunk SPL

```text
index=windows EventCode=4769 TicketEncryptionType=0x17
| stats count dc(ServiceName) AS distinct_services values(ServiceName) AS services BY AccountName Client_Address
| where count > 5 OR distinct_services > 3
```

**Triage:** Compare the requester, source address, volume, targeted SPNs, encryption configuration, and the account's normal behavior. RC4 alone is not proof of Kerberoasting.

## 4. Possible Pass-the-Hash behavior

Pass-the-Hash detection requires correlation; no single Windows event proves the technique. A useful starting point is a network logon using NTLM followed by privileged activity.

### Splunk SPL

```text
index=windows EventCode IN (4624,4672,4688)
| transaction host TargetUserName maxspan=5m
| search EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where mvfind(EventCode,"4672|4688") >= 0
| table _time host IpAddress TargetUserName AuthenticationPackageName EventCode ProcessName
```

**Triage:** Validate the source host, account role, logon process, administrative share access, remote-service creation, and nearby endpoint alerts. Tune service accounts and expected management systems before alerting.

## 5. Suspicious process creation from Sysmon

### Elastic KQL

```text
event.code:"1" and process.parent.name:("powershell.exe" or "cmd.exe" or "wscript.exe" or "mshta.exe")
```

### Splunk SPL

```text
index=sysmon EventCode=1
| where match(ParentImage,"(?i)\\\\(powershell|cmd|wscript|mshta)\\.exe$")
| table _time host User ParentImage Image CommandLine IntegrityLevel Hashes
```

**Triage:** Inspect the complete process tree, command line, user context, integrity level, file origin, hash reputation, and related network connections.

## Engineering next steps

- Replay known benign and authorized test activity to measure false positives.
- Normalize Windows fields across Elastic Common Schema and Splunk naming.
- Convert stable hunts into threshold or correlation rules.
- Add severity, suppression, asset criticality, and response guidance.
- Record screenshots of triggered detections and retain sanitized sample events.
