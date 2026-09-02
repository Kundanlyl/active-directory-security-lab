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

## 3. Password spraying across multiple accounts

Event 4625 records failed logons. Password spraying becomes more useful to investigate when many distinct accounts are targeted from one source in a short period.

### Elastic KQL

```text
event.code:"4625" and source.ip:*
```

Use this filter in a threshold or aggregation rule grouped by `source.ip`, counting distinct target users over a short interval.

### Splunk SPL

```text
index=windows EventCode=4625
| bucket _time span=5m
| stats count AS failures dc(TargetUserName) AS targeted_accounts values(TargetUserName) AS users BY _time IpAddress
| where failures >= 10 AND targeted_accounts >= 5
```

**Triage:** Check the source host, targeted accounts, failure reason, successful logons near the same time, and whether the source is an approved scanner or identity service.

## 4. AS-REP roasting exposure

A 4768 event with preauthentication type `0` can identify a ticket request for an account that does not require Kerberos preauthentication.

### Elastic KQL

```text
event.code:"4768" and winlog.event_data.PreAuthType:"0"
```

### Splunk SPL

```text
index=windows EventCode=4768 Pre_Authentication_Type=0
| table _time host TargetUserName IpAddress TicketEncryptionType Pre_Authentication_Type
```

**Triage:** Confirm whether preauthentication is intentionally disabled, review the source address and account history, and search for subsequent authentication or password-cracking indicators. Collector field names for preauthentication type vary and must be verified locally.

## 5. RC4 Kerberos service tickets

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

## 6. Possible Pass-the-Hash behavior

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

## 7. Suspicious process creation from Sysmon

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
