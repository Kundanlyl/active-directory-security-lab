# Credential-Security Testing

## Scope

Credential testing was performed only against accounts and hosts created for the isolated lab. Sensitive output is omitted from this public portfolio.

## Exercises completed

- Reviewed online authentication testing and observed the operational limitations of high-volume login attempts, including connection errors and the likelihood of rate limiting or other defensive controls.
- Extracted credential material from an authorized Windows lab system and performed offline NTLM hash analysis with Hashcat.
- Examined how password reuse produces identical NTLM hashes and increases the impact of credential compromise.
- Used Mimikatz in the authorized lab to inspect LSASS credential exposure and construct a controlled Pass-the-Hash test.
- Exercised SMB-based lateral-movement behavior with Metasploit and evaluated the Windows target's access denial as evidence of control effectiveness.

## Security lessons

1. NTLM material can be abused without recovering the plaintext password.
2. Password reuse can turn one recovered credential into access across multiple accounts or systems.
3. Offline cracking avoids online account-lockout controls, so password length and uniqueness remain important.
4. Credential Guard, LSASS protection, Microsoft Defender, remote-administration controls, and network segmentation can materially change an attacker's options.
5. Failed testing is still valuable when it demonstrates control effectiveness and is documented accurately.

## Evidence policy

The original screenshots included reusable lab passwords and credential hashes. They are intentionally excluded because public proof of the learning outcome does not require publishing authentication material.
