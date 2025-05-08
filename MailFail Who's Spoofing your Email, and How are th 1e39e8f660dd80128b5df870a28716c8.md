# MailFail: Who's Spoofing your Email, and How are they Doing it?

[https://www.youtube.com/live/UbdMAmsWus8](https://www.youtube.com/live/UbdMAmsWus8)

## Introduction Summary

In this webcast, Jack, a pentester from Black Hills Information Security, presents his research on email security protocols and their inherent flaws. The presentation walks through how email works, the different security mechanisms in place (SPF, DKIM, and DMARC), and how attackers can bypass these protections. Jack also introduces his browser extension "MailFail" that automates the detection of email security misconfigurations. The presentation covers practical demonstrations of email spoofing techniques and provides guidance on properly securing email domains.

## Key Takeaways

1. Email security relies on three main protocols (SPF, DKIM, and DMARC) that build upon each other, but the first two can be bypassed because they don't authenticate what users actually see in their email client.
2. DMARC closes many spoofing vulnerabilities by introducing the concept of "alignment" - ensuring the domain in the From header matches the domain authenticated by SPF or DKIM.
3. Many organizations have misconfigured security settings like weak DKIM keys (512-bit RSA) that can be cracked, missing DMARC records, or incomplete policies that leave their domains vulnerable to spoofing.
4. The MailFail browser extension automates the process of checking email security configurations, identifying vulnerabilities, and even providing commands to exploit them for testing purposes.

## Detailed Notes

### Email Basics

- SMTP (Simple Mail Transfer Protocol) was created in the early 1980s
- MTAs (Mail Transfer Agents) are the email servers that communicate using SMTP
- Email flow: User composes email → Sender's MTA → Recipient's MTA → Recipient's inbox
- Basic SMTP commands:
    - HELO/EHLO: Initiates connection and identifies sending server
    - STARTTLS: Creates encrypted channel (optional)
    - MAIL FROM: Specifies sender address
    - RCPT TO: Specifies recipient address
    - DATA: Everything after this is the email body

### SPF (Sender Policy Framework)

- SPF verifies that the sending server's IP address is authorized to send emails for a specific domain
- Implementation:
    - Domain owner publishes a TXT record listing authorized IP addresses
    - Receiving server checks if the connecting IP is on that list
- Verification process:
    1. Receiving MTA extracts domain from SMTP FROM address
    2. Looks up SPF record (TXT record starting with "v=spf1")
    3. Compares sending IP address with authorized IPs
    4. Passes or fails based on comparison
- Bypass technique:
    - The domain checked is the SMTP FROM domain, not the From header in the email body
    - An attacker can use their own domain in SMTP FROM (which passes SPF) but display any domain in the From header

### DKIM (DomainKeys Identified Mail)

- Uses public/private key cryptography to authenticate email
- Implementation:
    - Domain owner publishes public key in TXT record
    - Sending server uses private key to sign parts of the email
    - Receiving server verifies signature using the public key
- Verification process:
    1. Sender's MTA adds DKIM-Signature header with domain and selector
    2. Receiving MTA extracts domain and selector from this header
    3. Looks up public key via DNS (selector._domainkey.domain.com)
    4. Verifies signature using the public key
- Bypass technique:
    - Similar to SPF, the domain checked is from the DKIM-Signature header, not the From header
    - Attacker can use their own domain in DKIM-Signature, sign with their private key, but display any domain in From header
- Vulnerability: Weak DKIM keys
    - Keys smaller than 800 bits (especially 512-bit RSA) can be cracked
    - Once cracked, attacker has the private key and can perfectly sign emails
    - Cost: approximately $30 of compute time for 2 days

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

- Builds on SPF and DKIM by adding "alignment" checks
- Implementation:
    - Domain owner publishes TXT record at _dmarc.domain.com
    - Record specifies policy (none, quarantine, reject) and reporting options
- Key concept: Alignment
    - Checks if domain in From header matches domain authenticated by SPF or DKIM
    - Closes the main bypasses for SPF and DKIM
- Policies:
    - p=none: Take no action (deliver to inbox)
    - p=quarantine: Send to spam folder
    - p=reject: Don't deliver email at all
- DMARC passes if either SPF or DKIM passes AND alignment passes
- PCT field: Percentage of emails to apply policy to
    - PCT=60 means policy applies to only 60% of emails
    - Remaining 40% get downgraded policy (reject→quarantine, quarantine→none)
- Reporting:
    - rua=mailto - Aggregate reports (statistics)
    - ruf=mailto - Forensic reports (copies of emails)

### The MailFail Extension

- Browser extension for Firefox that automates email security checks
- Features:
    - Checks SPF, DKIM, DMARC configurations
    - Finds DKIM selectors through brute force
    - Identifies weak DKIM keys
    - Discovers available domains in SPF records
    - Checks for Direct Send, MTA-STS, BIMI, and more
    - Provides commands to exploit vulnerabilities for testing
    - Links to documentation for learning more

### Email Security Best Practices

- Set up SPF records for every subdomain
- Configure DMARC with p=reject policy
- Avoid using pct= percentage lower than 100
- Set up DMARC reporting
- Use DKIM keys of 2048 bits or larger
- Regularly check for misconfigurations with tools like MailFail

## Quiz Questions

1. **Question**: Why can SPF be easily bypassed despite correctly verifying the sending server's IP address?
    - **Answer**: SPF verifies the domain in the SMTP FROM field (used for protocol communication), but not the From header that users see in their email clients. An attacker can use their own domain in SMTP FROM to pass SPF checks while displaying any spoofed domain in the From header.
2. **Question**: What vulnerability exists in some DKIM implementations that would allow an attacker to perfectly forge signed emails?
    - **Answer**: Some domains use weak DKIM RSA keys (particularly 512-bit keys) that can be computationally cracked in about 2 days for approximately $30 of compute resources. Once cracked, the attacker has the private key and can create perfectly signed emails that pass DKIM verification.
3. **Question**: How does DMARC improve upon SPF and DKIM to prevent email spoofing?
    - **Answer**: DMARC introduces the concept of "alignment" - checking that the domain in the From header (visible to users) matches the domain authenticated by SPF or DKIM. This closes the bypass vulnerabilities in SPF and DKIM, and also specifies clear policies (none, quarantine, reject) for handling failed authentications.
4. **Question**: What does the PCT field in a DMARC record do, and why might it be problematic for security?
    - **Answer**: PCT (percentage) specifies what portion of emails the DMARC policy applies to. For example, PCT=60 means the policy applies to only 60% of emails, while 40% get a downgraded policy. This is problematic because it allows a percentage of spoofed emails to bypass protection, essentially creating a statistical backdoor.

## Notable Quotes

> "SPF does not ensure that the email address seen by the user is the one which was checked, which is an inherent flaw in SPF and is also something that even the authors of SPF noted in the initial proposal."
> 

> "DKIM is used to ensure that the email's To and From headers are correctly signed with the specified domain's private key. It doesn't ensure that the email is signed by the domain that's shown to the user in the email."
> 

> "DKIM also does not cryptographically sign the email body, which is a pretty common misconception."
> 

> "DMARC succeeds in the ways that all the previous ones have failed."
> 

> "DMARC has added this concept of alignment and that's what that means. So if SPF passes, alignment passes, DMARC passes."
> 

> "Email is a garbage fire in conclusion."
>

## Additional Resources

✉️ MailFail Extension (Firefox) and other resources
 https://m.ail.fail/
🛝 Webcast Slides -
https://www.blackhillsinfosec.com/wp-...

🔗 Jack's list of DKIM selectors -
https://github.com/ACK-J/MailFail/blob/main/DKIM_Selectors.txt

🔗 Download the extension -
https://addons.mozilla.org/en-US/firefox/addon/mailfail/

🔗 github repository - 
https://github.com/ACK-J/MailFail/

🔗 Reconstruct private keys from the two prime numbers - 
https://gist.github.com/ACK-J/487d0de5737458d953ca818a0645b09b

🔗 Send DKIM signed emails script with a private key -
https://gist.github.com/ACK-J/76585af46375641ec841cb6b77d345c3

🔗 Here's a bonus that wasn't in the presentation -
Python script that takes in a list of domains and checks them for DMARC misconfigurations - 
https://gist.github.com/ACK-J/8a189bafbb54e00fb1b3f3e22dcd81c9
