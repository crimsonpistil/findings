# Website Security Incident – Stakeholder Summary
The Breakers FWB website was recently compromised by external attackers who repurposed it as a malware distribution platform. This incident poses serious risks to visitor safety, staff credentials, and the organization’s reputation.

## Key Findings
- Malicious JavaScript was injected into the site, causing a fake Cloudflare “verification” page to appear for some visitors. This page attempted to trick users into executing a dangerous PowerShell command that could install malware.
- Attackers published spam blog posts about casinos and gambling, designed to manipulate search engine rankings and lure unsuspecting users to the compromised site.
- Real staff accounts—including Barbara Martens and Ethan Whited—were found active on the site, alongside the default “admin” account. These accounts may have been exploited to maintain access or publish content.

## Why This Matters
- The site was actively used to spread malware, not just defaced.
- Visitors may have been exposed to harmful software.
- Staff credentials could be compromised, allowing attackers to return even after cleanup.
- The site’s reputation and search visibility were weaponized to attract victims.

## Recommended Actions
- Reset all staff passwords immediately, including Barbara and Ethan’s accounts. Permanently disable the generic “admin” account.
- Remove all injected code and spam content, especially casino-related blog posts.
- Update WordPress core, themes, and plugins to eliminate known vulnerabilities.
- Enable stronger security controls, including two-factor authentication and activity monitoring.
- Conduct a full audit of user activity and site changes to identify any lingering threats.
- Implement ongoing monitoring and hardening measures
