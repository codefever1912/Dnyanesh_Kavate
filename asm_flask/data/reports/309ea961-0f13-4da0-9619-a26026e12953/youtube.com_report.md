# Attack Surface Monitoring Report: youtube.com
**Scan Date:** 2025-04-21
**Risk Score:** 95/100

## Executive Summary
The domain youtube.com has critical security vulnerabilities that require immediate attention. The attack surface is significantly exposed with multiple high-severity issues that could lead to system compromise. Urgent remediation is necessary to prevent potential breaches.

## Key Recommendations
1. Immediately restrict access to administrative interfaces using IP filtering or VPN requirements
2. Update or patch all services with known vulnerabilities, or place them behind a properly configured firewall
3. Replace expired SSL certificates with valid ones from trusted certificate authorities
4. Implement all missing security headers, particularly HSTS, CSP, and X-Frame-Options
5. Force password resets for all accounts and implement multi-factor authentication

## Subdomains
Discovered 26 subdomains:

| Subdomain | Status |
| --- | --- |
| admin.youtube.com | Live |
| ads.youtube.com | Live |
| app.youtube.com | Live |
| c.youtube.com | Live |
| cache1.c.youtube.com | Live |
| cache2.c.youtube.com | Live |
| cache3.c.youtube.com | Live |
| cache4.c.youtube.com | Live |
| cache5.c.youtube.com | Live |
| cache6.c.youtube.com | Live |
| cache7.c.youtube.com | Live |
| cache8.c.youtube.com | Live |
| cctldtest.youtube.com | Live |
| cms.youtube.com | Live |
| cyc.youtube.com | Live |
| gdata.youtube.com | Live |
| m.youtube.com | Live |
| misc-sni.youtube.com | Live |
| mx.youtube.com | Live |
| news.youtube.com | Live |
| partner.youtube.com | Live |
| sandbox.youtube.com | Live |
| uberproxy-san.youtube.com | Live |
| upload.youtube.com | Live |
| uploads.stage.gdata.youtube.com | Live |
| www.youtube.com | Live |

## DNS Records
### A Records
- `142.250.192.110`

### AAAA Records
- `2404:6800:4009:82a::200e`

### MX Records
- `0 smtp.google.com.`

### NS Records
- `ns2.google.com.`
- `ns1.google.com.`
- `ns4.google.com.`
- `ns3.google.com.`

### TXT Records
- `"v=spf1 include:google.com mx -all"`
- `"google-site-verification=QtQWEwHWM8tHiJ4s-jJWzEQrD_fF3luPnpzNDH-Nw-w"`
- `"facebook-domain-verification=64jdes7le4h7e7lfpi22rijygx58j1"`

### SOA Records
- `ns1.google.com. dns-admin.google.com. 749513245 900 900 1800 60`

### SPF Records
- `"v=spf1 include:google.com mx -all"`

### DMARC Records
- `"v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"`

## Technology Stack
- react

## HTTP Headers
| Header | Value |
| --- | --- |
| target | `youtube.com` |
| grade | `B-` |

## SSL/TLS Configuration
**Grade:** D

### Certificate Information
**Valid From:** None
**Valid Until:** None
**Expired:** Yes
**Self-Signed:** Yes

### Supported Protocols
- SSLv2: Not Supported
- SSLv3: Not Supported
- TLSv1: Not Supported
- TLSv1.1: Not Supported
- TLSv1.2: Supported
- TLSv1.3: Supported

### Vulnerabilities
- expired_certificate
- self_signed_certificate

## Sensitive Paths
| Path | Sensitivity | Status Code |
| --- | --- | --- |
| phpmyadmin | High | 301 |
| data | Low | 301 |
| backups | High | 301 |
| backup | High | 301 |
| login | High | 301 |
| wp-content | Low | 301 |
| dashboard | Medium | 301 |
| wp-admin | High | 301 |
| admin | High | 301 |
| administrator | High | 301 |
| db | High | 301 |
| config | High | 301 |
| setup | Low | 301 |
| tmp | Low | 301 |
| database | Low | 301 |
| install | Low | 301 |
| uploads | Low | 301 |
| mysql | High | 301 |
| temp | Low | 301 |
| configuration | High | 301 |
| admin.php | High | 301 |
| api | Medium | 301 |
| log | Medium | 301 |
| wp-login.php | High | 301 |
| user | Medium | 301 |
| login.php | High | 301 |
| account | Medium | 301 |
| accounts | Medium | 301 |
| home | Low | 301 |
| users | Medium | 301 |
| robots.txt | Low | 301 |
| logs | Medium | 301 |
| server-status | Low | 301 |
| .env | Low | 301 |
| .svn | Low | 301 |
| .git | Low | 301 |
| test | Low | 301 |
| dev | Low | 301 |
| staging | Low | 301 |
| development | Low | 301 |
| prod | Low | 301 |
| production | Low | 301 |
| phpinfo.php | Low | 301 |
| .DS_Store | Low | 301 |
| info.php | Low | 301 |
| console | Medium | 301 |
| wp-config.php | High | 301 |
| .htaccess | Low | 301 |

## OSINT and Breach Findings
**Total Breaches:** 12

**Emails Found:** 50
- admin@youtube.com
- contact@youtube.com
- david.y@youtube.com
- david.youtube@youtube.com
- david@youtube.com
- david_youtube@youtube.com
- davidyoutube@youtube.com
- help@youtube.com
- hostmaster@youtube.com
- info@youtube.com
- ... and 40 more

### Breach Details
#### Email Breach 1
**Date:** 2019-05-05
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 2
**Date:** 2019-06-08
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 1
**Date:** 2019-05-05
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 2
**Date:** 2019-06-08
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 1
**Date:** 2019-01-01
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 1
**Date:** 2019-01-01
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 1
**Date:** 2019-01-01
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 1
**Date:** 2019-09-09
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 2
**Date:** 2019-10-12
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Email Breach 3
**Date:** 2019-11-15
**Source:** Have I Been Pwned Email Check (Simulated)
**Exposed Data:**
- Email addresses
- Passwords

#### Pastebin Leak 1
**Date:** 2021-06-06
**Source:** Pastebin (Simulated)
**Exposed Data:**
- Email addresses
- API Keys
- Source Code

#### Pastebin Leak 2
**Date:** 2021-07-10
**Source:** Pastebin (Simulated)
**Exposed Data:**
- Email addresses
- API Keys
- Source Code


## Detailed Risk Findings
### Sensitive Paths Risks
#### Multiple sensitive paths exposed (Critical)
Found 48 sensitive paths or directories
**Affected Assets:**
- phpmyadmin
- data
- backups
- backup
- login
- ... and 5 more

#### Highly sensitive paths exposed (Critical)
Paths with high sensitivity are accessible
**Affected Assets:**
- phpmyadmin
- backups
- backup
- login
- wp-admin
- ... and 10 more

### OSINT Risks
#### Data breaches detected (Critical)
Found 12 data breaches involving the domain or associated emails
**Affected Assets:**
- Email Breach 1
- Email Breach 2
- Email Breach 1
- Email Breach 2
- Email Breach 1

#### Credential leaks detected (Critical)
Credentials have been exposed in data breaches
**Affected Assets:**
- Email Breach 1
- Email Breach 2
- Email Breach 1
- Email Breach 2
- Email Breach 1
- ... and 5 more

### SSL/TLS Risks
#### Expired SSL certificate (Critical)
SSL certificate has expired
**Affected Assets:**
- youtube.com

#### Self-signed SSL certificate (High)
Self-signed certificates are not trusted by browsers
**Affected Assets:**
- youtube.com

#### Poor SSL/TLS configuration (Medium)
SSL/TLS configuration received a grade of D
**Affected Assets:**
- youtube.com

### Subdomain Risks
#### Large number of subdomains (Low)
Found 26 subdomains, increasing the attack surface
**Affected Assets:**
- 26 subdomains


---
Report generated by Attack Surface Monitoring Tool on 2025-04-21