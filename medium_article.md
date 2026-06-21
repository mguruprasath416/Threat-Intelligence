# Building a Threat Intelligence IOC Dashboard: A Complete Guide for SOC Analysts

## From Zero to a Production-Ready Cyber Threat Intelligence Platform

---

*Published in: Cybersecurity | Threat Intelligence | SOC Operations*

*Reading time: 12 minutes*

---

### Introduction

When I started preparing for Threat Intelligence interviews, I realized that theoretical knowledge alone was not enough. Interviewers wanted candidates who understood real workflows — how analysts actually investigate suspicious IPs, track ransomware groups on Telegram, and correlate threat data from multiple sources.

So I built **IOC Sentinel** — a full-stack Cyber Threat Intelligence dashboard that does exactly what a real CTI team does every day.

This article walks you through what I built, why I built it, and what it teaches you about real-world Threat Intelligence operations.

---

### What Problem Does This Solve?

SOC analysts and CTI teams face a daily challenge: when a suspicious indicator appears — an IP address in a firewall log, a domain in a phishing email, a file hash from a malware alert — they have to manually check it across multiple platforms.

They open VirusTotal in one tab, AbuseIPDB in another, AlienVault OTX in a third. They copy-paste the indicator between them, manually note down the results, and then try to correlate everything together.

This process is slow, error-prone, and exhausting at scale.

**IOC Sentinel solves this by automating the entire pipeline:**

```
Analyst pastes indicator
        ↓
System auto-detects type (IP / domain / URL / hash)
        ↓
Queries VirusTotal + AbuseIPDB + OTX simultaneously
        ↓
Calculates unified threat score (0-100)
        ↓
Maps to MITRE ATT&CK techniques automatically
        ↓
Displays everything in one clean dashboard
```

---

### What is an IOC?

Before diving into the technical details, let me explain the core concept.

An **Indicator of Compromise (IOC)** is any piece of data that suggests a system may have been compromised or is being targeted. Common IOC types include:

- **IP addresses** — Servers used for command and control (C2) or scanning
- **Domains** — Malicious domains used for phishing or malware delivery
- **URLs** — Specific phishing links or malware download URLs
- **File hashes** — MD5, SHA1, or SHA256 fingerprints of malware files

When a security team detects an incident, they collect these indicators and investigate them to understand the threat, its origin, and its severity.

---

### The Tech Stack I Chose

I built this as a full-stack web application using tools that are widely used in the cybersecurity industry:

**Frontend:**
- React 18 for the user interface
- Recharts for data visualization
- Axios for API communication
- Vite as the build tool

**Backend:**
- Node.js with Express for the REST API
- MongoDB with Mongoose for data storage
- JWT for authentication
- Winston for logging
- node-cron for scheduled jobs

**Threat Intelligence APIs:**
- VirusTotal — scans indicators against 90+ antivirus engines
- AbuseIPDB — community-reported IP abuse database
- AlienVault OTX — open threat exchange with millions of threat pulses
- OpenPhish — live phishing URL feed

---

### The Architecture

The system follows a clean three-layer architecture:

```
React Frontend (port 5173)
        ↕  HTTP/JSON
Express Backend (port 5000)
        ↕  Mongoose ODM
MongoDB Database (port 27017)
        ↕  HTTPS
External APIs (VirusTotal, AbuseIPDB, OTX)
```

Every request from the frontend passes through JWT authentication middleware before reaching the controllers. This ensures only authenticated analysts can access the threat data.

---

### How the IOC Enrichment Works

This is the heart of the system. When an analyst submits an indicator, here is exactly what happens:

**Step 1 — Type Detection**

The system uses regex patterns to automatically identify what kind of indicator was submitted:

```javascript
// MD5 hash: exactly 32 hex characters
if (/^[a-fA-F0-9]{32}$/.test(indicator)) return 'hash';

// IPv4 address: four octets
if (/^(\d{1,3}\.){3}\d{1,3}$/.test(indicator)) return 'ip';

// URL: starts with http or https
if (/^https?:\/\/.+/i.test(indicator)) return 'url';

// Domain: label.label format
if (/^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(indicator)) return 'domain';
```

The analyst does not need to specify the type — they just paste and the system figures it out.

**Step 2 — Parallel API Calls**

Instead of calling each API one after another (which would take 3x longer), the system calls them all simultaneously using Promise.allSettled:

```javascript
const [vtResult, abuseResult, otxResult] = await Promise.allSettled([
  virustotalService.enrichIP(ip),
  abuseipdbService.checkIP(ip),
  otxService.getIPData(ip),
]);
```

The key advantage of Promise.allSettled over Promise.all is that even if one API is down or returns an error, the other results are still returned. Partial data is better than no data.

**Step 3 — Threat Score Calculation**

Each API returns different data formats. VirusTotal gives you engine detection counts. AbuseIPDB gives you a confidence percentage. OTX gives you a pulse count. These cannot be directly compared.

The threat scorer normalizes everything to a 0-100 scale and applies weighted averaging:

```
For an IP address:
  VT score   × 40% weight
  Abuse score × 40% weight
  OTX score  × 20% weight
  ─────────────────────────
  Final score = weighted average
```

The weights were chosen based on the reliability and specificity of each source for different indicator types. VirusTotal and AbuseIPDB are equally weighted for IPs because both provide highly relevant data. OTX gets less weight because pulse counts can be influenced by public research not related to malicious activity.

**Step 4 — MITRE ATT&CK Mapping**

After scoring, the system automatically maps the indicator to relevant MITRE ATT&CK techniques based on what the APIs revealed:

```
High AbuseIPDB score with brute-force category
        ↓
Maps to T1110 — Brute Force (Credential Access)

OpenPhish confirms URL as phishing
        ↓
Maps to T1566.002 — Spearphishing Link (Initial Access)

High VT detections on a file hash
        ↓
Maps to T1204.002 — Malicious File (Execution)
```

This contextualizes the raw indicator data into attacker behavior language that security teams understand.

---

### The Dashboard

The main dashboard gives analysts a real-time overview of their threat landscape:

**Four KPI Cards** show total IOC count, critical threats, high threats, and medium threats at a glance.

**Severity Donut Chart** shows the distribution of threat levels across all indicators — are most threats low severity or are there many critical ones?

**IOC Type Breakdown** shows what kinds of indicators the team is investigating — mostly IPs? More domains? This helps identify what attack vectors are most active.

**30-Day Trend Chart** shows whether threat activity is increasing or decreasing over the past month. A sudden spike often indicates an active campaign.

**Top Countries Chart** shows where threats are geographically originating — useful for understanding which threat actors may be involved.

---

### The Live Threat Feed

The system runs a background job every 6 hours that automatically downloads the OpenPhish phishing URL feed and imports all fresh phishing URLs into the database.

This means analysts arrive at work each morning to a dashboard already populated with the latest phishing threats — they do not need to manually import anything.

The Threat Feed page shows a live scrolling ticker of critical and high severity threats at the top, followed by a filterable table of all active indicators. The page auto-refreshes every 30 seconds.

---

### Authentication and Access Control

Security tools need strong access control. The system implements:

**JWT Authentication:** After login, the server generates a signed JWT token containing the user ID and role. This token is sent with every subsequent request in the Authorization header. The server verifies the signature on each request without needing to query the database.

**Role-Based Access Control:** Two roles exist — Analyst and Admin. Analysts can search IOCs, view data, and flag false positives. Admins have additional permissions to delete IOCs and manage the system. The first registered user automatically receives the Admin role.

**Per-User Data Isolation:** Each user only sees their own IOCs. When user A searches an IP, user B cannot see that search result. This is enforced at the database query level by always filtering on the submittedBy field.

---

### What I Learned Building This

**1. Parallel API calls are essential in threat intelligence**

When you are investigating a live incident, speed matters. Making three sequential API calls might take 9-12 seconds total. Making them in parallel takes 3-4 seconds — the time of the slowest single call. In a real SOC environment, analysts investigate dozens of indicators per incident. Those seconds add up.

**2. Cache everything with a TTL**

Threat intelligence data does not change minute-to-minute. An IP flagged as malicious at 9am will still be flagged at 10am. Caching enrichment results for 24 hours means the second analyst to look up the same indicator gets an instant result instead of waiting for API calls. This also preserves free API quota.

**3. Partial data is better than no data**

Using Promise.allSettled instead of Promise.all means the system continues working even if one API is down. An analyst gets VirusTotal and AbuseIPDB results even if OTX is temporarily unavailable. A real-world tool must be resilient to third-party failures.

**4. Normalization is the key challenge in threat intelligence**

Every data source speaks a different language. The biggest engineering challenge was not calling the APIs — it was creating a scoring system that meaningfully combines data from sources with completely different output formats. This is exactly the challenge real CTI platforms like Recorded Future and ThreatConnect solve at scale.

**5. MITRE ATT&CK is the common language of security**

Adding MITRE technique mapping transformed the tool from a lookup database into an investigation assistant. Instead of just saying "this IP is malicious," the system now says "this IP is being used for T1110 brute force attacks in the Credential Access tactic." That context dramatically changes how an analyst responds.

---

### How This Relates to Real CTI Work

The workflows this system automates mirror exactly what CTI analysts do manually every day:

**Telegram Monitoring:** Analysts watch channels where hackers post stolen data. When a new post appears with IOCs, they extract the indicators and run them through enrichment tools like this one.

**Stealer Log Analysis:** When stealer logs appear containing corporate credentials, analysts check the associated infrastructure (C2 IPs, download domains) against threat intelligence. This dashboard is the tool they use for that check.

**Ransomware Investigation:** When a ransomware group announces a new victim, analysts look up the group's known infrastructure in threat intelligence databases. The search functionality here supports that workflow.

**Incident Response:** During active incidents, analysts collect IOCs from logs and alerts and need to quickly understand their threat level. This dashboard turns a 10-minute manual investigation into a 30-second automated one.

---

### What This Project Demonstrates for Interviews

When a CTI interviewer asks "how does IOC enrichment work?", most candidates describe the concept. I can open this dashboard and show them.

When they ask about MITRE ATT&CK, I can show automatic technique mapping on real indicators.

When they ask about threat scoring, I can explain the weighted algorithm I designed and why I made those choices.

**This is the difference between knowing about threat intelligence and demonstrating threat intelligence.**

---

### The Honest Gaps

This is a portfolio project, not a production enterprise platform. There are intentional gaps:

**No Telegram monitoring integration** — The system understands Telegram-based threats conceptually but does not directly connect to the Telegram API. Adding that would require additional infrastructure for persona management and legal compliance.

**No SIEM integration** — Enterprise CTI platforms integrate with Splunk, Microsoft Sentinel, or QRadar. This is a standalone tool.

**Single-user API quota** — All enrichment calls share one set of API keys. At enterprise scale, you would need key rotation and quota management.

**No threat actor profiling** — The system tracks IOCs but does not automatically group them into threat actor campaigns. That correlation is still manual.

These gaps are features of scope, not bugs. Knowing what is missing and why is itself a demonstration of CTI maturity.

---

### Technical Stack Summary

```
Frontend:   React + Vite + Recharts + Axios
Backend:    Node.js + Express + MongoDB + Mongoose
Auth:       JWT + bcrypt
Logging:    Winston
Scheduling: node-cron
APIs:       VirusTotal, AbuseIPDB, AlienVault OTX, OpenPhish
Deployment: Railway (backend + frontend) + MongoDB Atlas
```

---

### Getting Started

The project is open source. You can run it locally with:

```bash
# Clone the repository
git clone https://github.com/mguruprasath416/Threat-Intelligence.git
cd Threat-Intelligence

# Setup backend
cd backend/server
npm install
# Create .env with your API keys
npm run dev

# Setup frontend (new terminal)
cd client
npm install
npm run dev
```

Free API keys for VirusTotal, AbuseIPDB, and AlienVault OTX are available with a simple registration on each platform.

---

### Conclusion

Building this project taught me more about real CTI workflows than any course or certification I have taken.

The challenge of normalizing data from three different APIs into one coherent score taught me why threat intelligence correlation is hard. The MITRE mapping implementation taught me to think about threats in terms of attacker behavior, not just indicator metadata. The authentication and access control implementation taught me that security tools must themselves be secure.

For anyone preparing for SOC Analyst or CTI roles: build something. Not a tutorial project — something that solves a real problem you care about. The ability to say "I built this, here is how it works, here is what I learned" is more valuable in an interview than any certification.

---

### GitHub Repository

`https://github.com/mguruprasath416/Threat-Intelligence`

---

*If this article helped you, follow me for more content on Threat Intelligence, SOC operations, and cybersecurity engineering.*

*Tags: #CyberSecurity #ThreatIntelligence #SOC #CTI #React #NodeJS #MITRE #IOC #Malware #InfoSec*
