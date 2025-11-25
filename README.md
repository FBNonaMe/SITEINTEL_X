# 💀 SiteIntel-X: AI Offensive Intelligence Suite

![License](https://img.shields.io/badge/License-MIT-red.svg)
![Status](https://img.shields.io/badge/Status-WEAPONIZED-red)
![AI](https://img.shields.io/badge/AI-Gemini%202.5-cyan)
![Type](https://img.shields.io/badge/Type-Red%20Teaming-purple)

> **"The only secure system is one that is powered off."**

**SiteIntel-X** is a next-generation **Automated Red Teaming & Reconnaissance Platform**. It leverages **Google Gemini's** advanced reasoning to simulate complex cyber-attack chains, perform deep OSINT, and generate weaponized exploits in real-time.

Unlike traditional scanners that rely on static signatures, SiteIntel-X *infers* vulnerabilities based on architectural patterns, context, and leaked metadata.

---

## ⚡ Capabilities

### 👁️ PASSIVE_MODE (Ghost Protocol)
*The silent stalker. Gathers intelligence without triggering IDS/IPS.*

*   **Deep OSINT**: Scrapes LinkedIn and social footprints to identify key technical staff (Social Engineering targets).
*   **Mail Security Audit**: Analyzes SPF/DMARC records to determine if the domain is vulnerable to **Email Spoofing**.
*   **Archive Archaeology**: Digs through the **Wayback Machine** to find deprecated API endpoints (`/v1`, `/admin_old`) and forgotten backups.
*   **Leak Hunter**: Scours the Dark Web and breach databases for compromised credentials associated with the domain.
*   **Metadata Extraction**: Uses Google Dorks to find publicly indexed sensitive documents (PDF, XLS, DOCX, CONF).

### 💥 AGGRESSIVE_MODE (Assault Protocol)
*The battering ram. Active engagement and exploitation simulation.*

*   **Nuclei & Nmap Simulation**: Infers open ports, services, and maps the technology stack to specific **CVEs**.
*   **Cloud Raider**: Scans **AWS S3, Azure Blob, and GCP Storage** for exposed buckets and configuration files (`.env`, `terraform.tfstate`).
*   **Subdomain Takeover**: Identifies dangling CNAME records pointing to unclaimed third-party services (critical risk).
*   **Credential Access**:
    *   **Panel Enum**: Locates admin interfaces (`/wp-admin`, `/manager`).
    *   **Default Creds**: Suggests default logins based on the stack (e.g., `tomcat:s3cret`).
    *   **Password Spray**: Generates a custom brute-force wordlist based on the target's profile.
*   **Path Traversal / LFI**: Hunts for file inclusion parameters to read system files (`/etc/passwd`).
*   **API & GraphQL**: Checks for Introspection, BOLA, and IDOR vulnerabilities.
*   **Client-Side SAST**: Scans JavaScript bundles for hardcoded API keys (Stripe, AWS) and dangerous DOM sinks (`eval()`).

---

## 🛠️ The Arsenal

### 💉 The Weaponizer (Auto-Exploit)
Found a CVE? SiteIntel-X writes the code for you.
*   **Context-Aware**: Generates Python 3 `requests` scripts tailored to the target's specific tech stack.
*   **Safe Verification**: Creates Proof-of-Concept (PoC) payloads (e.g., `whoami`, `version()`) to verify flaws without destroying the server.

### 🎣 Phishing Lure Generator
*   Auto-generates convincing "Security Update" email templates based on the detected software versions to trick admins into handing over credentials.

### 📊 Cyberpunk Dashboard
*   **Recon Tab**: Subdomains, Ports, Hidden Dirs.
*   **Vulns Tab**: CVEs, Weaponized URLs (SQLi/XSS).
*   **Intel Tab**: Emails, WAF Detect, Credential Access.
*   **Infra Tab**: Geolocation, Whois, Leaks.
*   **Client Tab**: DOM XSS, Subdomain Takeover.

---

## 🚀 Installation & Usage

### Prerequisites
*   Node.js & npm
*   Google Gemini API Key (Paid Tier recommended for high throughput)

### Setup

```bash
# Clone the repository
git clone https://github.com/FBNonaMe/SITEINTEL_X

# Enter the war room
cd siteintel-x

# Install dependencies
npm install

# Set your warhead (API Key)
# Create a .env file and add:
# API_KEY=your_gemini_api_key_here

# Launch
npm start
```

---

## ⚠️ Disclaimer

**SiteIntel-X is designed for AUTHORIZED security audits and educational purposes only.**

Using this tool against targets without prior mutual consent is illegal. The developer accepts no responsibility for any damage caused by the misuse of this software.

*Scan responsibly. Or don't. I'm code, not a cop.* 😈

---

<div align="center">
  <sub> FBNonaMe</sub>
</div>
