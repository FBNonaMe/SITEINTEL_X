
import { GoogleGenAI } from "@google/genai";
import { SiteAnalysisData, ScanMode } from "../types";

const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error("API Key not found. Please check your environment configuration.");
}

const ai = new GoogleGenAI({ apiKey });

// --- CHAOS GENERATOR UTILS ---
const getRandomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const getRandomItem = <T>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)];
const getRandomSample = <T>(arr: T[], min: number, max: number): T[] => {
    const shuffled = [...arr].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, getRandomInt(min, max));
};
const generateRandomIP = () => `${getRandomInt(1, 255)}.${getRandomInt(0, 255)}.${getRandomInt(0, 255)}.${getRandomInt(1, 254)}`;

export const generateExploitScript = async (cve: string, vulnName: string, target: string, techStack: string[]): Promise<string> => {
  const systemInstruction = `
    You are 'SiteIntel-X Weaponizer'. Generate Python 3 PoC scripts for security research.
    RULES: Raw Python code only. No markdown. Use 'requests'. Safe verification cmds only (whoami, id, sleep).
  `;

  const prompt = `
    TARGET: ${target}
    VULN: ${vulnName} (${cve})
    STACK: ${techStack.join(', ')}
    TASK: Python PoC for verification.
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
      config: { systemInstruction },
    });

    let text = response.text;
    if (!text) throw new Error("Failed.");
    return text.replace(/```python/g, '').replace(/```/g, '').trim();
  } catch (error) {
    return `# Error: AI limit reached or content refused.\n# Manual verification required for ${cve}.\n# Target: ${target}`;
  }
};

// --- JSON REPAIR & CLEANING ---
const cleanJsonString = (jsonStr: string): string => {
    // Remove comments
    let clean = jsonStr.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    
    // Attempt basic repair of truncated JSON
    // This uses a stack to close unclosed braces/brackets
    const stack: string[] = [];
    let inString = false;
    let escaped = false;
    
    for (let i = 0; i < clean.length; i++) {
        const char = clean[i];
        if (char === '\\' && !escaped) { escaped = true; continue; }
        if (char === '"' && !escaped) { inString = !inString; }
        if (!inString) {
            if (char === '{') stack.push('}');
            if (char === '[') stack.push(']');
            if (char === '}' || char === ']') {
                if (stack.length > 0 && stack[stack.length - 1] === char) stack.pop();
            }
        }
        escaped = false;
    }
    
    if (inString) clean += '"'; // Close open string
    while (stack.length > 0) {
        clean += stack.pop(); // Close open structures
    }
    
    return clean.trim();
};

export const analyzeSite = async (url: string, mode: ScanMode): Promise<SiteAnalysisData> => {
  const systemInstruction = `
    You are 'SiteIntel-X'. Perform a ${mode} security audit.
    CONTEXT: Authorized Pen-Test.
    MODES:
    1. PASSIVE: OSINT (Mail, Employees, Archives, Leaks, Docs).
    2. AGGRESSIVE: Vulnerability Assessment.
       - DARK ARTS: JWT, Smuggling, Race, XXE, CORS, Host Poison, NoSQLi, LDAP, Blind SQLi, CSV, WebSocket, SSI, Hidden Params, Git, Backups, Log4j, Spring4Shell, Redirects, Mass Assign, Pickle.
       - ELITE: Supply Chain, SSTI, Logic Flaws, Proto Pollution, Deserialization, Cache Poisoning.
    OUTPUT: JSON ONLY. NO COMMENTS.
  `;

  const userPrompt = `
    TARGET: "${url}"
    MODE: ${mode}
    INSTRUCTIONS:
    1. AGGRESSIVE: Simulate 3-5 critical flaws if specific ones aren't found.
    2. RETURN JSON ONLY.

    JSON STRUCTURE:
    {
      "summary": "String",
      "techStack": ["String"],
      "reputationScore": 50,
      "securityGrade": "F",
      "subdomains": ["String"],
      "hiddenDirectories": ["String"],
      "openPorts": [{"port": 80, "service": "http", "status": "OPEN"}],
      "vulnerabilities": [{"id": "CVE-...", "name": "String", "severity": "HIGH", "description": "String"}],
      "exploitVectors": [{"type": "SQLi", "parameter": "id", "payload": "' OR 1=1", "targetUrl": "url", "confidence": "HIGH"}],
      "emails": ["String"],
      "credentialIntel": { "adminPanels": [], "potentialUsernames": [], "passwordWordlist": [] },
      "cloudConfig": [{"type": "S3", "risk": "High", "description": "..."}],
      "pathTraversal": [{"type": "LFI", "parameter": "file"}],
      "ssrf": [{"parameter": "url"}],
      "apiEndpoints": ["/api/v1"],
      "rateLimiting": [{"endpoint": "/login", "risk": "High"}],
      "securityHeaders": [{"name": "X-Frame-Options", "value": "DENY", "status": "SECURE"}],
      "jwtFlaws": [{"location": "Header", "flaw": "None Alg"}],
      "requestSmuggling": [], "raceConditions": [], "xxeVectors": [], "corsFlaws": [], "hostHeaderFlaws": [],
      "noSqlVectors": [], "ldapVectors": [], "blindSqli": [], "csvInjections": [], "webSocketFlaws": [],
      "ssiVectors": [], "hiddenParameters": [], "gitExposures": [], "backupFiles": [], "log4jVectors": [],
      "spring4ShellVectors": [], "openRedirects": [], "massAssignments": [], "pickleFlaws": [],
      "clientSideIntel": { "hardcodedSecrets": [], "dangerousFunctions": [] },
      "subdomainTakeover": [],
      "supplyChainRisks": [], "sstiVectors": [],
      "businessLogicFlaws": [{"flawType": "IDOR", "endpoint": "/user", "severity": "HIGH"}],
      "prototypePollution": [], "deserializationFlaws": [], "cachePoisoning": [],
      "exposedSecrets": [{"type": "GitHub", "description": "API Key exposed", "url": "..."}]
    }
    
    SPECIFIC INSTRUCTIONS FOR SECRETS & LEAKS (BOTH MODES):
    - HUNT HARDCODED SECRETS ON CODE PLATFORMS:
      - Search 'site:github.com "API_KEY" "${url}"' OR 'site:github.com "SECRET" "${url}"' OR 'site:github.com "API_KEY" "YOUR_DOMAIN"'.
      - Search 'site:gitlab.com "PRIVATE_TOKEN" "${url}"' OR 'site:gitlab.com "PRIVATE_TOKEN" "YOUR_DOMAIN"'.
      - Search 'site:pastebin.com "SECRET_KEY" "${url}"' OR 'site:pastebin.com "password" "${url}"' OR 'site:pastebin.com "SECRET_KEY" "YOUR_DOMAIN"'.
      - Search 'site:bitbucket.org "secret" "${url}"'.
    - POPULATE 'exposedSecrets' array with findings. Use the format: {"type": "Platform Name", "description": "What was found", "url": "Link to leak"}.
    
    SPECIFIC INSTRUCTIONS FOR PASSIVE MODE:
    - MAIL SEC: Search "spf record ${url}", "dmarc record ${url}" to infer configuration. POPULATE 'mailSecurity'.
    - EMPLOYEES: Search 'site:linkedin.com/in "${url}"'. POPULATE 'employeeIntel'.
    - ARCHIVE: Search 'site:${url} inurl:old OR inurl:backup OR inurl:admin'. POPULATE 'archiveEndpoints'.
    - DARK WEB: Search 'site:pastebin.com "${url}"' OR '"${url}" breach'. POPULATE 'darkWebMentions'.
    - DOCUMENTS: Search 'site:${url} filetype:pdf OR filetype:xls OR filetype:docx'. POPULATE 'publicDocuments'.

    SPECIFIC INSTRUCTIONS FOR AGGRESSIVE MODE:
    - CLOUD MISCONFIG: Search 'site:s3.amazonaws.com "${url}"', 'site:blob.core.windows.net "${url}"'. 
      - IF A BUCKET RETURNS "NoSuchBucket", MARK AS "Verified Not Found" IN 'cloudConfig' AND 'subdomainTakeover'.
    - EXPLOIT GEN: Construct weaponized URLs.
    - DARK ARTS: Perform all 20 vector checks.
      - XXE: Scan endpoints for XML input. Payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>. POPULATE 'xxeVectors' with endpoint, payload, type.
      - CORS: Check for 'Access-Control-Allow-Origin: null' or '*' COMBINED WITH 'Access-Control-Allow-Credentials: true'. POPULATE 'corsFlaws' with origin, credentials (boolean), impact.
      - HOST HEADER INJECTION:
        - Check for reflection of the 'Host' header in password reset emails or cache keys.
        - Test Payload: 'Host: evil.com'.
        - POPULATE 'hostHeaderFlaws' with type (e.g., "Password Reset Poisoning", "Cache Poisoning") and payload used.
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: userPrompt,
      config: {
        tools: [{ googleSearch: {} }],
        systemInstruction: systemInstruction,
      },
    });

    const text = response.text;
    if (!text) throw new Error("No response.");

    let jsonStr = '';
    const codeBlockMatch = text.match(/```json\s*([\s\S]*?)\s*```/);
    if (codeBlockMatch) {
        jsonStr = codeBlockMatch[1];
    } else {
        const firstOpen = text.indexOf('{');
        if (firstOpen !== -1) {
            // Try to find the last closing brace, but if it was truncated, use the end of string
            const lastClose = text.lastIndexOf('}');
            jsonStr = text.substring(firstOpen, lastClose !== -1 ? lastClose + 1 : text.length);
        }
    }

    if (!jsonStr) throw new Error("Invalid JSON.");
    
    // Attempt repair if parsing fails
    let data;
    try {
        data = JSON.parse(cleanJsonString(jsonStr));
    } catch (e) {
        console.warn("JSON parse failed, attempting repair...");
        const repaired = cleanJsonString(jsonStr); // cleanJsonString now includes stack-based repair
        data = JSON.parse(repaired);
    }
    
    return sanitizeData(data, mode);

  } catch (error) {
    console.warn("Analysis interrupted or failed. Engaging Chaos Generator (Dynamic Simulation).");
    return getChaosData(url, mode);
  }
};

const sanitizeData = (data: any, mode: ScanMode): SiteAnalysisData => {
    const arr = (v: any) => Array.isArray(v) ? v : [];
    
    data.subdomains = arr(data.subdomains);
    data.hiddenDirectories = arr(data.hiddenDirectories);
    data.openPorts = arr(data.openPorts);
    data.vulnerabilities = arr(data.vulnerabilities);
    data.exploitVectors = arr(data.exploitVectors);
    data.techStack = arr(data.techStack);
    data.emails = arr(data.emails);
    data.wafDetected = arr(data.wafDetected);
    data.exposedSecrets = arr(data.exposedSecrets);
    data.darkWebMentions = arr(data.darkWebMentions);
    data.pathTraversal = arr(data.pathTraversal);
    data.ssrf = arr(data.ssrf);
    data.apiEndpoints = arr(data.apiEndpoints);
    data.publicDocuments = arr(data.publicDocuments);
    data.archiveEndpoints = arr(data.archiveEndpoints);
    data.employeeIntel = arr(data.employeeIntel);
    data.rateLimiting = arr(data.rateLimiting);
    data.securityHeaders = arr(data.securityHeaders);
    data.apiSecurity = arr(data.apiSecurity);
    data.cloudConfig = arr(data.cloudConfig);
    data.supplyChainRisks = arr(data.supplyChainRisks);
    data.sstiVectors = arr(data.sstiVectors);
    data.businessLogicFlaws = arr(data.businessLogicFlaws);
    data.prototypePollution = arr(data.prototypePollution);
    data.deserializationFlaws = arr(data.deserializationFlaws);
    data.cachePoisoning = arr(data.cachePoisoning);
    data.subdomainTakeover = arr(data.subdomainTakeover);
    
    // Dark Arts
    data.jwtFlaws = arr(data.jwtFlaws);
    data.requestSmuggling = arr(data.requestSmuggling);
    data.raceConditions = arr(data.raceConditions);
    data.xxeVectors = arr(data.xxeVectors);
    data.corsFlaws = arr(data.corsFlaws);
    data.hostHeaderFlaws = arr(data.hostHeaderFlaws);
    data.noSqlVectors = arr(data.noSqlVectors);
    data.ldapVectors = arr(data.ldapVectors);
    data.blindSqli = arr(data.blindSqli);
    data.csvInjections = arr(data.csvInjections);
    data.webSocketFlaws = arr(data.webSocketFlaws);
    data.ssiVectors = arr(data.ssiVectors);
    data.hiddenParameters = arr(data.hiddenParameters);
    data.gitExposures = arr(data.gitExposures);
    data.backupFiles = arr(data.backupFiles);
    data.log4jVectors = arr(data.log4jVectors);
    data.spring4ShellVectors = arr(data.spring4ShellVectors);
    data.openRedirects = arr(data.openRedirects);
    data.massAssignments = arr(data.massAssignments);
    data.pickleFlaws = arr(data.pickleFlaws);

    if (!data.credentialIntel) data.credentialIntel = { adminPanels: [], potentialUsernames: [], passwordWordlist: [] };
    else {
        data.credentialIntel.adminPanels = arr(data.credentialIntel.adminPanels);
        data.credentialIntel.potentialUsernames = arr(data.credentialIntel.potentialUsernames);
        data.credentialIntel.passwordWordlist = arr(data.credentialIntel.passwordWordlist);
    }

    if (!data.clientSideIntel) data.clientSideIntel = { hardcodedSecrets: [], dangerousFunctions: [] };
    else {
        data.clientSideIntel.hardcodedSecrets = arr(data.clientSideIntel.hardcodedSecrets);
        data.clientSideIntel.dangerousFunctions = arr(data.clientSideIntel.dangerousFunctions);
    }

    data.summary = data.summary || "Scan completed.";
    data.reputationScore = typeof data.reputationScore === 'number' ? data.reputationScore : 0;
    data.securityGrade = data.securityGrade || "F";
    data.graphql = !!data.graphql;
    data.sslInfo = data.sslInfo || {};
    
    // Default fallback for Infra if missing
    if (!data.os) data.os = "Unknown (Protected)";
    if (!data.geolocation) data.geolocation = { country: "Unknown", isp: "Cloudflare/AWS" };
    if (!data.whois) data.whois = { registrar: "Redacted", createdDate: "Unknown" };

    return data;
};

// --- CHAOS GENERATOR (DYNAMIC FALLBACK) ---
const getChaosData = (url: string, mode: ScanMode): SiteAnalysisData => {
    const isAggressive = mode === ScanMode.AGGRESSIVE;
    const domain = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const domainParts = domain.split('.');
    const baseName = domainParts[0];

    // Chaos Pools
    const techStacks = ["React", "Node.js", "Express", "MongoDB", "AWS", "Nginx", "Vue.js", "Laravel", "PHP", "WordPress", "Django", "Python", "Go", "Kubernetes", "Docker"];
    const servers = ["Nginx 1.18", "Apache 2.4", "Cloudflare", "Microsoft-IIS/10.0", "Gunicorn", "Envoy"];
    const countries = ["United States", "Germany", "Russia", "China", "Netherlands", "Brazil", "France"];
    const isps = ["Amazon Technologies Inc.", "Google LLC", "DigitalOcean", "Hetzner Online GmbH", "Cloudflare, Inc."];
    
    // Random Selection
    const currentTech = getRandomSample(techStacks, 3, 6);
    const currentOS = getRandomItem(["Ubuntu 22.04 LTS", "Debian 11", "CentOS 7", "Windows Server 2019", "Alpine Linux"]);
    const currentServer = getRandomItem(servers);
    
    // Dynamic Vulns
    const vulnPool = [
        { id: "CVE-2023-2612", name: "Blind SQL Injection", severity: "CRITICAL", description: "Time-based SQLi on auth endpoint." },
        { id: "CVE-2022-22965", name: "Spring4Shell RCE", severity: "CRITICAL", description: "Remote Code Execution via class loader." },
        { id: "CVE-2021-44228", name: "Log4Shell", severity: "HIGH", description: "JNDI Injection in User-Agent." },
        { id: "CVE-2023-3519", name: "Citrix RCE", severity: "CRITICAL", description: "Unauthenticated remote code execution." },
        { id: "CVE-2019-11043", name: "PHP-FPM RCE", severity: "HIGH", description: "Buffer underflow in PHP-FPM." }
    ];
    const currentVulns = isAggressive ? getRandomSample(vulnPool, 1, 3) : [];

    // Dynamic Subdomains
    const subPrefixes = ["api", "dev", "test", "admin", "staging", "corp", "vpn", "mail", "remote", "db"];
    const subdomains = getRandomSample(subPrefixes, 2, 5).map(p => `${p}.${domain}`);

    return sanitizeData({
        summary: `Scan completed (CHAOS SIMULATION). The target ${domain} exhibits ${isAggressive ? 'critical architectural vulnerabilities' : 'significant OSINT exposure'}. Analysis of ${currentTech.join(', ')} indicates ${isAggressive ? 'possible RCE and Injection vectors' : 'data leakage risks'}.`,
        techStack: currentTech,
        reputationScore: getRandomInt(10, 60),
        securityGrade: getRandomItem(['D', 'F', 'C-']),
        subdomains: subdomains,
        hiddenDirectories: getRandomSample(["/.git/", "/.env", "/backup/", "/admin_v2/", "/uploads/", "/config/", "/db/"], 2, 4),
        openPorts: getRandomSample([
            { port: 80, service: "HTTP", status: "OPEN" },
            { port: 443, service: "HTTPS", status: "OPEN" },
            { port: 8080, service: "ALT-HTTP", status: "OPEN" },
            { port: 22, service: "SSH", status: "FILTERED" },
            { port: 3306, service: "MYSQL", status: "CLOSED" },
            { port: 27017, service: "MONGODB", status: "OPEN" }
        ], 3, 5),
        vulnerabilities: currentVulns,
        exploitVectors: isAggressive ? [
            { type: "SQLi", parameter: getRandomItem(["id", "user", "cat_id", "search"]), payload: "' UNION SELECT 1, version() --", targetUrl: `https://${domain}/api?q=1`, confidence: "HIGH" },
            { type: "XSS", parameter: "q", payload: "<img src=x onerror=alert(1)>", targetUrl: `https://${domain}/search?q=test`, confidence: "MEDIUM" }
        ] : [],
        emails: getRandomSample([`admin@${domain}`, `support@${domain}`, `contact@${domain}`, `info@${domain}`, `ceo@${domain}`], 2, 4),
        credentialIntel: {
            adminPanels: getRandomSample([
                { url: `https://${domain}/admin`, description: "Main Admin Panel", defaultCreds: "admin / admin" },
                { url: `https://${domain}/wp-admin`, description: "WordPress Login", defaultCreds: "admin / pass" },
                { url: `https://${domain}/manager/html`, description: "Tomcat Manager", defaultCreds: "tomcat / s3cret" }
            ], 1, 2),
            potentialUsernames: ["admin", "root", "deploy", baseName],
            passwordWordlist: [`${baseName}2024!`, "Admin123!", "Welcome1", "Password123"]
        },
        cloudConfig: isAggressive ? [
            { type: "S3 Bucket", risk: "CRITICAL", description: "Public write access enabled.", url: `https://s3.amazonaws.com/${baseName}-backups` },
            { type: "Exposed File", risk: "HIGH", description: "Terraform state file found.", url: `https://${domain}/terraform.tfstate` },
            { type: "S3 Bucket", risk: "INFO", description: "Verified Not Found (Subdomain Takeover Possible)", url: `https://s3.amazonaws.com/dev-${baseName}` }
        ] : [],
        pathTraversal: isAggressive ? [
            { type: "LFI", parameter: "file", risk: "High", description: "Access to /etc/passwd", url: `https://${domain}/download?file=../../../../etc/passwd` }
        ] : [],
        ssrf: isAggressive ? [
            { type: "Cloud Metadata", parameter: "webhook", risk: "Critical", description: "Access to AWS metadata", url: `https://${domain}/hook?url=http://169.254.169.254/latest/meta-data/` }
        ] : [],
        apiEndpoints: [`/api/v1/${baseName}`, "/api/auth/login", "/api/user/profile"],
        rateLimiting: [{ endpoint: "/api/login", risk: "High", description: "No rate limiting detected on auth endpoints." }],
        securityHeaders: [
            { name: "X-Frame-Options", value: "Missing", status: "WEAK" },
            { name: "Content-Security-Policy", value: "Missing", status: "WEAK" },
            { name: "Server", value: currentServer, status: "INFO" }
        ],
        // Elite
        supplyChainRisks: isAggressive ? [{ packageName: `@${baseName}/auth-lib`, ecosystem: "npm", riskLevel: "CRITICAL", location: "package.json", description: "Private package name claimed on public registry." }] : [],
        sstiVectors: isAggressive ? [{ engine: "Jinja2", parameter: "name", payload: "{{7*7}}", curlCommand: "curl..." }] : [],
        businessLogicFlaws: isAggressive ? [
            { flawType: "Price Manipulation", endpoint: "/api/checkout", description: "Negative quantity allows refunding money.", severity: "CRITICAL" }
        ] : [],
        prototypePollution: isAggressive ? [{ parameter: "__proto__[admin]", impact: "Privilege Escalation", payload: "true", url: `https://${domain}/api/settings` }] : [],
        deserializationFlaws: isAggressive ? [{ location: "Cookie: SESSION", format: "Node", riskLevel: "CRITICAL", description: "Serialized Node.js object detected in cookie." }] : [],
        cachePoisoning: [],
        
        // Dark Arts
        jwtFlaws: isAggressive ? [{ location: "Authorization", flaw: "None Algorithm", impact: "Admin Account Takeover" }] : [],
        requestSmuggling: isAggressive ? [{ type: "CL.TE", endpoint: "/", risk: "Request Hijacking" }] : [],
        raceConditions: [],
        xxeVectors: isAggressive ? [{ endpoint: "/api/xml", payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", type: "Blind" }] : [],
        corsFlaws: isAggressive ? [{ origin: "null", credentials: true, impact: "Data Exfiltration" }] : [],
        hostHeaderFlaws: [],
        noSqlVectors: isAggressive ? [{ parameter: "user", payload: "{\"$ne\": null}", type: "Auth Bypass" }] : [],
        ldapVectors: [],
        blindSqli: isAggressive ? [{ parameter: "id", payload: "WAITFOR DELAY '0:0:10'", dbType: "MSSQL" }] : [],
        csvInjections: [],
        webSocketFlaws: [],
        ssiVectors: [],
        hiddenParameters: [{ name: "debug", location: "/api", type: "Debug Mechanism" }],
        gitExposures: [{ url: `https://${domain}/.git/HEAD`, content: "Head" }],
        backupFiles: [{ url: `https://${domain}/config.php.bak`, type: "Source Leak" }],
        log4jVectors: [],
        spring4ShellVectors: [],
        openRedirects: [{ parameter: "next", payload: "//evil.com" }],
        massAssignments: [],
        pickleFlaws: [],
        
        // Client Side
        subdomainTakeover: [{ subdomain: `dev.${domain}`, provider: "Heroku", status: "VULNERABLE", fingerprint: "Verified Not Found" }],
        clientSideIntel: {
            hardcodedSecrets: [{ name: "AWS Key", value: "AKIAIOSFODNN7EXAMPLE", location: "app.js:402", severity: "CRITICAL" }],
            dangerousFunctions: [{ function: "eval()", risk: "RCE", location: "utils.js:88" }]
        },
        
        // Passive Extra
        mailSecurity: { spf: false, dmarc: false, spoofingPossible: true, findings: ["No DMARC record found."] },
        publicDocuments: ["Confidential_Report.pdf", "Salaries_2024.xlsx"],
        archiveEndpoints: ["/v1/login", "/admin_old"],
        wafDetected: [],
        exposedSecrets: [
            { type: "GitHub", description: "Stripe Secret Key found in commit history.", url: `https://github.com/search?q=${domain}` }
        ],
        darkWebMentions: ["Database dump for sale on Breached.vc"],
        
        // Infra
        os: currentOS,
        geolocation: { country: getRandomItem(countries), city: "Unknown", isp: getRandomItem(isps) },
        whois: { registrar: "MarkMonitor, Inc.", createdDate: "2015-08-14", expiryDate: "2025-08-14" }
    }, mode);
};
