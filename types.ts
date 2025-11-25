
export interface Vulnerability {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
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
  
  // Vulnerabilities & Security
  vulnerabilities: Vulnerability[];
  securityHeaders: SecurityHeader[];
  sslInfo: {
    issuer?: string;
    validTo?: string;
    protocol?: string;
    grade?: string;
  };
  
  // Specific Scans
  apiSecurity: string[]; // BOLA, IDOR, Rate Limiting findings
  apiEndpoints?: string[]; // Discovered API routes (e.g., /api/v1/user)
  cloudConfig: string[]; // S3, Azure blobs
  graphql?: boolean;
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
