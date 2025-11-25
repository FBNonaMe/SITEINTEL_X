import React, { useState } from 'react';
import { analyzeSite } from './services/geminiService';
import { SiteAnalysisData, ScanStatus, ScanMode } from './types';
import ScannerInput from './components/ScannerInput';
import ResultDashboard from './components/ResultDashboard';
import { Radar, Terminal, ShieldCheck, Skull, Fingerprint, Ghost, AlertTriangle } from 'lucide-react';

const App: React.FC = () => {
  const [status, setStatus] = useState<ScanStatus>(ScanStatus.IDLE);
  const [data, setData] = useState<SiteAnalysisData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (url: string, mode: ScanMode) => {
    setStatus(ScanStatus.SCANNING);
    setError(null);
    setData(null);

    try {
      const result = await analyzeSite(url, mode);
      setData(result);
      setStatus(ScanStatus.COMPLETE);
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred during the scan.");
      setStatus(ScanStatus.ERROR);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 relative overflow-x-hidden selection:bg-red-500/30 selection:text-red-100">
      
      {/* Background Grid Effect - More aggressive red tint */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none opacity-20"></div>

      <header className="relative pt-8 pb-16 px-4 text-center">
        <div className="inline-flex items-center justify-center p-2 mb-4 bg-slate-900/80 rounded-full border border-slate-800 shadow-xl backdrop-blur-md">
            <Skull className="w-3 h-3 text-red-500 mr-2 animate-pulse" />
            <span className="text-xs font-mono text-slate-400">OFFENSIVE_CYBER_INTEL // V 2.0.0</span>
        </div>
        <h1 className="text-4xl md:text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-purple-500 to-cyan-500 mb-4 tracking-tighter">
          SITE<span className="text-white">INTEL</span>_X
        </h1>
        <p className="text-slate-400 max-w-xl mx-auto text-lg">
           Automated Red Teaming & Reconnaissance Suite. 
           <br/>
           <span className="text-xs font-mono text-slate-600">Simulate Nuclei, Nmap, and Shodan vectors via AI inference.</span>
        </p>
      </header>

      <main className="relative px-4 pb-20 flex flex-col items-center z-10 w-full">
        <ScannerInput onScan={handleScan} isLoading={status === ScanStatus.SCANNING} />

        {status === ScanStatus.SCANNING && (
          <div className="flex flex-col items-center justify-center py-20 animate-pulse">
            <div className="relative">
                <div className="absolute inset-0 bg-red-500/20 rounded-full blur-xl animate-pulse"></div>
                <Radar className="w-16 h-16 text-red-500 animate-spin-slow mb-4 relative z-10" />
            </div>
            <p className="font-mono text-red-400 text-lg tracking-widest">INITIALIZING_ATTACK_VECTORS...</p>
            <div className="h-1 w-48 bg-slate-800 mt-4 rounded-full overflow-hidden">
                <div className="h-full bg-red-500 animate-progress"></div>
            </div>
            <p className="text-slate-500 text-xs mt-2 font-mono">Enumerating subdomains :: Checking CVEs :: Scanning Ports</p>
          </div>
        )}

        {status === ScanStatus.ERROR && (
           <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-6 rounded-lg max-w-2xl w-full text-center backdrop-blur-sm shadow-[0_0_30px_rgba(239,68,68,0.2)]">
              <h3 className="font-bold text-lg mb-2 flex items-center justify-center gap-2">
                <AlertTriangle /> Scan Aborted
              </h3>
              <p className="font-mono text-sm">{error}</p>
           </div>
        )}

        {status === ScanStatus.COMPLETE && data && (
          <ResultDashboard data={data} />
        )}

        {status === ScanStatus.IDLE && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl w-full mt-8 opacity-60">
             <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/30 flex flex-col items-center text-center hover:border-red-500/50 transition-colors group">
                <Ghost className="w-10 h-10 text-slate-600 group-hover:text-red-500 mb-4 transition-colors" />
                <h3 className="font-bold text-slate-300">Passive Recon</h3>
                <p className="text-xs text-slate-500 mt-2 font-mono">
                    Subdomain enumeration (RapidDNS/Certsh sim), Waybackurls, Tech Stack Analysis.
                </p>
             </div>
             <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/30 flex flex-col items-center text-center hover:border-red-500/50 transition-colors group">
                <Fingerprint className="w-10 h-10 text-slate-600 group-hover:text-red-500 mb-4 transition-colors" />
                <h3 className="font-bold text-slate-300">Deep Scan</h3>
                <p className="text-xs text-slate-500 mt-2 font-mono">
                    Port Scanning sim, CMS Misconfig, HTTP Security Headers, SSL/TLS Grade.
                </p>
             </div>
             <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/30 flex flex-col items-center text-center hover:border-red-500/50 transition-colors group">
                <Terminal className="w-10 h-10 text-slate-600 group-hover:text-red-500 mb-4 transition-colors" />
                <h3 className="font-bold text-slate-300">Vuln Assessment</h3>
                <p className="text-xs text-slate-500 mt-2 font-mono">
                    Nuclei sim, XSS/SSRF/SQLi vector analysis, API & Cloud Misconfiguration checks.
                </p>
             </div>
          </div>
        )}
      </main>

      <footer className="py-8 text-center text-slate-700 text-xs relative z-10 border-t border-slate-900/50 font-mono">
        <p>CAUTION: USE RESPONSIBLY. UNAUTHORIZED SCANNING MAY BE ILLEGAL.</p>
        <p className="opacity-50 mt-1">POWERED BY GEMINI OFFENSIVE INTELLIGENCE</p>
      </footer>
    </div>
  );
};

export default App;