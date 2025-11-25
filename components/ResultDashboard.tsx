
import React, { useState } from 'react';
import { SiteAnalysisData } from '../types';
import { generateExploitScript } from '../services/geminiService';
import { 
  Shield, Activity, Server, Target, Lock, AlertTriangle, Globe, Database, Cloud, Code, Wifi, FileWarning, EyeOff, Zap, Users, Bomb, Layers, Terminal, ExternalLink, ShieldCheck, MapPin, Calendar, Key, Ghost, Cpu, Flame, Download, Mail, Copy, Box, X, FileText, History, Unlock, KeyRound, FileCode, Laptop, BoxSelect, ShoppingCart, Workflow, Network, Binary, RotateCw, Braces, Share2, Skull, GitBranch, Save, Clock, ArrowRightLeft, AlertOctagon
} from 'lucide-react';
import { ResponsiveContainer, RadialBarChart, RadialBar, Legend, Tooltip } from 'recharts';

interface ResultDashboardProps {
  data: SiteAnalysisData;
}

const ResultDashboard: React.FC<ResultDashboardProps> = ({ data }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'recon' | 'vulns' | 'intel' | 'infra' | 'config' | 'client' | 'elite' | 'dark'>('overview');
  const [isExploitModalOpen, setIsExploitModalOpen] = useState(false);
  const [generatedExploit, setGeneratedExploit] = useState<string>('');
  const [isGeneratingExploit, setIsGeneratingExploit] = useState(false);
  const [currentExploitTarget, setCurrentExploitTarget] = useState<string>('');

  const scoreData = [
    { name: 'Reputation', uv: data.reputationScore, fill: data.reputationScore > 70 ? '#10b981' : data.reputationScore > 40 ? '#f59e0b' : '#ef4444' },
    { name: 'Max', uv: 100, fill: '#1e293b' }
  ];

  const getSeverityColor = (sev: string) => {
    switch (sev) {
        case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/30';
        case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
        case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
        case 'LOW': return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
        default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const renderFinding = (item: string | any) => {
    if (!item) return null;
    if (typeof item === 'string') return item;
    return (
        <div className="flex flex-col gap-1 w-full">
            <div className="flex justify-between items-center">
                 <span className="font-bold text-xs uppercase text-cyan-400">{item.type || 'Detection'}</span>
                 {item.confidence && <span className="text-[10px] bg-slate-800 px-1 rounded text-slate-400">{item.confidence}</span>}
            </div>
            {item.parameter && <div className="text-xs font-mono"><span className="text-slate-500">Param:</span> {item.parameter}</div>}
            {item.url && <div className="break-all text-xs opacity-70 font-mono text-yellow-300/80">{item.url}</div>}
            {item.description && <div className="text-xs text-slate-300">{item.description}</div>}
            {item.risk && <div className="text-xs text-red-400 font-bold">RISK: {item.risk}</div>}
        </div>
    );
  };

  const handleGenerateExploit = async (vulnName: string, cveId: string) => {
    setIsExploitModalOpen(true);
    setIsGeneratingExploit(true);
    setGeneratedExploit('');
    setCurrentExploitTarget(`${vulnName} (${cveId})`);
    try {
        const targetUrl = data.subdomains?.[0] || 'target.com';
        const code = await generateExploitScript(cveId, vulnName, targetUrl, data.techStack);
        setGeneratedExploit(code);
    } catch (error) {
        setGeneratedExploit("# Error generating exploit.");
    } finally {
        setIsGeneratingExploit(false);
    }
  };

  const downloadReport = () => {
    const filename = `siteintel_scan_${new Date().toISOString().split('T')[0]}.json`;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
  };

  return (
    <div className="w-full max-w-7xl mx-auto animate-in fade-in slide-in-from-bottom-8 duration-700 relative">
      <div className="flex flex-col md:flex-row justify-between items-end md:items-center mb-6 gap-4">
          <div className="flex overflow-x-auto gap-2 pb-2 border-b border-slate-800 scrollbar-hide w-full md:w-auto">
            {[
                { id: 'overview', icon: Activity, label: 'Overview' },
                { id: 'recon', icon: Target, label: 'Recon' },
                { id: 'vulns', icon: Shield, label: 'Vulns' },
                { id: 'client', icon: Laptop, label: 'Client' },
                { id: 'elite', icon: Zap, label: 'Elite' },
                { id: 'dark', icon: Skull, label: 'DARK' },
                { id: 'intel', icon: Bomb, label: 'Intel' },
                { id: 'infra', icon: Globe, label: 'Infra' },
                { id: 'config', icon: Server, label: 'Config' }
            ].map((tab) => (
                <button key={tab.id} onClick={() => setActiveTab(tab.id as any)} className={`flex items-center gap-2 px-4 py-3 rounded-t-lg font-mono text-sm transition-colors min-w-fit whitespace-nowrap ${activeTab === tab.id ? tab.id === 'dark' ? 'bg-slate-900 text-purple-500 border-purple-900 border-t border-x' : 'bg-slate-800 text-cyan-400 border-t border-x border-slate-700' : 'text-slate-500 hover:text-slate-300'}`}>
                    <tab.icon className={`w-4 h-4 ${tab.id === 'dark' ? 'animate-pulse' : ''}`} /> {tab.label.toUpperCase()}
                </button>
            ))}
          </div>
          <button onClick={downloadReport} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded text-cyan-400 font-mono text-xs uppercase tracking-wider transition-colors"><Download className="w-4 h-4" /> Export Intel</button>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm relative overflow-hidden">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2"><Activity className="text-cyan-400 w-5 h-5" /> Target Executive Summary</h2>
                    <p className="text-slate-300 leading-relaxed text-sm lg:text-base font-light">{data.summary}</p>
                    <div className="mt-6">
                        <h3 className="text-sm font-bold text-slate-400 mb-2 uppercase tracking-wider">Detected Tech Stack</h3>
                        <div className="flex flex-wrap gap-2">
                            {data.techStack?.map((tech, idx) => (<span key={idx} className="px-2 py-1 bg-slate-900 border border-slate-600 rounded text-cyan-300 text-xs font-mono flex items-center gap-1"><Code className="w-3 h-3" /> {tech}</span>))}
                        </div>
                    </div>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm flex flex-col items-center justify-center relative">
                    <div className="h-48 w-full relative">
                         <ResponsiveContainer width="100%" height="100%">
                        <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="100%" barSize={20} data={scoreData} startAngle={180} endAngle={0}>
                            <RadialBar background dataKey="uv" cornerRadius={10} />
                            <Legend iconSize={0} layout="vertical" verticalAlign="middle" wrapperStyle={{top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center'}} content={() => (
                                <div className="text-center">
                                    <div className="text-4xl font-black text-white">{data.reputationScore}</div>
                                    <div className="text-xs text-slate-400 uppercase tracking-widest">Reputation</div>
                                </div>
                            )} />
                        </RadialBarChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="w-full mt-4 pt-4 border-t border-slate-700">
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-sm">Security Grade</span>
                            <span className={`text-2xl font-black ${data.securityGrade === 'A' ? 'text-green-500' : data.securityGrade === 'B' ? 'text-cyan-500' : data.securityGrade === 'C' ? 'text-yellow-500' : 'text-red-500'}`}>{data.securityGrade}</span>
                        </div>
                    </div>
                </div>
            </div>
        )}

        {activeTab === 'recon' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><FileText className="text-cyan-400 w-5 h-5" /> Public Documents (Metadata)</h3>
                    <div className="max-h-64 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
                        {data.publicDocuments?.length ? data.publicDocuments.map((doc, idx) => (<div key={idx} className="p-2 bg-slate-900/50 border border-slate-700 rounded text-sm text-cyan-300 font-mono flex items-center justify-between group hover:border-cyan-500/50 transition-colors"><span className="truncate w-full">{renderFinding(doc)}</span></div>)) : <div className="text-slate-500 italic text-sm">No public documents found.</div>}
                    </div>
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><History className="text-yellow-400 w-5 h-5" /> Wayback Archive Findings</h3>
                    <div className="max-h-64 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
                        {data.archiveEndpoints?.length ? data.archiveEndpoints.map((path, idx) => (<div key={idx} className="p-2 bg-slate-900/50 border border-slate-700 rounded text-sm text-yellow-300 font-mono break-all">{renderFinding(path)}</div>)) : <div className="text-slate-500 italic text-sm">No interesting history found.</div>}
                    </div>
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Globe className="text-cyan-400 w-5 h-5" /> Subdomains Discovered</h3>
                    <div className="max-h-64 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
                        {data.subdomains?.length ? data.subdomains.map((sub, idx) => (<div key={idx} className="p-2 bg-slate-900/50 border border-slate-700 rounded text-sm text-cyan-300 font-mono flex items-center justify-between group hover:border-cyan-500/50 transition-colors"><span>{sub}</span></div>)) : <div className="text-slate-500 italic text-sm">No subdomains enumerated.</div>}
                    </div>
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><EyeOff className="text-cyan-400 w-5 h-5" /> Hidden Directories</h3>
                    <div className="max-h-64 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
                        {data.hiddenDirectories?.length ? data.hiddenDirectories.map((dir, idx) => (<div key={idx} className="p-2 bg-slate-900/50 border border-slate-700 rounded text-sm text-yellow-300 font-mono">{dir}</div>)) : <div className="text-slate-500 italic text-sm">No hidden paths found.</div>}
                    </div>
                 </div>
                 <div className="md:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Wifi className="text-cyan-400 w-5 h-5" /> Open Ports & Services</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {data.openPorts?.length ? data.openPorts.map((port, idx) => (<div key={idx} className="p-3 bg-slate-900 border border-slate-700 rounded-lg flex flex-col items-center justify-center text-center group hover:border-red-500/50 transition-colors"><span className="text-2xl font-black text-white group-hover:text-red-400">{port.port}</span><span className="text-xs text-slate-400 uppercase font-mono">{port.service}</span><span className={`text-[10px] px-2 py-0.5 rounded-full mt-2 ${port.status === 'OPEN' ? 'bg-red-500/20 text-red-400' : 'bg-slate-700 text-slate-400'}`}>{port.status}</span></div>)) : <div className="col-span-4 text-slate-500 italic text-center">No open ports inferred.</div>}
                    </div>
                 </div>
            </div>
        )}

        {activeTab === 'vulns' && (
            <div className="space-y-4">
                {data.exploitVectors?.length > 0 && (
                  <div className="mb-8 border border-red-500/50 rounded-xl bg-red-950/20 p-6 relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-2 opacity-10"><Flame className="w-24 h-24 text-red-500" /></div>
                    <h3 className="text-xl font-bold text-red-400 mb-4 flex items-center gap-2 animate-pulse"><Zap className="w-5 h-5" /> WEAPONIZED PAYLOADS (ACTIVE)</h3>
                    <div className="space-y-3">
                      {data.exploitVectors.map((vector, idx) => (
                        <div key={idx} className="bg-slate-950/50 border border-red-500/30 rounded-lg p-3">
                          <div className="flex justify-between items-start mb-2"><span className="px-2 py-0.5 bg-red-600/20 text-red-400 text-xs font-bold border border-red-500/50 rounded uppercase">{vector.type}</span><span className="text-xs text-slate-500 font-mono">CONFIDENCE: {vector.confidence}</span></div>
                          <div className="font-mono text-sm text-slate-300 break-all mb-2">Param: <span className="text-cyan-400">{vector.parameter}</span><br/>Payload: <span className="text-yellow-400">{vector.payload}</span></div>
                          <a href={vector.targetUrl} target="_blank" rel="noopener noreferrer" className="flex items-center justify-center w-full py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-bold tracking-widest uppercase rounded transition-colors">LAUNCH EXPLOIT <ExternalLink className="w-3 h-3 ml-2" /></a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                 {data.pathTraversal?.length > 0 && (
                    <div className="mb-8 border border-orange-500/50 rounded-xl bg-orange-950/20 p-6 relative">
                         <h3 className="text-xl font-bold text-orange-400 mb-4 flex items-center gap-2"><FileCode className="w-5 h-5" /> PATH TRAVERSAL / LFI VECTORS</h3>
                        <div className="space-y-2">{data.pathTraversal.map((item, idx) => (<div key={idx} className="flex items-start gap-3 p-3 bg-slate-900/50 border border-orange-500/30 rounded text-orange-200"><FileWarning className="w-5 h-5 flex-shrink-0 mt-0.5" /><span className="font-mono text-sm break-all w-full">{renderFinding(item)}</span></div>))}</div>
                    </div>
                 )}
                 {data.ssrf?.length > 0 && (
                    <div className="mb-8 border border-indigo-500/50 rounded-xl bg-indigo-950/20 p-6 relative">
                        <h3 className="text-xl font-bold text-indigo-400 mb-4 flex items-center gap-2"><Network className="w-5 h-5" /> SSRF HUNTER (CLOUD METADATA)</h3>
                         <div className="space-y-2">{data.ssrf.map((item, idx) => (<div key={idx} className="flex items-start gap-3 p-3 bg-slate-900/50 border border-indigo-500/30 rounded text-indigo-200"><Cloud className="w-5 h-5 flex-shrink-0 mt-0.5" /><span className="font-mono text-sm break-all w-full">{renderFinding(item)}</span></div>))}</div>
                    </div>
                 )}
                {data.vulnerabilities?.length > 0 ? (
                    data.vulnerabilities.map((vuln, idx) => (
                        <div key={idx} className={`p-4 rounded-xl border flex flex-col md:flex-row gap-4 backdrop-blur-sm ${getSeverityColor(vuln.severity)}`}>
                            <div className="flex-shrink-0 flex flex-col items-center justify-center min-w-[80px]"><AlertTriangle className="w-8 h-8 mb-2" /><span className="font-black text-sm tracking-wider">{vuln.severity}</span></div>
                            <div className="flex-grow">
                                <div className="flex items-center justify-between mb-2"><h4 className="font-bold text-lg">{vuln.name}</h4><div className="flex items-center gap-2"><span className="font-mono text-xs opacity-70 border border-current px-2 py-1 rounded">{vuln.id}</span><button onClick={() => handleGenerateExploit(vuln.name, vuln.id)} className="px-3 py-1 bg-slate-900 hover:bg-slate-800 border border-current rounded text-xs font-bold uppercase tracking-wider flex items-center gap-1 transition-colors"><Terminal className="w-3 h-3" /> AUTO-EXPLOIT</button></div></div>
                                <p className="text-sm opacity-90 mb-2">{vuln.description}</p>
                            </div>
                        </div>
                    ))
                ) : <div className="text-center p-12 bg-slate-800/50 rounded-xl border border-slate-700"><ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-4" /><h3 className="text-xl font-bold text-white">System Secure</h3></div>}
            </div>
        )}
        
        {activeTab === 'elite' && (
            <div className="grid grid-cols-1 gap-6">
                <div className="bg-red-950/20 border border-red-500/50 rounded-xl p-6 relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-4 opacity-10"><Bomb className="w-32 h-32 text-red-500" /></div>
                    <div className="relative z-10">
                        <h3 className="text-2xl font-black text-red-500 mb-2 flex items-center gap-2"><Zap className="w-6 h-6" /> ELITE VECTOR ANALYSIS (NON-PUBLIC)</h3>
                        <p className="text-red-300/70 text-sm max-w-2xl mb-8">Advanced logic inference, supply chain analysis, and architectural flaws.</p>
                         <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                             <div className="space-y-4">
                                <h4 className="text-lg font-bold text-white flex items-center gap-2"><BoxSelect className="text-purple-400 w-5 h-5" /> Supply Chain Risks</h4>
                                {data.supplyChainRisks?.length ? data.supplyChainRisks.map((risk, idx) => (
                                    <div key={idx} className="bg-slate-900/80 border border-purple-500/40 p-4 rounded-lg"><div className="flex justify-between items-start mb-2"><span className="font-mono text-purple-300 font-bold">{risk.packageName}</span><span className="bg-red-600/20 text-red-400 text-[10px] px-2 py-0.5 rounded border border-red-500/30 uppercase font-bold">{risk.riskLevel}</span></div><p className="text-xs text-slate-400 mb-2">{risk.description}</p></div>
                                )) : <div className="text-sm text-slate-500 italic">No supply chain risks detected.</div>}
                            </div>
                             <div className="space-y-4">
                                <h4 className="text-lg font-bold text-white flex items-center gap-2"><Workflow className="text-orange-400 w-5 h-5" /> SSTI</h4>
                                {data.sstiVectors?.length ? data.sstiVectors.map((vector, idx) => (<div key={idx} className="bg-slate-900/80 border border-orange-500/40 p-4 rounded-lg"><div className="text-orange-300 font-bold text-sm mb-2">{vector.engine}</div><div className="bg-black/40 p-2 rounded text-xs font-mono text-yellow-500 break-all">{vector.payload}</div></div>)) : <div className="text-sm text-slate-500 italic">No SSTI vectors detected.</div>}
                            </div>
                            <div className="space-y-4">
                                <h4 className="text-lg font-bold text-white flex items-center gap-2"><AlertOctagon className="text-red-400 w-5 h-5" /> Business Logic Flaws</h4>
                                {data.businessLogicFlaws?.length ? data.businessLogicFlaws.map((flaw, idx) => (<div key={idx} className="bg-slate-900/80 border border-red-500/40 p-4 rounded-lg"><div className="text-red-300 font-bold text-sm mb-2">{flaw.flawType}</div><div className="text-xs text-slate-400">{flaw.description}</div><div className="mt-2 text-xs font-mono text-slate-500">Endpoint: {flaw.endpoint}</div></div>)) : <div className="text-sm text-slate-500 italic">No logic flaws inferred.</div>}
                            </div>
                            <div className="space-y-4">
                                <h4 className="text-lg font-bold text-white flex items-center gap-2"><Binary className="text-cyan-400 w-5 h-5" /> Ultra-Elite (Proto/Cache/Serial)</h4>
                                {data.prototypePollution?.length > 0 && <div className="text-xs text-cyan-300">Prototype Pollution Detected</div>}
                                {data.deserializationFlaws?.length > 0 && <div className="text-xs text-cyan-300">Insecure Deserialization Detected</div>}
                                {data.cachePoisoning?.length > 0 && <div className="text-xs text-cyan-300">Cache Poisoning Detected</div>}
                                {(!data.prototypePollution?.length && !data.deserializationFlaws?.length && !data.cachePoisoning?.length) && <div className="text-sm text-slate-500 italic">No ultra-elite flaws detected.</div>}
                            </div>
                         </div>
                    </div>
                </div>
            </div>
        )}

        {activeTab === 'dark' && (
            <div className="grid grid-cols-1 gap-6">
                <div className="bg-slate-900 border border-purple-500/50 rounded-xl p-6 relative overflow-hidden shadow-[0_0_50px_rgba(168,85,247,0.1)]">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-purple-500 via-pink-500 to-red-500"></div>
                    <div className="absolute top-0 right-0 p-4 opacity-20"><Skull className="w-48 h-48 text-purple-600 animate-pulse" /></div>
                    <h3 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600 mb-2 flex items-center gap-3 relative z-10"><Skull className="w-8 h-8 text-purple-500" /> DARK ARTS MODULE (20 VECTORS)</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
                        <div className="bg-slate-950/50 border border-purple-500/30 p-4 rounded-lg">
                            <h4 className="text-purple-400 font-bold mb-3 flex items-center gap-2 text-sm"><KeyRound className="w-4 h-4" /> AUTH & SESSION</h4>
                            <div className="space-y-2">
                                {data.jwtFlaws?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-purple-500 pl-2">JWT: {i.flaw}</div>)}
                                {data.ldapVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-purple-500 pl-2">LDAP: {i.parameter}</div>)}
                                {data.noSqlVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-purple-500 pl-2">NoSQL: {i.parameter}</div>)}
                                {data.raceConditions?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-purple-500 pl-2">Race: {i.endpoint}</div>)}
                                {!data.jwtFlaws?.length && !data.ldapVectors?.length && !data.noSqlVectors?.length && !data.raceConditions?.length && <div className="text-xs text-slate-600 italic">No auth flaws detected.</div>}
                            </div>
                        </div>
                        <div className="bg-slate-950/50 border border-pink-500/30 p-4 rounded-lg">
                            <h4 className="text-pink-400 font-bold mb-3 flex items-center gap-2 text-sm"><ArrowRightLeft className="w-4 h-4" /> TRAFFIC MANIPULATION</h4>
                            <div className="space-y-2">
                                {data.requestSmuggling?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-pink-500 pl-2">Smuggling: {i.type}</div>)}
                                {data.hostHeaderFlaws?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-pink-500 pl-2">Host Poison: {i.type}</div>)}
                                {data.corsFlaws?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-pink-500 pl-2 mb-1"><span className="font-bold text-pink-400">CORS:</span> {i.origin} {i.credentials && <span className="ml-1 text-[10px] bg-pink-900/50 text-pink-300 px-1 rounded">CRED</span>}</div>)}
                                {data.openRedirects?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-pink-500 pl-2">Redirect: {i.parameter}</div>)}
                                {data.webSocketFlaws?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-pink-500 pl-2">WS Hijack: {i.endpoint}</div>)}
                                {!data.requestSmuggling?.length && !data.hostHeaderFlaws?.length && !data.corsFlaws?.length && !data.openRedirects?.length && <div className="text-xs text-slate-600 italic">Traffic secure.</div>}
                            </div>
                        </div>
                        <div className="bg-slate-950/50 border border-red-500/30 p-4 rounded-lg">
                            <h4 className="text-red-400 font-bold mb-3 flex items-center gap-2 text-sm"><Terminal className="w-4 h-4" /> INJECTION & RCE</h4>
                            <div className="space-y-2">
                                {data.xxeVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2 mb-1"><span className="font-bold text-red-400">XXE:</span> {i.endpoint}<div className="text-[10px] text-slate-500 font-mono break-all">{i.payload}</div></div>)}
                                {data.ssiVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">SSI: {i.endpoint}</div>)}
                                {data.csvInjections?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">CSV: {i.parameter}</div>)}
                                {data.log4jVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">Log4Shell: {i.location}</div>)}
                                {data.spring4ShellVectors?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">Spring4Shell: {i.location}</div>)}
                                {data.pickleFlaws?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">Pickle RCE: {i.parameter}</div>)}
                                {data.blindSqli?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-red-500 pl-2">Blind SQLi: {i.parameter}</div>)}
                                {!data.xxeVectors?.length && !data.log4jVectors?.length && !data.blindSqli?.length && <div className="text-xs text-slate-600 italic">No advanced injection found.</div>}
                            </div>
                        </div>
                        <div className="bg-slate-950/50 border border-yellow-500/30 p-4 rounded-lg">
                            <h4 className="text-yellow-400 font-bold mb-3 flex items-center gap-2 text-sm"><GitBranch className="w-4 h-4" /> INFRA & LEAKS</h4>
                            <div className="space-y-2">
                                {data.gitExposures?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-yellow-500 pl-2">Git: {i.url}</div>)}
                                {data.backupFiles?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-yellow-500 pl-2">Backup: {i.url}</div>)}
                                {data.hiddenParameters?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-yellow-500 pl-2">Hidden Param: {i.name}</div>)}
                                {data.massAssignments?.map((i,k) => <div key={k} className="text-xs text-slate-400 border-l-2 border-yellow-500 pl-2">Mass Assign: {i.parameter}</div>)}
                                {!data.gitExposures?.length && !data.backupFiles?.length && <div className="text-xs text-slate-600 italic">Infra secure.</div>}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        )}
        
        {activeTab === 'client' && (
            <div className="grid grid-cols-1 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2"><Globe className="text-red-500 w-6 h-6 animate-pulse" /> SUBDOMAIN TAKEOVER (DANGLING CNAME)</h3>
                    <div className="grid gap-4">{data.subdomainTakeover?.length ? data.subdomainTakeover.map((item, idx) => (<div key={idx} className="bg-red-950/20 border border-red-500/50 p-4 rounded-lg flex flex-col md:flex-row justify-between items-center gap-4"><div className="flex items-center gap-4"><div className="bg-red-500/20 p-3 rounded-full"><AlertTriangle className="w-6 h-6 text-red-500" /></div><div><div className="text-lg font-bold text-white font-mono">{item.subdomain}</div><div className="text-sm text-red-300">Provider: {item.provider}</div></div></div><div className="text-right"><div className="px-3 py-1 bg-red-600 text-white text-xs font-bold rounded uppercase tracking-wider mb-1 inline-block">{item.status}</div></div></div>)) : <div className="p-8 text-center bg-slate-900/50 rounded-lg border border-slate-800"><ShieldCheck className="w-8 h-8 text-green-500 mx-auto mb-2" /><div className="text-slate-400">No dangling CNAME records found. DNS appears clean.</div></div>}</div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Key className="text-yellow-400 w-5 h-5" /> Hardcoded Secrets (JS)</h3>
                        <div className="space-y-3">{data.clientSideIntel?.hardcodedSecrets?.length ? data.clientSideIntel.hardcodedSecrets.map((secret, idx) => (<div key={idx} className="p-3 bg-yellow-900/10 border border-yellow-500/30 rounded"><div className="flex justify-between items-center mb-1"><span className="text-yellow-200 font-bold text-sm">{secret.name}</span><span className="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded border border-red-500/30">{secret.severity}</span></div><div className="font-mono text-xs text-slate-400 mb-1 break-all">{secret.value}</div><div className="text-xs text-slate-600 font-mono text-right">{secret.location}</div></div>)) : <div className="text-sm text-slate-500 italic">No hardcoded secrets found in public JS.</div>}</div>
                    </div>
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Code className="text-purple-400 w-5 h-5" /> Dangerous Functions (DOM XSS)</h3>
                        <div className="space-y-3">{data.clientSideIntel?.dangerousFunctions?.length ? data.clientSideIntel.dangerousFunctions.map((func, idx) => (<div key={idx} className="p-3 bg-purple-900/10 border border-purple-500/30 rounded flex justify-between items-center"><div><div className="text-purple-200 font-mono font-bold text-sm">{func.function}</div><div className="text-xs text-slate-500">{func.location}</div></div><div className="text-xs text-red-400 font-bold uppercase border border-red-500/30 px-2 py-1 rounded bg-red-900/20">{func.risk}</div></div>)) : <div className="text-sm text-slate-500 italic">No dangerous DOM sinks detected.</div>}</div>
                    </div>
                </div>
            </div>
        )}

        {activeTab === 'intel' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="md:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-red-600"></div>
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><KeyRound className="text-red-500 w-6 h-6 animate-pulse" /> CREDENTIAL ACCESS & ADMIN PANELS</h3>
                    {data.credentialIntel ? (<div className="space-y-6"><div><h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Admin Interfaces Detected</h4><div className="grid gap-2">{data.credentialIntel.adminPanels?.length ? data.credentialIntel.adminPanels.map((panel, idx) => (<div key={idx} className="bg-slate-900 border border-slate-700 p-3 rounded flex flex-col md:flex-row md:items-center justify-between gap-2"><div><div className="text-cyan-400 font-mono text-sm font-bold">{panel.url}</div><div className="text-slate-500 text-xs">{panel.description}</div></div>{panel.defaultCreds && <div className="bg-red-900/30 border border-red-500/30 px-3 py-1 rounded text-red-300 text-xs font-mono">DEFAULT: {panel.defaultCreds}</div>}</div>)) : <div className="text-slate-500 text-sm italic">No exposed admin panels found via common dorks.</div>}</div></div></div>) : <div className="text-slate-500 italic">Credential analysis not available in Passive Mode. Switch to AGGRESSIVE.</div>}
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Layers className="text-cyan-400 w-5 h-5" /> WAF Detection</h3>
                    <div className="space-y-2">{data.wafDetected?.length ? data.wafDetected.map((waf, idx) => (<div key={idx} className="flex items-center gap-3 p-3 bg-red-900/20 border border-red-500/50 rounded-lg text-red-200"><Shield className="w-5 h-5" /><span className="font-bold">{waf}</span><span className="text-xs ml-auto opacity-70">DETECTED</span></div>)) : <div className="p-3 bg-green-900/20 border border-green-500/50 rounded-lg text-green-200 flex items-center gap-3"><Shield className="w-5 h-5" /><span className="font-bold">No WAF Detected</span></div>}</div>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Users className="text-cyan-400 w-5 h-5" /> Harvested Emails (OSINT)</h3>
                    <div className="max-h-48 overflow-y-auto custom-scrollbar">{data.emails?.length ? <ul className="space-y-2">{data.emails.map((email, idx) => (<li key={idx} className="flex items-center gap-2 text-sm font-mono text-slate-300 p-2 hover:bg-slate-700/50 rounded transition-colors"><div className="w-2 h-2 rounded-full bg-cyan-500"></div>{email}</li>))}</ul> : <div className="text-slate-500 italic text-sm">No emails harvested.</div>}</div>
                </div>
            </div>
        )}

        {activeTab === 'infra' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><MapPin className="text-cyan-400 w-5 h-5" /> Server Geolocation</h3>
                    {data.geolocation ? (<div className="space-y-2 text-sm"><div className="flex justify-between border-b border-slate-700 pb-2"><span className="text-slate-400">Country</span><span className="text-white font-mono">{data.geolocation.country}</span></div><div className="flex justify-between border-b border-slate-700 pb-2"><span className="text-slate-400">City</span><span className="text-white font-mono">{data.geolocation.city || 'Unknown'}</span></div><div className="flex justify-between"><span className="text-slate-400">ISP / Hoster</span><span className="text-cyan-400 font-mono">{data.geolocation.isp}</span></div></div>) : <div className="text-slate-500 italic">Geo-data unavailable.</div>}
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Calendar className="text-cyan-400 w-5 h-5" /> Whois & Registrar</h3>
                    {data.whois ? (<div className="space-y-2 text-sm"><div className="flex justify-between border-b border-slate-700 pb-2"><span className="text-slate-400">Registrar</span><span className="text-white font-mono">{data.whois.registrar}</span></div><div className="flex justify-between border-b border-slate-700 pb-2"><span className="text-slate-400">Created</span><span className="text-white font-mono">{data.whois.createdDate}</span></div><div className="flex justify-between"><span className="text-slate-400">Expires</span><span className="text-red-400 font-mono">{data.whois.expiryDate}</span></div></div>) : <div className="text-slate-500 italic">Whois data masked or unavailable.</div>}
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Server className="text-cyan-400 w-5 h-5" /> OS Fingerprint</h3>
                     <div className="p-4 bg-slate-900 border border-slate-700 rounded text-center"><div className="text-2xl font-mono text-white mb-1">{data.os || 'Unknown OS'}</div><div className="text-xs text-slate-500 uppercase tracking-widest">Operating System</div></div>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Mail className="text-purple-400 w-5 h-5" /> Mail Security (Spoofing)</h3>
                    {data.mailSecurity ? (<div className="space-y-4"><div className="grid grid-cols-2 gap-4"><div className={`p-3 border rounded text-center ${data.mailSecurity.spf ? 'bg-green-900/20 border-green-500/50 text-green-400' : 'bg-red-900/20 border-red-500/50 text-red-400'}`}><div className="font-bold">SPF</div><div className="text-xs">{data.mailSecurity.spf ? 'SECURE' : 'MISSING/WEAK'}</div></div><div className={`p-3 border rounded text-center ${data.mailSecurity.dmarc ? 'bg-green-900/20 border-green-500/50 text-green-400' : 'bg-red-900/20 border-red-500/50 text-red-400'}`}><div className="font-bold">DMARC</div><div className="text-xs">{data.mailSecurity.dmarc ? 'ENFORCED' : 'MISSING'}</div></div></div>{data.mailSecurity.spoofingPossible && <div className="p-3 bg-red-900/30 border border-red-500 text-red-200 text-sm rounded flex items-center gap-2 animate-pulse"><AlertTriangle className="w-4 h-4" /><span>DOMAIN SPOOFING POSSIBLE (CEO FRAUD RISK)</span></div>}</div>) : <div className="text-slate-500 italic">Mail security records not analyzed.</div>}
                </div>
            </div>
        )}

        {activeTab === 'config' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><ShieldCheck className="text-cyan-400 w-5 h-5" /> HTTP Security Headers</h3>
                    <div className="space-y-2">{data.securityHeaders?.length ? data.securityHeaders.map((header, idx) => (<div key={idx} className="flex justify-between items-center p-2 bg-slate-900/50 rounded border border-slate-700"><span className="text-sm font-mono text-slate-300">{header.name}</span><span className={`text-xs font-bold px-2 py-0.5 rounded ${header.status === 'SECURE' ? 'bg-green-500/20 text-green-400' : header.status === 'WEAK' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'}`}>{header.status}</span></div>)) : <div className="text-slate-500 italic">No headers analyzed.</div>}</div>
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Braces className="text-purple-400 w-5 h-5" /> API Security</h3>
                    <div className="space-y-4"><div><h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Discovered Endpoints</h4><div className="flex flex-wrap gap-2">{data.apiEndpoints?.length ? data.apiEndpoints.map((ep, idx) => (<span key={idx} className="px-2 py-1 bg-purple-900/20 text-purple-300 text-xs font-mono rounded border border-purple-500/30 w-full block break-all">{renderFinding(ep)}</span>)) : <span className="text-slate-500 italic text-sm">No API endpoints enumerated.</span>}</div></div></div>
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Share2 className="text-pink-400 w-5 h-5" /> GraphQL Security</h3>
                    <div className="flex items-center justify-between mb-4"><span className="text-slate-400 text-sm">Endpoint Detected</span><span className={`font-mono font-bold ${data.graphql ? 'text-red-400' : 'text-slate-500'}`}>{data.graphql ? 'YES' : 'NO'}</span></div>{data.graphql && <div className="space-y-2">{data.graphqlFindings && data.graphqlFindings.map((finding, idx) => (<div key={idx} className="p-2 bg-pink-900/20 border border-pink-500/30 rounded text-pink-200 text-xs font-mono">{renderFinding(finding)}</div>))}</div>}
                 </div>
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Cloud className="text-cyan-400 w-5 h-5" /> Cloud Misconfigurations</h3>
                    <div className="space-y-2">{data.cloudConfig?.length ? data.cloudConfig.map((item, idx) => (<div key={idx} className="flex items-start gap-2 p-2 bg-red-900/20 border border-red-500/30 rounded text-red-200 text-sm"><AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" /><div className="w-full">{renderFinding(item)}</div></div>)) : <div className="text-slate-500 italic">No exposed cloud buckets or config files.</div>}</div>
                 </div>
            </div>
        )}
      </div>

      {isExploitModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-2xl shadow-2xl relative overflow-hidden">
                <div className="flex justify-between items-center p-4 border-b border-slate-700 bg-slate-800"><h3 className="text-lg font-bold text-white flex items-center gap-2"><Terminal className="text-red-500 w-5 h-5" /> WEAPONIZER // {currentExploitTarget}</h3><button onClick={() => setIsExploitModalOpen(false)} className="text-slate-500 hover:text-white transition-colors"><X className="w-5 h-5" /></button></div>
                <div className="p-0 bg-black">{isGeneratingExploit ? <div className="p-8 flex flex-col items-center justify-center text-red-500 font-mono gap-4"><RotateCw className="w-8 h-8 animate-spin" /><div className="text-sm tracking-widest animate-pulse">GENERATING_EXPLOIT_POC...</div></div> : <div className="relative group"><pre className="p-4 text-xs md:text-sm font-mono text-green-400 overflow-x-auto custom-scrollbar h-[400px]">{generatedExploit}</pre><button onClick={() => navigator.clipboard.writeText(generatedExploit)} className="absolute top-4 right-4 bg-slate-800/80 hover:bg-slate-700 text-white p-2 rounded opacity-0 group-hover:opacity-100 transition-opacity" title="Copy Code"><Copy className="w-4 h-4" /></button></div>}</div>
                <div className="p-3 bg-slate-800 border-t border-slate-700 text-right"><span className="text-xs text-slate-500 font-mono mr-4">USE FOR EDUCATIONAL PURPOSES ONLY</span></div>
            </div>
        </div>
      )}
    </div>
  );
};

export default ResultDashboard;
