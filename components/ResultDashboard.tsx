
import React, { useState } from 'react';
import { SiteAnalysisData } from '../types';
import { 
  Shield, 
  Activity, 
  Server, 
  Target, 
  Lock, 
  AlertTriangle,
  Globe,
  Database,
  Cloud,
  Code,
  Wifi,
  FileWarning,
  EyeOff,
  Zap
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  RadialBarChart, 
  RadialBar, 
  Legend,
  Tooltip
} from 'recharts';

interface ResultDashboardProps {
  data: SiteAnalysisData;
}

const ResultDashboard: React.FC<ResultDashboardProps> = ({ data }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'recon' | 'vulns' | 'config'>('overview');

  const scoreData = [
    {
      name: 'Reputation',
      uv: data.reputationScore,
      fill: data.reputationScore > 70 ? '#10b981' : data.reputationScore > 40 ? '#f59e0b' : '#ef4444',
    },
    {
      name: 'Max',
      uv: 100,
      fill: '#1e293b',
    }
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

  return (
    <div className="w-full max-w-7xl mx-auto animate-in fade-in slide-in-from-bottom-8 duration-700">
      
      {/* Tab Navigation */}
      <div className="flex overflow-x-auto gap-2 mb-6 pb-2 border-b border-slate-800">
        {[
            { id: 'overview', icon: Activity, label: 'Overview' },
            { id: 'recon', icon: Target, label: 'Reconnaissance' },
            { id: 'vulns', icon: Shield, label: 'Vulnerabilities' },
            { id: 'config', icon: Server, label: 'Configuration' }
        ].map((tab) => (
            <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-3 rounded-t-lg font-mono text-sm transition-colors
                    ${activeTab === tab.id 
                        ? 'bg-slate-800 text-cyan-400 border-t border-x border-slate-700' 
                        : 'text-slate-500 hover:text-slate-300'}`}
            >
                <tab.icon className="w-4 h-4" />
                {tab.label.toUpperCase()}
            </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
            <>
                <div className="lg:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm relative overflow-hidden">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                    <Activity className="text-cyan-400 w-5 h-5" />
                    Target Executive Summary
                    </h2>
                    <p className="text-slate-300 leading-relaxed text-sm lg:text-base font-light">
                    {data.summary}
                    </p>
                    <div className="mt-6 flex flex-wrap gap-2">
                        {data.techStack.map((tech, idx) => (
                            <span key={idx} className="px-2 py-1 bg-slate-900 border border-slate-600 rounded text-cyan-300 text-xs font-mono">
                                {tech}
                            </span>
                        ))}
                    </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 backdrop-blur-sm flex flex-col items-center justify-center relative">
                    <div className="h-48 w-full relative">
                         <ResponsiveContainer width="100%" height="100%">
                        <RadialBarChart cx="50%" cy="50%" innerRadius="70%" outerRadius="100%" barSize={15} data={scoreData} startAngle={180} endAngle={0}>
                            <RadialBar background dataKey="uv" cornerRadius={10} />
                            <Legend iconSize={0} layout="vertical" verticalAlign="middle" wrapperStyle={{top: '60%', left: '50%', transform: 'translate(-50%, 0)'}} content={() => (
                                <div className="text-center">
                                    <span className="text-4xl font-black text-white block">{data.reputationScore}</span>
                                    <span className="text-xs text-slate-500 uppercase">Trust Score</span>
                                </div>
                            )}/>
                        </RadialBarChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="w-full mt-4 flex items-center justify-between p-3 bg-slate-900/50 rounded border border-slate-700">
                        <span className="text-sm text-slate-400">Security Grade</span>
                        <span className={`text-xl font-bold ${data.securityGrade.startsWith('A') ? 'text-green-400' : data.securityGrade.startsWith('B') ? 'text-cyan-400' : 'text-red-400'}`}>
                            {data.securityGrade}
                        </span>
                    </div>
                </div>
                
                 {/* Quick Stats */}
                 <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800 text-center">
                        <div className="text-2xl font-bold text-white">{data.openPorts.length}</div>
                        <div className="text-xs text-slate-500 uppercase">Open Ports</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800 text-center">
                        <div className="text-2xl font-bold text-white">{data.subdomains.length}</div>
                        <div className="text-xs text-slate-500 uppercase">Subdomains</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800 text-center">
                        <div className="text-2xl font-bold text-red-400">{data.vulnerabilities.length}</div>
                        <div className="text-xs text-slate-500 uppercase">Vulns Found</div>
                    </div>
                    <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-800 text-center">
                        <div className="text-2xl font-bold text-orange-400">{data.apiSecurity?.length || 0}</div>
                        <div className="text-xs text-slate-500 uppercase">API Risks</div>
                    </div>
                 </div>
            </>
        )}

        {/* RECONNAISSANCE TAB */}
        {activeTab === 'recon' && (
            <div className="lg:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Globe className="text-indigo-400 w-5 h-5" />
                        Subdomain Enumeration
                    </h3>
                    <div className="h-64 overflow-y-auto pr-2 custom-scrollbar">
                         {data.subdomains.length > 0 ? (
                            <ul className="space-y-2">
                                {data.subdomains.map((sub, i) => (
                                    <li key={i} className="flex items-center gap-3 text-sm text-slate-300 font-mono p-2 hover:bg-slate-700/50 rounded transition-colors border-l-2 border-transparent hover:border-indigo-500">
                                        <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full"></div>
                                        {sub}
                                    </li>
                                ))}
                            </ul>
                         ) : <div className="text-slate-500 italic">No subdomains discovered in public index.</div>}
                    </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Wifi className="text-emerald-400 w-5 h-5" />
                        Port Scan & Services
                    </h3>
                    <div className="h-64 overflow-y-auto pr-2 custom-scrollbar">
                        <table className="w-full text-sm text-left">
                            <thead className="text-xs text-slate-500 uppercase bg-slate-900/50">
                                <tr>
                                    <th className="px-4 py-2">Port</th>
                                    <th className="px-4 py-2">Service</th>
                                    <th className="px-4 py-2">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-700">
                                {data.openPorts.map((p, i) => (
                                    <tr key={i} className="hover:bg-slate-700/30">
                                        <td className="px-4 py-2 font-mono text-emerald-400">{p.port}</td>
                                        <td className="px-4 py-2 text-slate-300">{p.service} {p.version && <span className="text-xs text-slate-500">({p.version})</span>}</td>
                                        <td className="px-4 py-2"><span className="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 text-xs border border-emerald-500/20">{p.status}</span></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="md:col-span-2 bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <EyeOff className="text-purple-400 w-5 h-5" />
                        Hidden Directories & Assets
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {data.hiddenDirectories.map((dir, i) => (
                            <span key={i} className="px-3 py-1 bg-slate-900 border border-slate-600 rounded text-slate-300 text-sm font-mono hover:border-purple-500 transition-colors cursor-default">
                                {dir}
                            </span>
                        ))}
                         {data.hiddenDirectories.length === 0 && <span className="text-slate-500 italic">No hidden paths inferred.</span>}
                    </div>
                </div>
            </div>
        )}

        {/* VULNERABILITIES TAB */}
        {activeTab === 'vulns' && (
            <div className="lg:col-span-3 space-y-6">
                 <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <AlertTriangle className="text-red-500 w-5 h-5" />
                        Identified Vulnerabilities
                    </h3>
                    <div className="space-y-4">
                        {data.vulnerabilities.length > 0 ? (
                            data.vulnerabilities.map((vuln, i) => (
                                <div key={i} className={`p-4 rounded-lg border flex flex-col md:flex-row gap-4 ${getSeverityColor(vuln.severity)}`}>
                                    <div className="flex-shrink-0">
                                        <span className="font-bold font-mono px-2 py-1 rounded bg-black/20 text-xs">
                                            {vuln.severity}
                                        </span>
                                    </div>
                                    <div className="flex-1">
                                        <div className="flex justify-between items-start">
                                            <h4 className="font-bold text-lg">{vuln.name}</h4>
                                            <span className="font-mono text-xs opacity-75">{vuln.id}</span>
                                        </div>
                                        <p className="text-sm opacity-90 mt-1">{vuln.description}</p>
                                        {vuln.location && (
                                            <div className="mt-2 text-xs font-mono bg-black/20 p-2 rounded inline-block">
                                                Location: {vuln.location}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div className="p-8 text-center text-slate-500 border border-dashed border-slate-700 rounded-lg">
                                No specific CVEs or vulnerabilities detected in public footprint.
                            </div>
                        )}
                    </div>
                 </div>

                 <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Cloud className="text-sky-400 w-5 h-5" />
                            Cloud & Storage Misconfig
                        </h3>
                        <ul className="space-y-2 list-disc list-inside text-slate-300 text-sm">
                            {data.cloudConfig.map((item, i) => (
                                <li key={i}>{item}</li>
                            ))}
                            {data.cloudConfig.length === 0 && <li className="text-slate-500 list-none">No exposed buckets detected.</li>}
                        </ul>
                    </div>
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Database className="text-orange-400 w-5 h-5" />
                                API Security Suite
                            </h3>
                            {data.graphql && <span className="px-2 py-1 bg-pink-900/50 text-pink-400 text-xs border border-pink-800 rounded font-mono">GraphQL DETECTED</span>}
                        </div>
                        
                        {/* API Endpoints List */}
                        {data.apiEndpoints && data.apiEndpoints.length > 0 && (
                            <div className="mb-4 p-3 bg-slate-900/50 rounded border border-slate-800">
                                <h4 className="text-xs text-slate-500 uppercase font-bold mb-2 flex items-center gap-1">
                                    <Zap className="w-3 h-3" /> Discovered Endpoints
                                </h4>
                                <div className="flex flex-wrap gap-1">
                                    {data.apiEndpoints.map((ep, i) => (
                                        <span key={i} className="text-xs font-mono px-2 py-1 bg-slate-800 text-slate-300 rounded border border-slate-700">
                                            {ep}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                         <ul className="space-y-2 list-none text-slate-300 text-sm">
                            {data.apiSecurity?.map((item, i) => (
                                <li key={i} className="flex items-start gap-2 p-2 rounded hover:bg-slate-700/30 transition-colors">
                                    <AlertTriangle className="w-4 h-4 text-orange-500 flex-shrink-0 mt-0.5" />
                                    <span>{item}</span>
                                </li>
                            ))}
                            
                            {(!data.apiSecurity?.length && !data.graphql && (!data.apiEndpoints || data.apiEndpoints.length === 0)) && (
                                <li className="text-slate-500 italic text-center py-4">No critical API flaws or endpoints detected.</li>
                            )}
                        </ul>
                    </div>
                 </div>
            </div>
        )}

        {/* CONFIGURATION TAB */}
        {activeTab === 'config' && (
            <div className="lg:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Code className="text-pink-400 w-5 h-5" />
                        Security Headers
                    </h3>
                    <div className="space-y-3">
                        {data.securityHeaders.map((header, i) => (
                            <div key={i} className="flex items-center justify-between p-2 bg-slate-900/50 rounded border border-slate-700">
                                <span className="font-mono text-sm text-slate-300">{header.name}</span>
                                <div className="flex items-center gap-3">
                                    <span className="text-xs text-slate-500 max-w-[150px] truncate">{header.value}</span>
                                    {header.status === 'SECURE' ? (
                                        <Shield className="w-4 h-4 text-green-500" />
                                    ) : (
                                        <FileWarning className="w-4 h-4 text-red-500" />
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                     <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Lock className="text-yellow-400 w-5 h-5" />
                        SSL/TLS Configuration
                    </h3>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center border-b border-slate-700 pb-2">
                            <span className="text-slate-400">Issuer</span>
                            <span className="text-slate-200">{data.sslInfo.issuer || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-slate-700 pb-2">
                            <span className="text-slate-400">Validity</span>
                            <span className="text-slate-200">{data.sslInfo.validTo || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-400">Grade</span>
                            <span className={`font-bold px-3 py-1 rounded ${data.sslInfo.grade === 'A' || data.sslInfo.grade === 'A+' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                {data.sslInfo.grade || 'N/A'}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        )}

      </div>
    </div>
  );
};

export default ResultDashboard;
