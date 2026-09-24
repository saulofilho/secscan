import React, { useState, useMemo } from 'react';
import {
  Clock,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Users,
  Calendar,
  AlertCircle,
  FileCode,
  Filter,
  Search,
  Check,
  RotateCcw,
  Sparkles,
  ArrowRight,
  ChevronRight,
  TrendingDown,
  ShieldCheck,
  Zap,
  Info
} from 'lucide-react';
import { ScanFinding, ManagedVulnerabilityItem, SlaStatus, SeverityLevel } from '../types';
import { buildAsocInventory, CORPORATE_SLA_POLICY, ENGINEERING_TEAMS } from '../lib/asocManager';

interface AsocSlaDashboardProps {
  findings: ScanFinding[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
  onNavigateToScanner?: () => void;
}

export const AsocSlaDashboard: React.FC<AsocSlaDashboardProps> = ({
  findings,
  onNavigateToFile,
  onNavigateToScanner
}) => {
  const { items: initialItems, metrics } = useMemo(() => {
    return buildAsocInventory(findings);
  }, [findings]);

  const [managedItems, setManagedItems] = useState<ManagedVulnerabilityItem[]>(initialItems);

  React.useEffect(() => {
    setManagedItems(initialItems);
  }, [initialItems]);

  const [selectedTeam, setSelectedTeam] = useState<string>('ALL');
  const [selectedSlaStatus, setSelectedSlaStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Handle resolving an item
  const handleToggleResolve = (id: string) => {
    setManagedItems(prev => prev.map(item => {
      if (item.id === id) {
        const nextStatus = item.status === 'RESOLVED' ? 'OPEN' : 'RESOLVED';
        return {
          ...item,
          status: nextStatus,
          slaStatus: nextStatus === 'RESOLVED' ? 'REMEDIATED' : item.remainingHours <= 0 ? 'BREACHED' : 'WITHIN_SLA'
        };
      }
      return item;
    }));
  };

  // Filter items
  const filteredItems = useMemo(() => {
    return managedItems.filter(item => {
      if (selectedTeam !== 'ALL' && item.assignedTeam !== selectedTeam) return false;
      if (selectedSlaStatus !== 'ALL' && item.slaStatus !== selectedSlaStatus) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = item.title.toLowerCase().includes(q);
        const matchesFile = item.sourceFile.toLowerCase().includes(q);
        const matchesOwner = item.assignedOwner.toLowerCase().includes(q);
        if (!matchesTitle && !matchesFile && !matchesOwner) return false;
      }
      return true;
    });
  }, [managedItems, selectedTeam, selectedSlaStatus, searchQuery]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono text-zinc-200">
      {/* Top Hero Banner */}
      <div className="bg-[#0A050B] border border-purple-500/30 rounded-xl p-5 sm:p-6 shadow-[0_0_25px_rgba(168,85,247,0.08)] relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/40 flex items-center gap-1.5">
                <Clock className="w-5 h-5 text-purple-400" />
                <TrendingDown className="w-4 h-4 text-purple-300" />
              </div>
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white uppercase">
                ASOC &amp; Vulnerability SLA Manager
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-700/60 text-xs font-bold">
                AppSec Operations (Tier-1)
              </span>
            </div>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl leading-relaxed">
              Gestão corporativa do ciclo de vida de vulnerabilidades com cálculo de Débito Técnico de Segurança, conformidade com políticas de SLA por severidade (P0: 48h, P1: 7d, P2: 30d) e atribuição direta a times de engenharia.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="px-5 py-3 rounded-xl bg-black/60 border border-purple-900/50 flex items-center gap-4">
              <div>
                <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">SLA Compliance Rate</span>
                <span className={`text-2xl font-black ${
                  metrics.slaCompliancePercentage >= 85 ? 'text-emerald-400' : metrics.slaCompliancePercentage >= 60 ? 'text-amber-400' : 'text-rose-400'
                }`}>
                  {metrics.slaCompliancePercentage}%
                </span>
              </div>
              <div className="w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm"
                   style={{
                     borderColor: metrics.slaCompliancePercentage >= 85 ? '#34d399' : metrics.slaCompliancePercentage >= 60 ? '#fbbf24' : '#f43f5e',
                     color: metrics.slaCompliancePercentage >= 85 ? '#34d399' : metrics.slaCompliancePercentage >= 60 ? '#fbbf24' : '#f43f5e'
                   }}>
                {metrics.withinSlaCount}/{metrics.totalVulnerabilities}
              </div>
            </div>
          </div>
        </div>

        {/* Top KPIs Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-5 pt-5 border-t border-zinc-800/80">
          <div className="bg-black/40 border border-zinc-800 rounded-lg p-3">
            <div className="text-[10px] text-zinc-400 uppercase tracking-wider">Total de Vulnerabilidades</div>
            <div className="text-xl font-bold text-white mt-0.5">{metrics.totalVulnerabilities}</div>
            <div className="text-[10px] text-zinc-500 mt-0.5">{metrics.openCount} em aberto</div>
          </div>

          <div className="bg-black/40 border border-emerald-900/40 rounded-lg p-3">
            <div className="text-[10px] text-emerald-400 uppercase tracking-wider">Dentro do SLA</div>
            <div className="text-xl font-bold text-emerald-400 mt-0.5">{metrics.withinSlaCount}</div>
            <div className="text-[10px] text-emerald-500/80 mt-0.5">Prazo em conformidade</div>
          </div>

          <div className="bg-black/40 border border-amber-900/40 rounded-lg p-3">
            <div className="text-[10px] text-amber-400 uppercase tracking-wider">Próximo de Estourar</div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">{metrics.nearingBreachCount}</div>
            <div className="text-[10px] text-amber-500 mt-0.5">&lt; 24 horas restantes</div>
          </div>

          <div className="bg-black/40 border border-rose-900/40 rounded-lg p-3">
            <div className="text-[10px] text-rose-400 uppercase tracking-wider">SLA Estourado (Breached)</div>
            <div className="text-xl font-bold text-rose-400 mt-0.5">{metrics.breachedCount}</div>
            <div className="text-[10px] text-rose-500 mt-0.5">Violação de política</div>
          </div>

          <div className="bg-black/40 border border-purple-900/40 rounded-lg p-3 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-purple-400 uppercase tracking-wider">MTTR Médio</div>
            <div className="text-xl font-bold text-purple-300 mt-0.5">{metrics.mttrHours}h</div>
            <div className="text-[10px] text-purple-500 mt-0.5">Tempo Médio de Resolução</div>
          </div>
        </div>
      </div>

      {/* Corporate SLA Policy Reference */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-[#0c080e] border border-rose-950/60 rounded-lg">
          <div className="text-[10px] text-rose-400 font-bold uppercase">SLA P0 - Crítica</div>
          <div className="text-base font-bold text-white mt-0.5">48 Horas</div>
          <div className="text-[10px] text-zinc-500">Exposição de chave ativa ou RCE</div>
        </div>
        <div className="p-3 bg-[#0c080e] border border-orange-950/60 rounded-lg">
          <div className="text-[10px] text-orange-400 font-bold uppercase">SLA P1 - Alta</div>
          <div className="text-base font-bold text-white mt-0.5">7 Dias (168h)</div>
          <div className="text-[10px] text-zinc-500">SQLi, BOLA, IDOR, SSRF</div>
        </div>
        <div className="p-3 bg-[#0c080e] border border-yellow-950/60 rounded-lg">
          <div className="text-[10px] text-yellow-400 font-bold uppercase">SLA P2 - Média</div>
          <div className="text-base font-bold text-white mt-0.5">30 Dias (720h)</div>
          <div className="text-[10px] text-zinc-500">Headers ausentes, CORS fraco</div>
        </div>
        <div className="p-3 bg-[#0c080e] border border-zinc-800 rounded-lg">
          <div className="text-[10px] text-zinc-400 font-bold uppercase">SLA P3 - Baixa</div>
          <div className="text-base font-bold text-white mt-0.5">90 Dias</div>
          <div className="text-[10px] text-zinc-500">Boas práticas de higiene</div>
        </div>
      </div>

      {/* Filters and Search Bar */}
      <div className="p-3.5 bg-[#080E09] border border-zinc-800 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-zinc-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por vulnerabilidade, arquivo ou engenheiro responsável..."
            className="w-full bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-purple-400"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Team Filter */}
          <select
            value={selectedTeam}
            onChange={(e) => setSelectedTeam(e.target.value)}
            className="bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-300 focus:outline-none focus:border-purple-400"
          >
            <option value="ALL">Todos os Times</option>
            {ENGINEERING_TEAMS.map(team => (
              <option key={team} value={team}>Time: {team}</option>
            ))}
          </select>

          {/* SLA Status Filter */}
          <select
            value={selectedSlaStatus}
            onChange={(e) => setSelectedSlaStatus(e.target.value)}
            className="bg-black/50 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-300 focus:outline-none focus:border-purple-400"
          >
            <option value="ALL">Todos os Status de SLA</option>
            <option value="BREACHED">🔴 Estourado (Breached)</option>
            <option value="NEARING_BREACH">🟡 Próximo de Estourar</option>
            <option value="WITHIN_SLA">🟢 Dentro do Prazo</option>
            <option value="REMEDIATED">✓ Remediado</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities Table / Cards */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <div className="p-12 rounded-xl bg-[#080E09] border border-dashed border-zinc-800 text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <h3 className="text-sm font-bold text-white">Nenhuma pendência ou violação de SLA</h3>
            <p className="text-xs text-zinc-500 max-w-md mx-auto">
              Nenhuma vulnerabilidade ativa rastreada no momento. O workspace está limpo ou todos os itens filtrados foram remediados.
            </p>
          </div>
        ) : (
          filteredItems.map(item => {
          const isBreached = item.slaStatus === 'BREACHED';
          const isNearing = item.slaStatus === 'NEARING_BREACH';
          const isResolved = item.status === 'RESOLVED';

          return (
            <div
              key={item.id}
              className={`p-4 rounded-xl border transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                isResolved
                  ? 'bg-[#040805] border-emerald-950/60 opacity-75'
                  : isBreached
                  ? 'bg-[#0f0406] border-rose-900/60 shadow-[0_0_15px_rgba(244,63,94,0.06)]'
                  : isNearing
                  ? 'bg-[#0f0c04] border-amber-900/60'
                  : 'bg-[#080E09] border-zinc-800 hover:border-zinc-700'
              }`}
            >
              <div className="space-y-1.5 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    item.severity === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {item.severity}
                  </span>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isResolved
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : isBreached
                      ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse'
                      : isNearing
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-zinc-800 text-zinc-300'
                  }`}>
                    {isResolved ? '✓ REMEDIADO' : isBreached ? '⚠️ SLA ESTOURADO' : isNearing ? '⏳ EXPIRANDO EM BREVE' : 'DENTRO DO PRAZO'}
                  </span>

                  <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-bold">
                    Time: {item.assignedTeam}
                  </span>

                  <span className="text-[10px] text-zinc-500">
                    SLA Máximo: {item.slaPolicyHours}h
                  </span>
                </div>

                <h3 className={`font-bold text-sm text-white ${isResolved ? 'line-through text-zinc-500' : ''}`}>
                  {item.title}
                </h3>

                <div className="flex items-center gap-4 text-xs text-zinc-400 pt-0.5 flex-wrap">
                  <button
                    type="button"
                    onClick={() => onNavigateToFile && onNavigateToFile(item.sourceFile, item.line)}
                    className="inline-flex items-center gap-1 hover:text-purple-400 cursor-pointer underline underline-offset-2"
                  >
                    <FileCode className="w-3.5 h-3.5 text-purple-400" />
                    <span>{item.sourceFile}:{item.line}</span>
                  </button>

                  <span className="flex items-center gap-1 text-zinc-400">
                    <Users className="w-3.5 h-3.5 text-zinc-500" />
                    <span>{item.assignedOwner}</span>
                  </span>

                  <span className="text-[11px] text-zinc-500">
                    {item.remainingHours > 0
                      ? `${item.remainingHours}h restantes`
                      : `Atrasado há ${Math.abs(item.remainingHours)}h`}
                  </span>
                </div>
              </div>

              {/* Action Controls */}
              <div className="flex items-center gap-2.5 shrink-0 self-start md:self-center">
                <button
                  type="button"
                  onClick={() => handleToggleResolve(item.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer border ${
                    isResolved
                      ? 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-white'
                      : 'bg-purple-950/80 hover:bg-purple-900 text-purple-200 border-purple-700/60'
                  }`}
                >
                  <Check className="w-3.5 h-3.5" />
                  <span>{isResolved ? 'Reabrir Ticket' : 'Marcar Remediado'}</span>
                </button>
              </div>
            </div>
          );
        }))}
      </div>
    </div>
  );
};
