import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon, Play, Copy, Check, Trash2, ArrowRight, CornerDownLeft } from 'lucide-react';
import { ScanReport, CliCommandHistory } from '../types';
import { exportToJson, exportToCsv, exportToSarif } from '../lib/scanner';

interface CliTerminalViewProps {
  report: ScanReport;
  onTriggerScan: () => void;
}

export const CliTerminalView: React.FC<CliTerminalViewProps> = ({ report, onTriggerScan }) => {
  const [inputCommand, setInputCommand] = useState('');
  const [history, setHistory] = useState<CliCommandHistory[]>([
    {
      id: 'init-1',
      command: 'secscan --version',
      timestamp: new Date().toLocaleTimeString(),
      exitCode: 0,
      output: `SecScan Static Analysis Security Tool (SAST) v1.0.0
Node.js Runtime: 22.x LTS | Architecture: x86_64
Default exclusions: node_modules, vendor, dist, .git, *.min.js
Type 'help' or 'secscan --help' for available flags.`
    },
    {
      id: 'init-2',
      command: 'secscan run . --format table',
      timestamp: new Date().toLocaleTimeString(),
      exitCode: 0,
      output: `🛡️  SecScan SAST Static Security Scan Report
────────────────────────────────────────────────────────────────────────────────
Target: ./workspace | Scanned Files: ${report.scannedFilesCount} | Ignored: ${report.ignoredFilesCount}
Findings Detected: ${report.findings.length} | Security Score: ${report.metrics.securityScore}/100
────────────────────────────────────────────────────────────────────────────────
${report.findings.map(f => `[${f.severity}] ${f.ruleName}\n  File:    ${f.file}:${f.line}\n  Secret:  ${f.maskedSecret}\n  Entropy: ${f.entropy}`).join('\n\n')}`
    }
  ]);

  const [copiedId, setCopiedId] = useState<string | null>(null);
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminalBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const handleRunCommand = (cmdText: string) => {
    const raw = cmdText.trim();
    if (!raw) return;

    const lower = raw.toLowerCase();
    let output = '';
    let exitCode = 0;

    if (lower === 'clear') {
      setHistory([]);
      setInputCommand('');
      return;
    }

    if (lower === 'help' || lower === 'secscan --help' || lower === 'secscan -h') {
      output = `
🛡️ SecScan CLI Command Reference Manual:

Usage:
  secscan <command> [directory] [options]

Commands:
  secscan run [dir]          Execute SAST secret & API path scan
  secscan rules              List all registered regex detection rules
  secscan metrics            Display executive vulnerability metrics
  secscan export [format]    Export report (json, csv, sarif)

Options:
  --format <table|json|sarif|csv>   Output format (Default: table)
  --ignore <patterns>               Exclude directories (Default: node_modules, dist)
  --fail-on <critical|high|medium>  Return exit code 1 if findings meet threshold
  --output <file>                   Write output directly to disk

Examples:
  secscan run . --format json
  secscan run . --format sarif --output secscan.sarif
  secscan run ./src --fail-on critical
  clear`;
    } else if (lower.includes('export')) {
      if (lower.includes('json')) {
        output = exportToJson(report);
      } else if (lower.includes('csv')) {
        output = exportToCsv(report);
      } else if (lower.includes('sarif')) {
        output = exportToSarif(report);
      } else {
        output = exportToJson(report);
      }
    } else if (lower.includes('rules')) {
      output = `Loaded Rules: 14 Active SAST Detectors\n- AWS AKID (CRITICAL)\n- AWS Secret Key (CRITICAL)\n- Stripe Secret Key (CRITICAL)\n- GitHub PAT (CRITICAL)\n- Google/Gemini API Key (HIGH)\n- JWT Static Token (HIGH)\n- Database Password URIs (CRITICAL)\n- Sensitive API Endpoints (MEDIUM)`;
    } else if (lower.includes('metrics')) {
      output = `SAST Compliance Score: ${report.metrics.securityScore}/100\nTotal Secrets: ${report.findings.length} (Critical: ${report.metrics.criticalCount}, High: ${report.metrics.highCount})\nAPI Routes: ${report.apiEndpoints.length}\nFiles Scanned: ${report.scannedFilesCount} (Ignored: ${report.ignoredFilesCount})\nScan Duration: ${report.durationMs}ms`;
    } else if (lower.startsWith('secscan') || lower.startsWith('scan')) {
      if (lower.includes('--fail-on critical') && report.metrics.criticalCount > 0) {
        exitCode = 1;
        output = `❌ [SecScan CI Failure] Found ${report.metrics.criticalCount} critical secret(s). Build aborted with Exit Code 1.`;
      } else if (lower.includes('--format json')) {
        output = exportToJson(report);
      } else if (lower.includes('--format sarif')) {
        output = exportToSarif(report);
      } else {
        output = `[SecScan Execution Completed]\nScanned: ${report.scannedFilesCount} files\nBypassed: ${report.ignoredFilesCount} dependencies (node_modules/vendor)\nFindings: ${report.findings.length}\nElapsed Time: ${report.durationMs}ms\nStatus: SUCCESS`;
      }
    } else {
      exitCode = 127;
      output = `secscan: command not found: ${raw}. Type 'help' for available commands.`;
    }

    setHistory(prev => [
      ...prev,
      {
        id: `cmd-${Date.now()}`,
        command: raw,
        timestamp: new Date().toLocaleTimeString(),
        exitCode,
        output
      }
    ]);

    setInputCommand('');
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const presetCommands = [
    'secscan run .',
    'secscan run . --format json',
    'secscan run . --format sarif',
    'secscan run . --fail-on critical',
    'secscan metrics',
    'help'
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header Info */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // INTERACTIVE TTY ENVIRONMENT
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-[#00FF41] border border-[#222]">
              $ SECSCAN_CLI
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
            CLI Terminal & Automation
          </h1>
          <p className="text-xs font-mono text-[#888] mt-1.5 max-w-2xl leading-relaxed">
            Simulação realista e execução interativa de comandos da CLI do SecScan. Você também pode rodar diretamente no seu terminal ou CI/CD via <code className="bg-[#000] px-1.5 py-0.5 border border-[#222] text-[#FF3E00] font-mono text-[11px]">node bin/secscan.js</code>.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setHistory([])}
            className="inline-flex items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Limpar Console</span>
          </button>
        </div>
      </div>

      {/* Preset Command Shortcuts */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
        <span className="text-[10px] font-black uppercase tracking-[0.2em] text-[#666] shrink-0">PRESETS:</span>
        {presetCommands.map((cmd, idx) => (
          <button
            key={idx}
            onClick={() => handleRunCommand(cmd)}
            className="px-3 py-1.5 bg-[#0A0A0A] hover:bg-white hover:text-black text-[#AAA] font-mono text-[10px] shrink-0 transition-colors border border-[#222]"
          >
            {cmd}
          </button>
        ))}
      </div>

      {/* Terminal Canvas */}
      <div className="bg-[#050505] text-zinc-100 border border-[#222] overflow-hidden font-mono text-xs">
        {/* Terminal Titlebar */}
        <div className="px-4 py-3 bg-[#0A0A0A] border-b border-[#222] flex items-center justify-between select-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-none bg-[#FF3E00] inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-none bg-[#666] inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-none bg-[#333] inline-block"></span>
            <span className="ml-2 text-[#888] text-[10px] font-mono uppercase tracking-wider">SECSCAN_CLI_v1.0.0 // TTY_0</span>
          </div>

          <div className="flex items-center gap-2 text-[#666] text-[10px] font-mono uppercase tracking-wider">
            <TerminalIcon className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>NODE_V22.14.0</span>
          </div>
        </div>

        {/* Terminal Content Stream */}
        <div className="p-5 space-y-4 min-h-[380px] max-h-[520px] overflow-y-auto leading-relaxed select-text bg-[#030303]">
          {history.map((item) => (
            <div key={item.id} className="space-y-2 group">
              {/* Command Prompt Line */}
              <div className="flex items-center justify-between text-[#888] text-[11px]">
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-[#FF3E00] font-black">sast@runner</span>
                  <span className="text-[#444]">:</span>
                  <span className="text-white">~/workspace</span>
                  <span className="text-[#00FF41]">$ {item.command}</span>
                </div>

                <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <span className={`text-[9px] font-mono uppercase px-1.5 py-0.2 ${item.exitCode === 0 ? 'bg-[#00FF41]/10 text-[#00FF41]' : 'bg-[#FF3E00]/10 text-[#FF3E00]'}`}>
                    exit: {item.exitCode}
                  </span>
                  <button
                    onClick={() => handleCopy(item.output, item.id)}
                    className="p-1 hover:text-white text-[#666] transition-colors"
                    title="Copiar saída do comando"
                  >
                    {copiedId === item.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Output Content */}
              <pre className="p-4 bg-[#080808] text-[#CCC] whitespace-pre-wrap break-all border border-[#1A1A1A] font-mono text-[11px] leading-relaxed">
                {item.output}
              </pre>
            </div>
          ))}

          <div ref={terminalBottomRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3.5 bg-[#0A0A0A] border-t border-[#222] flex items-center gap-3">
          <span className="text-[#FF3E00] font-black pl-1 select-none font-mono">$</span>
          <input
            type="text"
            value={inputCommand}
            onChange={(e) => setInputCommand(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleRunCommand(inputCommand);
              }
            }}
            placeholder="Digite um comando (ex: secscan run . --format json)..."
            className="flex-1 bg-transparent text-white font-mono text-xs focus:outline-none placeholder-[#555]"
          />
          <button
            onClick={() => handleRunCommand(inputCommand)}
            className="px-3 py-1.5 bg-[#FF3E00] hover:bg-white hover:text-black text-white text-[10px] font-black uppercase tracking-wider transition-colors"
          >
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
